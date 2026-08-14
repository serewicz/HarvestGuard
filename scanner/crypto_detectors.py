"""Shared internal crypto-detector framework for the crypto-inventory scanner.

HG-033 adds **no new detection capability**. Every cryptographic format the
crypto-inventory scanner recognizes was already recognized before this module
existed; this is an implementation refactor that moves the previously
interleaved dispatch logic in ``scanner/crypto_inventory.py`` behind a small,
explicit detector abstraction so a future format-specific issue can add one
detector without reworking traversal, accounting, privacy, or reporting.

What this module owns:

- **Shared scan context.** ``FileContext`` and ``RootContext`` give detectors
  the views they need over one already-visited asset -- leading bytes, full
  bytes, a bounded text view, a fixed-name sibling marker check -- without
  each detector re-reading the file. Every view is derived from a single read
  per file, which is exactly the read behavior the scanner had before HG-033
  (``_scan_file`` opened each candidate file once and passed the full bytes
  to each check); the context does not add, remove, or defer any read.
- **Detector declarations.** ``FileDetector`` and ``RootDetector`` are frozen
  dataclasses, not classes to subclass: a detector is data (identity, scope,
  priority, candidate predicate, detect callable, rule id, confidence,
  evidence wording, terminal behavior, safe metadata allowlist) plus two plain
  functions.
- **Static registry.** ``build_registry`` produces a deterministic, ordered
  tuple from an explicit input sequence. There is no reflection, no import-
  order or filesystem dependence, no environment variable, no entry point, and
  no runtime discovery -- the registry is whatever the caller listed, sorted by
  declared priority, with duplicate priorities rejected so no pair of detectors
  can have their relative order decided by the caller's listing order.
- **Terminal/non-terminal interaction.** ``DetectionResult`` models the four
  outcomes the current scanner actually needs: no match; match and continue;
  match and stop for this asset; and "this detector owns the asset but found
  nothing reportable" (a terminal claim, which is what keeps a file named
  ``gocryptfs.conf`` that failed root validation from falling through into
  PEM/DER/PKCS#12 parsing).
- **Safe metadata allowlisting.** Detector output is treated as untrusted until
  allowlisted: each detector declares which of the ten approved metadata keys
  it may populate, ``build_registry`` rejects a declaration outside that set,
  and ``enforce_metadata_allowlist`` omits any metadata field a detector
  populated without declaring. There is deliberately no generic dictionary
  path from a parser into ``technical_metadata``.
- **Error isolation.** A detector's expected non-match is a ``DetectionResult``,
  not an exception. An *unexpected* exception from a candidate predicate or a
  detect callable is wrapped in ``DetectorExecutionError``, which names the
  detector id, the asset location, and the exception *type* only -- never the
  exception message, which could carry parser payloads or file content. It is
  never converted into a clean non-match.

Traversal is deliberately **not** owned here. The scanner walks the target,
applies exclusions and symlink rules, and counts inspected files; detectors
only ever see one already-discovered asset at a time and have no filesystem
entry point beyond the fixed-name sibling check ``RootContext`` exposes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Sequence

# The text-decode boundary the crypto-inventory scanner has always applied:
# a file larger than this is not decoded to text at all. Unchanged by HG-033
# and shared here so the context, the candidate gate, and the detectors cannot
# drift apart.
MAX_TEXT_BYTES = 5_000_000

# Scope/family values a detector may declare.
SCOPE_FILE = "file"
SCOPE_ROOT = "root"

# The complete set of metadata keys any crypto-inventory detector may populate,
# matching the record keys `CryptoInventoryFinding.to_record()` emits and
# `normalize_crypto_inventory_df` copies into `technical_metadata`. A detector
# declaring anything outside this set is a programming error and is rejected at
# registry-build time rather than silently widening the privacy boundary.
SAFE_METADATA_KEYS = frozenset(
    {
        "Algorithm",
        "Key Size",
        "Signature Algorithm",
        "Expiration",
        "Issuer",
        "Subject",
        "Fingerprint",
        "Format",
        "Config Version",
        "Mode",
    }
)

# Record key -> the finding attribute that carries it. The allowlist is enforced
# against the finding object's own fields rather than a free-form dictionary,
# which is what makes "undeclared metadata cannot reach normalized findings"
# structural instead of a convention.
METADATA_ATTRIBUTES: dict[str, str] = {
    "Algorithm": "algorithm",
    "Key Size": "key_size",
    "Signature Algorithm": "signature_algorithm",
    "Expiration": "expiration",
    "Issuer": "issuer",
    "Subject": "subject",
    "Fingerprint": "fingerprint",
    "Format": "format",
    "Config Version": "config_version",
    "Mode": "mode",
}

_UNSET = object()


def decode_text(data: bytes) -> str | None:
    """The crypto-inventory scanner's text view of ``data``, or None when it has
    none: too large to decode, binary (a NUL in the first 4 KiB), or not
    decodable as UTF-8 or ASCII. Behavior is unchanged from HG-033's
    predecessor ``_decode_text``; it lives here so ``FileContext`` can cache one
    text view per file instead of every text detector decoding again."""
    if len(data) > MAX_TEXT_BYTES:
        return None
    if b"\x00" in data[:4096]:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        try:
            return data.decode("ascii")
        except UnicodeDecodeError:
            return None


class DetectorExecutionError(RuntimeError):
    """An unexpected exception escaped a detector's candidate predicate or
    detect callable.

    This is never an expected non-match (detectors return a ``DetectionResult``
    for that) and is never swallowed into one: the scanner surfaces it through
    its existing scanner-error path while preserving the findings already
    collected, exactly as it does for a traversal failure.

    The message carries the detector id, the asset location, and the exception
    *type name* only. The exception's own message is deliberately omitted: a
    parser exception can quote the bytes it choked on, and raw bytes, key
    material, passphrases, ciphertext, plaintext, and parser payloads must never
    reach scanner errors, CLI output, or Markdown reports.

    ``partial_findings`` carries the findings earlier detectors already produced
    for the *same* asset before the failure. Without it those findings would be
    lost with the abandoned ``run_detectors`` call and could never reach
    ``LocalScanError.partial_findings``, which would make one detector's defect
    silently discard another detector's valid evidence about the same file.
    """

    def __init__(
        self,
        detector_id: str,
        location: str,
        cause: BaseException,
        partial_findings: Iterable[Any] = (),
    ):
        self.detector_id = detector_id
        self.location = location
        self.cause = cause
        self.partial_findings: tuple[Any, ...] = tuple(partial_findings)
        super().__init__(
            f"crypto detector '{detector_id}' failed on {location}: "
            f"{type(cause).__name__}"
        )


@dataclass(frozen=True)
class ScanScope:
    """The requested scan's own scope rules, supplied by the scanner.

    This exists for exactly one question (HG-041): when an aggregate detector
    checks a fixed-name supporting sibling, is that sibling *in scope for this
    scan*, or did the user exclude it? ``RootContext.has_regular_sibling`` can
    only answer the filesystem half of that ("is it a genuine regular file"),
    which would let aggregate evidence quietly ignore a ``--exclude`` pattern.

    The scanner supplies its own rules as callables rather than the framework
    reimplementing them: ``match_path_for`` is the scanner's own root-relative
    POSIX match path for a path (the same value traversal would assign that
    sibling, and the bare basename when the scan target is a single file), and
    ``is_excluded`` is the scanner's own exclusion matcher. There is deliberately
    no second exclusion grammar here, and nothing in this dataclass lists, globs,
    walks, or opens anything.
    """

    target_path: Path
    match_path_for: Callable[[Path], str]
    is_excluded: Callable[[Path, str], bool]


@dataclass
class FileContext:
    """One regular file the scanner has already discovered, shared by every file
    detector that inspects it.

    The bytes are read once, on first access, and cached: two detectors reading
    ``data`` (or ``leading_bytes``, or ``text``) do not produce two reads, which
    is what keeps a growing registry from turning into a
    ``detectors x full-file-read`` pattern. ``memo`` is a per-file scratch space
    for shared candidate work (the scanner's candidate gate) so that too is
    evaluated once per file rather than once per detector.
    """

    path: Path
    # The scan's scope rules, when the caller is the scanner's own traversal.
    # None when a detector is exercised outside a scan (a direct unit test), in
    # which case scope-aware sibling eligibility falls back to the filesystem
    # check alone -- there are no exclusion patterns to respect.
    scope: ScanScope | None = None
    memo: dict[str, Any] = field(default_factory=dict, repr=False)
    _data: Any = field(default=_UNSET, repr=False)
    _text: Any = field(default=_UNSET, repr=False)

    @property
    def name(self) -> str:
        return self.path.name

    @property
    def suffix(self) -> str:
        """The lowercased extension, the form every extension-based candidate
        predicate compares against."""
        return self.path.suffix.lower()

    @property
    def location(self) -> str:
        return str(self.path)

    def readable(self) -> bool:
        """Whether the file's bytes could be read, performing the single cached
        read. False for an unreadable file (permission denied, vanished or
        replaced mid-scan, or another OSError), which produces no finding and no
        evidence -- unchanged from the scanner's pre-HG-033 behavior."""
        return self._load() is not None

    def _load(self) -> bytes | None:
        if self._data is _UNSET:
            try:
                self._data = self.path.read_bytes()
            except (OSError, PermissionError):
                self._data = None
        return self._data

    @property
    def data(self) -> bytes:
        """The file's full bytes.

        Requested explicitly, and only by the detectors whose parsers genuinely
        need the whole asset (PKCS#12, DER, PEM, OpenPGP's declared-length
        check). Bounded by the file's own size, which is exactly the read the
        scanner already performed for every candidate file before HG-033 -- this
        framework neither widens nor narrows it. What it does change is what a
        detector *sees*: a leading-byte detector asks for a prefix through
        ``leading_bytes`` rather than receiving the whole buffer, so a future
        issue can narrow the read itself without revisiting those detectors.
        """
        data = self._load()
        if data is None:
            raise OSError(f"{self.path}: file contents are unavailable")
        return data

    def leading_bytes(self, count: int) -> bytes:
        """The first ``count`` bytes, or fewer when the file is shorter.

        Binary-safe and length-safe: an empty or truncated file yields a short
        or empty result rather than raising, which is what lets the leading-byte
        detectors (OpenSSL ``Salted__``, the OpenPGP packet header, the JKS
        magic header) keep their exact-position semantics without special-casing
        small files.
        """
        return self.data[:count]

    @property
    def text(self) -> str | None:
        """The bounded text view (see ``decode_text``), or None when this file
        has none. Cached, including the None: a binary or oversized file is not
        decoded again for each text detector."""
        if self._text is _UNSET:
            self._text = decode_text(self.data)
        return self._text

    def root_context(self) -> RootContext:
        """This file read as a root detector's marker file: the containing
        directory is the candidate root."""
        return RootContext(root_path=self.path.parent, marker=self, scope=self.scope)


@dataclass
class RootContext:
    """A candidate root/directory an aggregate detector may classify, reached
    through a marker file the scanner's own traversal discovered.

    Root detectors are given this instead of a directory to walk: there is no
    listing, globbing, or recursion here, only the already-read marker file and
    a fixed-name sibling check. That is what keeps aggregate detection to one
    finding per validated root with no per-contained-file amplification, and
    keeps traversal ownership with the scanner.
    """

    root_path: Path
    marker: FileContext
    scope: ScanScope | None = None

    @property
    def marker_path(self) -> Path:
        return self.marker.path

    @property
    def location(self) -> str:
        return str(self.root_path)

    def has_regular_sibling(self, name: str) -> bool:
        """Whether ``name`` exists in this root as a genuine regular file --
        ``is_file()`` alone would follow a symlink, so both conditions are
        required.

        ``name`` must be a bare filename. A separator or ``..`` would turn a
        marker check into a traversal primitive, so it is rejected outright
        rather than normalized.
        """
        if not name or name != Path(name).name or name in {".", ".."}:
            raise ValueError(f"sibling marker must be a bare filename, got: {name!r}")
        sibling = self.root_path / name
        return sibling.is_file() and not sibling.is_symlink()

    def has_eligible_regular_sibling(self, name: str) -> bool:
        """Whether ``name`` is a genuine regular non-symlink file in this root
        *and* in scope for the scan that reached this root (HG-041).

        The filesystem half is ``has_regular_sibling``, including its bare-
        filename requirement -- no listing, globbing, recursion, arbitrary path
        input, or file open. The scope half asks the scanner's own exclusion
        matcher about the sibling, using the scanner's own match path, so a
        sibling the user excluded behaves exactly as a missing one and aggregate
        supporting evidence cannot bypass ``--exclude``.

        Nothing here opens the sibling or counts it: supporting-evidence checks
        are not inspected files, so ``files_inspected`` is untouched.
        """
        if not self.has_regular_sibling(name):
            return False
        if self.scope is None:
            return True
        sibling = self.root_path / name
        return not self.scope.is_excluded(sibling, self.scope.match_path_for(sibling))


@dataclass(frozen=True)
class DetectionResult:
    """What one detector concluded about one asset.

    Four outcomes, which is exactly what the current scanner's dispatch needed:

    - ``no_match()`` -- not this format; keep evaluating later detectors.
    - ``match(findings)`` -- evidence found. Whether that ends evaluation for
      this asset comes from the detector's own ``terminal`` declaration, so the
      declaration is the single source of truth: a detector declared terminal
      owns the asset it matched, which is what stops a structurally identified
      OpenSSL/OpenPGP file saved with a misleading ``.p12``/``.der`` extension
      from also being reported as a malformed PKCS#12 or DER asset, while the
      non-terminal text detectors coexist (one PEM file legitimately holding a
      certificate, a private key, and an SSH public key reports all three).
    - ``claim()`` -- this detector owns the asset but has nothing reportable
      about it: terminal, with no findings.
    - ``match(findings, terminal=True)`` -- terminal for a reason the
      declaration cannot express. No current detector needs it; terminality is
      normally declared, not returned.

    There is deliberately no "first detector always wins" rule.
    """

    findings: tuple[Any, ...] = ()
    matched: bool = False
    terminal: bool = False

    @classmethod
    def no_match(cls) -> DetectionResult:
        return cls()

    @classmethod
    def match(cls, findings: Iterable[Any], terminal: bool = False) -> DetectionResult:
        return cls(findings=tuple(findings), matched=True, terminal=terminal)

    @classmethod
    def claim(cls) -> DetectionResult:
        return cls(matched=True, terminal=True)


@dataclass(frozen=True)
class FileDetector:
    """A file-scope detector declaration.

    ``candidate`` is the cheap gate deciding whether ``detect`` is worth
    running, and both receive the shared ``FileContext`` rather than raw bytes,
    so each detector reads only the view it declared it needs. ``rule_id``,
    ``confidence``, and ``evidence`` document the finding contract this detector
    produces (they are the values its findings carry, not a second source of
    truth the framework substitutes in), and ``metadata_keys`` is its safe
    metadata allowlist.

    ``terminal`` declares whether a match ends evaluation for that asset. It is
    enforced by ``run_detectors`` rather than being documentation only: a
    detector declared terminal owns what it matched.
    """

    detector_id: str
    priority: int
    candidate: Callable[[FileContext], bool]
    detect: Callable[[FileContext], DetectionResult]
    evidence: str
    confidence: str
    terminal: bool = False
    rule_id: str | None = None
    metadata_keys: frozenset[str] = frozenset()
    verification_rationale: str | None = None
    scope: str = SCOPE_FILE


@dataclass(frozen=True)
class RootDetector:
    """A root/directory-scope detector declaration.

    ``marker_filename`` is the candidate-root predicate: the scanner runs this
    detector when its own traversal discovers a file with that exact name, and
    the containing directory becomes the candidate root. ``owns_marker``
    declares that the classification of that marker file is terminal whether or
    not the root validated -- a marker that failed validation is not evidence of
    some other asset type either, and must not fall through to the file
    detectors.
    """

    detector_id: str
    priority: int
    marker_filename: str
    detect: Callable[[RootContext], DetectionResult]
    evidence: str
    confidence: str
    rule_id: str | None = None
    metadata_keys: frozenset[str] = frozenset()
    verification_rationale: str | None = None
    owns_marker: bool = True
    scope: str = SCOPE_ROOT


Detector = FileDetector | RootDetector


def build_registry(detectors: Sequence[Detector]) -> tuple[Detector, ...]:
    """The static detector registry: ``detectors`` ordered deterministically by
    declared priority.

    Ordering depends only on the declared ``priority`` -- never on import order,
    filesystem order, or an environment variable. Perturbing the input order
    therefore cannot change the registry, which is what makes intentional
    precedence a property of the declarations rather than of how this module
    happened to be imported.

    Priorities must therefore be unique: two detectors sharing one priority
    would leave their relative order decided by whichever came first in the
    caller's list, which is exactly the input-order dependence a static registry
    exists to rule out. A duplicate is rejected rather than tie-broken, so the
    ambiguity is fixed in the declaration where the intended precedence is
    visible. The sort key still names ``detector_id`` as a secondary term so the
    ordering is total by construction rather than relying on sort stability.

    Raises ``ValueError`` for a duplicate detector id, an empty id, a duplicate
    priority, or a metadata key outside ``SAFE_METADATA_KEYS``: all four are
    programming errors that would otherwise weaken ordering determinism or the
    privacy boundary silently.
    """
    seen: set[str] = set()
    priorities: dict[int, str] = {}
    for detector in detectors:
        detector_id = detector.detector_id
        if not detector_id:
            raise ValueError("detector id must be a non-empty string")
        if detector_id in seen:
            raise ValueError(f"duplicate crypto detector id: {detector_id}")
        seen.add(detector_id)
        if detector.priority in priorities:
            raise ValueError(
                f"duplicate crypto detector priority {detector.priority}: "
                f"{priorities[detector.priority]} and {detector_id}"
            )
        priorities[detector.priority] = detector_id
        unsafe = set(detector.metadata_keys) - SAFE_METADATA_KEYS
        if unsafe:
            raise ValueError(
                f"detector {detector_id} declares metadata keys outside the safe "
                f"allowlist: {sorted(unsafe)}"
            )
    return tuple(
        sorted(detectors, key=lambda detector: (detector.priority, detector.detector_id))
    )


def enforce_metadata_allowlist(finding: Any, metadata_keys: frozenset[str]) -> Any:
    """Omit any metadata field ``finding`` populated that its detector did not
    declare, and return the finding.

    Applied centrally to every finding every detector produces, so a parser that
    starts returning an extra field cannot widen what reaches
    ``technical_metadata``, JSON, or Markdown without that key first being
    declared here and in ``SAFE_METADATA_KEYS``. Omission rather than rejection:
    an undeclared value is dropped, and the rest of the finding still stands as
    evidence.
    """
    for key, attribute in METADATA_ATTRIBUTES.items():
        if key not in metadata_keys and getattr(finding, attribute, None) is not None:
            setattr(finding, attribute, None)
    return finding


def _invoke(detector: Detector, call: Callable[[Any], Any], context: Any) -> Any:
    try:
        return call(context)
    except Exception as exc:  # noqa: BLE001 - deliberately broad; see below.
        # Any unexpected escape from detector code is isolated and attributed
        # here rather than becoming a clean non-match. The scanner turns this
        # into its existing scanner-error path with partial findings preserved.
        raise DetectorExecutionError(detector.detector_id, context.location, exc) from exc


def run_detectors(
    context: FileContext, detectors: Sequence[Detector]
) -> list[Any]:
    """Every finding ``detectors`` produce for one already-read file, in
    registry order.

    Root detectors are evaluated in the same ordered pass as file detectors --
    their position in the registry is what places aggregate root classification
    ahead of the file-format branches that would otherwise misread a marker
    file -- but they receive a ``RootContext`` for the containing directory
    instead of the file context.

    Accounting is unaffected by anything here: the scanner counts the file once
    before calling this, so the number of detectors that inspect it, the number
    of views they take of it, and the number of findings they produce (including
    malformed ones) cannot change ``Crypto files inspected``.

    An unexpected detector failure raises ``DetectorExecutionError`` carrying the
    findings collected for this file so far, so evidence an earlier non-terminal
    detector already produced for the same asset survives a later detector's
    defect instead of being lost with this call.
    """
    findings: list[Any] = []
    for detector in detectors:
        try:
            owns_asset = False
            if detector.scope == SCOPE_ROOT:
                if context.name != detector.marker_filename:
                    continue
                result = _invoke(detector, detector.detect, context.root_context())
                # Belt and braces alongside the detector's own terminal result: a
                # marker file an owning root detector rejected is not evidence of
                # some other asset type either, so it must not fall through into
                # the file-format detectors even if a future root detector forgets
                # to say so in its result.
                owns_asset = detector.owns_marker
            else:
                if not _invoke(detector, detector.candidate, context):
                    continue
                result = _invoke(detector, detector.detect, context)
                # Terminality is the detector's declaration, not its result:
                # `terminal=True` on a file detector means "a match ends
                # evaluation for this asset", which is what the OpenSSL, OpenPGP,
                # JKS, PKCS#12, and DER precedence relies on.
                owns_asset = detector.terminal
            if not isinstance(result, DetectionResult):
                raise DetectorExecutionError(
                    detector.detector_id,
                    context.location,
                    TypeError(f"detector returned {type(result).__name__}"),
                )
        except DetectorExecutionError as exc:
            # Attributed to the failing detector, but the valid evidence earlier
            # detectors produced for this same file travels with the error so the
            # scanner can preserve it as partial findings.
            exc.partial_findings = tuple(findings)
            raise
        if result.matched:
            for finding in result.findings:
                findings.append(
                    enforce_metadata_allowlist(finding, detector.metadata_keys)
                )
        elif detector.scope != SCOPE_ROOT:
            # A file detector that did not match never ends evaluation, however
            # it was declared -- the DER detector's "extension looked right but
            # nothing parsed" path must fall through to the text detectors.
            owns_asset = False
        if result.terminal or owns_asset:
            break
    return findings
