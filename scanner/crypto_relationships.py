"""Internal-only cryptographic relationship model for the crypto-inventory
architecture.

HG-034 adds **no new detection capability** and **no public output**. Nothing
here reaches the CLI, JSON output, Markdown reports, the Streamlit dashboard,
the legacy DataFrame, or ``NormalizedFinding``: findings remain the only
first-class public inventory records. This module exists so that a later
format-specific issue can represent a *directly observed* structural connection
between two already-discovered cryptographic assets without re-inventing
identity rules, direction semantics, deduplication, or the privacy boundary.

What this module is:

- **A reference model, not an asset model.** A relationship names two endpoints
  by the stable ``finding_id`` of findings HarvestGuard already produced. It
  never duplicates a finding, never creates a synthetic asset, and never
  mutates or re-identifies the findings it references.
- **A fixed vocabulary.** ``RelationshipType`` is closed: ``contains``,
  ``corresponds_to``, ``references``, ``member_of``, ``issued_by``. Adding a
  type requires an explicit code and test change, which is what keeps vague,
  assessment-flavored relations (``related_to``, ``depends_on``, ``protects``,
  ``at_risk_from``, ``owned_by``) out.
- **Deterministic identity.** ``relationship_id`` is derived from the
  relationship type, both stable finding IDs (canonicalized for symmetric
  types), and the relationship rule ID -- nothing else. Timestamps, scan IDs,
  host, process, traversal or detector order, confidence, evidence prose,
  provenance text, limitations, and errors are all excluded, so re-observing the
  same relationship in a later scan yields the same ID.
- **Explicit direction.** Four types are directional (reversing the endpoints is
  a *different* relationship and gets a different ID); ``corresponds_to`` is
  symmetric (endpoints are canonically ordered, so reversed input yields one
  identical record).
- **Required provenance.** Every relationship names the component and the
  relationship rule that created it, the scan context it was observed in, whether
  the observation is repeatable, and the ISO-8601 time HarvestGuard collected the
  evidence. None of these is optional, and each accepts safe values only -- a
  machine identifier or a real timestamp, never prose or asset contents.
- **Evidence-only.** Every relationship requires evidence text describing what
  was structurally observed. Construction-time guards reject assessment wording
  (risk, remediation, compliance, HNDL, quantum, severity, business impact) and
  inference wording (same directory, similar name, probably, assumed), because a
  relationship must not be created from guesswork, naming similarity, proximity,
  extension, co-location, ownership, or business assumption.
- **Narrow by construction.** There is deliberately **no** metadata dictionary,
  no free-form blob field, and no serialization path. Every text field is
  length-bounded, must be printable, and is rejected outright if it carries a
  PEM/OpenPGP armor header or the OpenSSL ``Salted__`` magic, so raw keys,
  certificates, ciphertext, plaintext, passphrases, salts, KDF values, config
  contents, packet bodies, and parser payloads have no channel into a
  relationship. Rejection is not a channel either: a validation message names the
  refused *field* and at most the Python type supplied, never the value, so a
  passphrase a defective caller passed where an identifier belonged cannot travel
  out through an exception or through ``RelationshipCollection.rejections``.

What this module is **not**: a graph. There is no graph database, no graph
library, no graph API, no persistence, no traversal, no path search, no
transitive closure, and no cycle analysis. A future relationship set may well
contain cycles; nothing here requires or checks acyclicity. Deduplication is
exact-identity suppression over one flat collection, never transitive merging,
and the record that survives is selected independently of the order the
duplicates arrived in.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, fields
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Iterable, Mapping

# The internal component name relationship records carry when a caller does not
# name a more specific one. Provenance must explain which internal component
# created a relationship, and HG-034 has exactly one: this model.
RELATIONSHIP_MODEL_COMPONENT = "crypto_relationship_model"


class RelationshipType(str, Enum):
    """The closed relationship vocabulary.

    Deliberately small and structural. Each type names something a parser can
    directly observe, never an assessment, dependency, or ownership claim:

    - ``contains`` -- a parsed container directly contains an object (a PKCS#12
      holding a certificate, a keystore holding an entry).
    - ``corresponds_to`` -- two observed assets carry matching key material (a
      certificate's public key equals a private key's public key). Symmetric.
    - ``references`` -- a supported manifest or configuration directly names
      another observed asset.
    - ``member_of`` -- an observed certificate is part of an observed chain or
      bundle.
    - ``issued_by`` -- a parsed certificate's issuer directly matches another
      observed certificate's subject.

    A ``str`` enum so a relationship converts cleanly with ``dataclasses.asdict``
    plus ``json.dumps`` in tests without any serializer of its own.
    """

    CONTAINS = "contains"
    CORRESPONDS_TO = "corresponds_to"
    REFERENCES = "references"
    MEMBER_OF = "member_of"
    ISSUED_BY = "issued_by"


# Direction is a property of the type, declared once here rather than decided at
# each call site. Every allowed type must appear in exactly one of these two
# sets; `_check_vocabulary_partition` enforces that at import time so adding a
# type without declaring its direction is an immediate, loud failure.
DIRECTIONAL_RELATIONSHIP_TYPES = frozenset(
    {
        RelationshipType.CONTAINS,
        RelationshipType.REFERENCES,
        RelationshipType.MEMBER_OF,
        RelationshipType.ISSUED_BY,
    }
)

SYMMETRIC_RELATIONSHIP_TYPES = frozenset({RelationshipType.CORRESPONDS_TO})

# The same confidence vocabulary scanner findings already use. Relationship
# confidence describes confidence in the observed relationship evidence only --
# never severity, exposure, remediation priority, or priority for action. High
# requires direct structural proof; HG-034 itself only ever constructs High.
SUPPORTED_RELATIONSHIP_CONFIDENCE = ("High", "Medium", "Low")

# Text fields are bounded so no field can become a blob smuggling channel for
# key material, config contents, or a parser payload. A relationship's evidence
# is one observed structural fact, which is a sentence, not a document.
MAX_TEXT_FIELD_CHARS = 500

# Identifier-shaped fields (rule ID, creator component, scan context) accept
# machine identifiers only, never prose and never raw content.
_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9._:\-]+$")

# A stable finding ID is the SHA-256 hex digest `NormalizedFinding._generate_id`
# produces. Requiring that shape keeps a path, a filename, or a chunk of file
# content from being passed as an endpoint.
_FINDING_ID_PATTERN = re.compile(r"^[0-9a-f]{64}$")

# Structural markers of raw cryptographic material. Their presence in any text
# field means raw content reached the relationship model, which is rejected
# rather than scrubbed: the caller has a privacy defect to fix, and a silently
# trimmed record would hide it. This is a backstop, not a redaction engine --
# the real guarantee is that the model has no metadata field to put content in.
_RAW_MATERIAL_MARKERS = (
    "-----BEGIN",
    "-----END",
    "Salted__",
    "PuTTY-User-Key-File",
    "BEGIN PGP",
)

# Assessment vocabulary. A relationship states what was observed; it may not
# claim validity, trust, correctness, ownership, business use, security
# strength, compliance, remediation, HNDL, quantum readiness, or severity.
_PROHIBITED_CLAIM_TERMS = (
    "risk",
    "remediat",
    "recommend",
    "hndl",
    "quantum",
    "complian",
    "severity",
    "priorit",
    "business",
    "impact",
    "trust",
    "vulnerab",
    "secure",
    "insecure",
    "weak",
    "owner",
    "ownership",
    "exposure",
)

# Inference vocabulary. No relationship may be created from guesswork, naming
# similarity, proximity, extension, or co-location, so evidence wording that
# describes one of those is rejected at construction time.
_PROHIBITED_INFERENCE_TERMS = (
    "same directory",
    "same folder",
    "co-located",
    "colocated",
    "similar",
    "matching basename",
    "same basename",
    "filename suggests",
    "extension suggests",
    "probably",
    "likely",
    "appears to",
    "assume",
    "assumed",
    "assumption",
    "inferred",
    "infers",
    "guess",
    "presumab",
)


# Rejection-reason rule: a validation message names the *field* that was refused,
# and at most the Python *type* of what was supplied. It never quotes the
# supplied value. A rejected candidate value is untrusted content by definition --
# it may be a passphrase, a key fragment, a config line, or a parser payload that
# a defective caller passed where an identifier or timestamp belonged -- and
# `collect_relationships` retains these messages as `RelationshipCollection`
# rejection text. Quoting the value would carry exactly the material the privacy
# boundary excludes into a record the model calls safe. The field name is enough
# to locate the defect; the value is the caller's to log, under its own boundary.
class RelationshipValidationError(ValueError):
    """A candidate relationship is not a valid internal relationship record.

    Raised at construction time so an invalid relationship object cannot exist,
    and therefore cannot be mistaken for observed evidence or reach any
    downstream consumer. Subclasses distinguish the specific outcomes the model
    must tell apart.
    """


class UnknownRelationshipTypeError(RelationshipValidationError):
    """The relationship type is outside the fixed vocabulary."""


class MissingEndpointError(RelationshipValidationError):
    """An endpoint does not reference a known finding (a dangling relationship)."""


class SelfRelationshipError(RelationshipValidationError):
    """Source and target are the same finding.

    Rejected because no current relationship type requires a self-relationship:
    a container does not contain itself, and matching key material with itself
    is not an observation.
    """


class MalformedRelationshipError(RelationshipValidationError):
    """The relationship object is structurally invalid.

    Covers a missing or unsafe text field, an unsupported confidence value, a
    non-identifier rule ID, a non-boolean repeatability flag, and a supplied
    ``relationship_id`` that does not match the deterministic identity.
    """


class RelationshipModelError(RuntimeError):
    """An unexpected implementation failure inside the relationship model.

    Distinct from every validation outcome above: a validation failure is a
    statement about the candidate, while this is a defect in the model or its
    caller. It is never converted into a clean "no relationship" result, because
    absence of a relationship must mean "nothing was observed", not "something
    broke".

    The message names the stage and the exception *type* only. The original
    message is deliberately omitted, matching ``DetectorExecutionError``: a
    parser exception can quote the bytes it choked on, and raw content must
    never travel with an error.
    """

    def __init__(self, stage: str, cause: BaseException):
        self.stage = stage
        self.cause = cause
        super().__init__(
            f"relationship model failed during {stage}: {type(cause).__name__}"
        )


class RelationshipOutcome(str, Enum):
    """The seven outcomes the model distinguishes for one candidate.

    ``DUPLICATE`` is not an error: the same relationship observed twice is
    expected, and suppression is the correct handling. The remaining non-valid
    outcomes each name why a candidate was refused, so a caller can never read a
    rejection as an observation.
    """

    VALID = "valid"
    DUPLICATE = "duplicate"
    MISSING_ENDPOINT = "missing_endpoint"
    INVALID_TYPE = "invalid_type"
    SELF_RELATIONSHIP = "self_relationship"
    MALFORMED = "malformed"
    MODEL_ERROR = "model_error"


@dataclass(frozen=True)
class RelationshipProvenance:
    """Read-only view over a relationship's provenance fields.

    Mirrors ``findings.Provenance``: the underlying fields stay flat on
    ``CryptoRelationship`` so construction is one plain call, and this exists for
    callers that want structured access. Safe values only -- a component name, a
    rule ID, a scan context, a repeatability flag, and a collection timestamp.
    Never raw asset contents.
    """

    created_by: str
    relationship_rule_id: str
    scan_id: str
    collected_at: str
    repeatable: bool


@dataclass(frozen=True)
class CryptoRelationship:
    """One directly observed structural relationship between two findings.

    Immutable, and narrow on purpose: there is no metadata dictionary and no
    free-form field, so the only things a relationship can carry are stable
    finding IDs, a vocabulary type, a rule ID, bounded evidence text,
    confidence, safe provenance, repeatability, limitations, and errors.

    Validation happens in ``__post_init__``, so an invalid relationship object
    cannot be constructed at all. Endpoint *existence* is the one check this
    class cannot make on its own -- it does not know the finding universe -- so
    use ``build_relationship`` (or ``validate_endpoints``) with the set of known
    finding IDs whenever endpoints must be proven to exist.
    """

    relationship_type: RelationshipType
    source_finding_id: str
    target_finding_id: str
    evidence: str
    confidence: str
    relationship_rule_id: str
    scan_id: str
    created_by: str = RELATIONSHIP_MODEL_COMPONENT
    observed_at: str | datetime | None = None
    repeatable: bool = True
    limitations: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()
    relationship_id: str | None = None

    def __post_init__(self) -> None:
        relationship_type = coerce_relationship_type(self.relationship_type)
        source = _require_finding_id(self.source_finding_id, "source_finding_id")
        target = _require_finding_id(self.target_finding_id, "target_finding_id")
        if source == target:
            raise SelfRelationshipError(
                "source_finding_id and target_finding_id must differ for "
                f"{relationship_type.value}"
            )
        evidence = _require_evidence(self.evidence)
        confidence = _require_confidence(self.confidence)
        rule_id = _require_identifier(self.relationship_rule_id, "relationship_rule_id")
        created_by = _require_identifier(self.created_by, "created_by")
        # Required, not optional: provenance must explain which scan context
        # observed the relationship, so a record with no scan context is
        # malformed rather than a record with unknown provenance.
        scan_id = _require_identifier(self.scan_id, "scan_id")
        if not isinstance(self.repeatable, bool):
            raise MalformedRelationshipError(
                "repeatable must be a bool: "
                f"{type(self.repeatable).__name__}"
            )
        limitations = _safe_text_tuple(self.limitations, "limitations")
        errors = _safe_text_tuple(self.errors, "errors")
        # Symmetric canonicalization happens before identity is derived, so
        # reversed input for `corresponds_to` produces one identical record --
        # same endpoints in the same order, same ID -- while a directional type
        # keeps the caller's order and therefore a distinct ID when reversed.
        source, target = canonical_endpoints(relationship_type, source, target)
        derived_id = derive_relationship_id(relationship_type, source, target, rule_id)
        if self.relationship_id is not None and self.relationship_id != derived_id:
            raise MalformedRelationshipError(
                "relationship_id does not match the deterministic identity for this "
                "relationship"
            )

        object.__setattr__(self, "relationship_type", relationship_type)
        object.__setattr__(self, "source_finding_id", source)
        object.__setattr__(self, "target_finding_id", target)
        object.__setattr__(self, "evidence", evidence)
        object.__setattr__(self, "confidence", confidence)
        object.__setattr__(self, "relationship_rule_id", rule_id)
        object.__setattr__(self, "created_by", created_by)
        object.__setattr__(self, "scan_id", scan_id)
        object.__setattr__(self, "observed_at", _normalize_observed_at(self.observed_at))
        object.__setattr__(self, "limitations", limitations)
        object.__setattr__(self, "errors", errors)
        object.__setattr__(self, "relationship_id", derived_id)

    @property
    def is_symmetric(self) -> bool:
        return self.relationship_type in SYMMETRIC_RELATIONSHIP_TYPES

    @property
    def provenance(self) -> RelationshipProvenance:
        return RelationshipProvenance(
            created_by=self.created_by,
            relationship_rule_id=self.relationship_rule_id,
            scan_id=self.scan_id,
            collected_at=self.observed_at,
            repeatable=self.repeatable,
        )


@dataclass(frozen=True)
class RelationshipCollection:
    """The result of classifying a batch of candidate relationships.

    ``relationships`` holds the deduplicated, deterministically ordered valid
    records. ``outcomes`` is index-aligned with the input, so every candidate is
    accounted for. ``rejections`` carries one safe line per non-valid candidate:
    the candidate index, the outcome, and a reason naming the refused field (and
    at most the Python type supplied). A rejected candidate *value* never appears
    -- an invalid value is untrusted content, and the rejection-reason rule above
    ``RelationshipValidationError`` explains why quoting it would defeat the
    privacy boundary.

    ``has_model_errors`` exists so an unexpected failure cannot masquerade as
    absence of relationships: a caller that reads ``relationships`` must check
    it before treating an empty collection as "nothing was observed".
    """

    relationships: tuple[CryptoRelationship, ...] = ()
    outcomes: tuple[RelationshipOutcome, ...] = ()
    rejections: tuple[str, ...] = ()

    @property
    def has_model_errors(self) -> bool:
        return RelationshipOutcome.MODEL_ERROR in self.outcomes

    def counts(self) -> dict[str, int]:
        """Per-outcome candidate counts.

        Internal bookkeeping for the model's own callers and tests. It is not
        scanner accounting: relationships never contribute to ``Files scanned``
        or ``Crypto files inspected``, and no relationship count is added to any
        console summary or report in HG-034.
        """
        counts = {outcome.value: 0 for outcome in RelationshipOutcome}
        for outcome in self.outcomes:
            counts[outcome.value] += 1
        return counts


def coerce_relationship_type(value: Any) -> RelationshipType:
    """``value`` as a vocabulary member, or ``UnknownRelationshipTypeError``.

    Accepts a ``RelationshipType`` or its exact string value. Anything else --
    an unlisted name, a vague relation such as ``related_to`` or ``depends_on``,
    a differently-cased string, a non-string -- is rejected, which is what makes
    the vocabulary closed rather than conventional.
    """
    if isinstance(value, RelationshipType):
        return value
    if isinstance(value, str):
        try:
            return RelationshipType(value)
        except ValueError as exc:
            # The rejected value is deliberately not quoted -- see the
            # rejection-reason rule above `RelationshipValidationError`.
            raise UnknownRelationshipTypeError(
                "relationship_type is outside the fixed relationship vocabulary"
            ) from exc
    raise UnknownRelationshipTypeError(
        f"relationship_type must be a relationship type or string: {type(value).__name__}"
    )


def canonical_endpoints(
    relationship_type: RelationshipType, source_finding_id: str, target_finding_id: str
) -> tuple[str, str]:
    """The endpoint pair as identity sees it.

    Directional types keep the caller's order, so reversing the endpoints is a
    genuinely different relationship. Symmetric types are sorted, so the two
    orderings of one observation collapse to a single record and a single ID.
    """
    if relationship_type in SYMMETRIC_RELATIONSHIP_TYPES:
        return tuple(sorted((source_finding_id, target_finding_id)))  # type: ignore[return-value]
    return source_finding_id, target_finding_id


def derive_relationship_id(
    relationship_type: RelationshipType,
    source_finding_id: str,
    target_finding_id: str,
    relationship_rule_id: str,
) -> str:
    """The deterministic relationship identity.

    Derived from four stable fields only: the relationship type, both stable
    finding IDs (already canonicalized for symmetric types by the caller), and
    the relationship rule ID.

    Everything volatile is excluded by construction -- timestamps, scan ID,
    host, process ID, traversal order, detector order, file counts, confidence,
    evidence prose, provenance text, limitations, errors, and the order in which
    relationships happened to be built. Re-observing the same relationship in a
    later scan therefore yields the same ID, and rewording evidence never churns
    identity.
    """
    payload = {
        "relationship_type": relationship_type.value,
        "source_finding_id": source_finding_id,
        "target_finding_id": target_finding_id,
        "relationship_rule_id": relationship_rule_id,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def index_finding_ids(findings: Iterable[Any]) -> frozenset[str]:
    """The stable finding IDs of ``findings``, for endpoint validation.

    Reads ``finding_id`` and nothing else, and returns a frozenset: relationship
    work cannot mutate a finding, re-identify one, or hold a reference that lets
    it do so later.
    """
    return frozenset(
        finding_id
        for finding_id in (getattr(finding, "finding_id", None) for finding in findings)
        if isinstance(finding_id, str) and finding_id
    )


def validate_endpoints(
    relationship: CryptoRelationship, known_finding_ids: Iterable[str]
) -> None:
    """Raise ``MissingEndpointError`` unless both endpoints name a known finding.

    Dangling relationships are invalid: a relationship references assets
    HarvestGuard already observed and never creates a synthetic one, so an
    endpoint the finding universe does not contain is not evidence of anything.
    """
    known = known_finding_ids if isinstance(known_finding_ids, frozenset) else frozenset(
        known_finding_ids
    )
    for label, finding_id in (
        ("source", relationship.source_finding_id),
        ("target", relationship.target_finding_id),
    ):
        if finding_id not in known:
            raise MissingEndpointError(f"{label} endpoint does not reference a known finding")


def build_relationship(
    known_finding_ids: Iterable[str], **kwargs: Any
) -> CryptoRelationship:
    """A validated relationship whose endpoints are proven to exist.

    The construction entry point callers should use: it applies every
    ``CryptoRelationship`` validation *and* endpoint existence, so a relationship
    that reaches a caller is never dangling. Unexpected keyword arguments raise
    ``TypeError`` from the dataclass itself -- there is no metadata dictionary to
    absorb them, which is why arbitrary fields cannot be attached to a
    relationship at all.
    """
    relationship = CryptoRelationship(**kwargs)
    validate_endpoints(relationship, known_finding_ids)
    return relationship


def relationship_sort_key(relationship: CryptoRelationship) -> tuple[str, ...]:
    """The deterministic ordering key for a relationship collection.

    Uses the same stable fields identity uses, so ordering depends on what was
    observed rather than on construction, traversal, or detector order. Two runs
    over the same relationship set therefore produce the same sequence.
    """
    return (
        relationship.relationship_type.value,
        relationship.relationship_rule_id,
        relationship.source_finding_id,
        relationship.target_finding_id,
    )


def canonical_record_key(relationship: CryptoRelationship) -> tuple[object, ...]:
    """The tie-break order among duplicates that share one identity.

    Two candidates with the same identity may still differ in volatile fields:
    evidence wording, confidence, creating component, scan context, collection
    time, repeatability, limitations, errors. Which one survives suppression must
    not depend on the order the candidates happened to arrive in, so this covers
    every non-identity field and gives duplicates a total order.

    The ordering is plain lexicographic and carries no meaning: it is a
    deterministic tie-break, not a ranking, not a merge, and not evidence-history
    aggregation. Identity fields are excluded because duplicates share them.
    """
    return (
        relationship.evidence,
        relationship.confidence,
        relationship.created_by,
        relationship.scan_id,
        relationship.observed_at,
        relationship.repeatable,
        relationship.limitations,
        relationship.errors,
    )


def _canonical_of(
    existing: CryptoRelationship, candidate: CryptoRelationship
) -> CryptoRelationship:
    """The canonical one of two records sharing an identity.

    Commutative, so folding a batch in any order reaches the same record.
    """
    if canonical_record_key(candidate) < canonical_record_key(existing):
        return candidate
    return existing


def deduplicate_relationships(
    relationships: Iterable[CryptoRelationship],
) -> tuple[CryptoRelationship, ...]:
    """One canonical record per relationship identity, deterministically ordered.

    The same relationship observed several times collapses to a single record
    when its type, its endpoints (under the direction rules), and its rule ID
    match -- that is exactly the identity tuple, so suppression and identity can
    never disagree. Different types and different rule IDs stay distinct.

    Selection is order-independent: the retained record is the minimum under
    ``canonical_record_key``, not the first one seen, so two batches holding the
    same observations in different orders produce the same canonical record even
    when duplicates differ in evidence wording or provenance. HG-034 does not
    aggregate evidence history, merge unrelated evidence types, or deduplicate
    transitively: there is no traversal here, only exact identity.
    """
    canonical: dict[str, CryptoRelationship] = {}
    for relationship in relationships:
        relationship_id = relationship.relationship_id
        assert relationship_id is not None  # set in __post_init__
        existing = canonical.get(relationship_id)
        canonical[relationship_id] = (
            relationship if existing is None else _canonical_of(existing, relationship)
        )
    return tuple(sorted(canonical.values(), key=relationship_sort_key))


def collect_relationships(
    candidates: Iterable[Any], known_finding_ids: Iterable[str]
) -> RelationshipCollection:
    """Classify ``candidates`` into a validated, deduplicated collection.

    Each candidate may be a ``CryptoRelationship`` or a mapping of constructor
    keyword arguments. Every candidate gets exactly one outcome, so no rejection
    is silent: an invalid type, a dangling endpoint, a self-relationship, a
    malformed object, a duplicate, and an unexpected model failure are all
    distinguishable, and no rejected candidate reaches ``relationships``.

    ``VALID`` versus ``DUPLICATE`` describes each candidate's position -- the
    first arrival of an identity against a later repeat of it -- while the
    canonical record kept for that identity is chosen order-independently by
    ``deduplicate_relationships``.

    An unexpected exception is recorded as ``MODEL_ERROR`` rather than dropped,
    so a caller cannot mistake a broken batch for a batch that observed no
    relationships (see ``RelationshipCollection.has_model_errors``).
    """
    known = frozenset(known_finding_ids)
    accepted: dict[str, CryptoRelationship] = {}
    outcomes: list[RelationshipOutcome] = []
    rejections: list[str] = []

    for index, candidate in enumerate(candidates):
        try:
            if isinstance(candidate, CryptoRelationship):
                relationship = candidate
                validate_endpoints(relationship, known)
            elif isinstance(candidate, Mapping):
                relationship = build_relationship(known, **candidate)
            else:
                raise MalformedRelationshipError(
                    f"candidate must be a CryptoRelationship or mapping, got "
                    f"{type(candidate).__name__}"
                )
        except UnknownRelationshipTypeError as exc:
            outcomes.append(RelationshipOutcome.INVALID_TYPE)
            rejections.append(f"candidate {index}: invalid_type: {exc}")
            continue
        except MissingEndpointError as exc:
            outcomes.append(RelationshipOutcome.MISSING_ENDPOINT)
            rejections.append(f"candidate {index}: missing_endpoint: {exc}")
            continue
        except SelfRelationshipError as exc:
            outcomes.append(RelationshipOutcome.SELF_RELATIONSHIP)
            rejections.append(f"candidate {index}: self_relationship: {exc}")
            continue
        except (RelationshipValidationError, TypeError) as exc:
            # TypeError is the dataclass rejecting an unknown or missing keyword,
            # which is a malformed candidate, not a model defect.
            outcomes.append(RelationshipOutcome.MALFORMED)
            rejections.append(f"candidate {index}: malformed: {exc}")
            continue
        except Exception as exc:  # noqa: BLE001 - deliberately broad; see below.
            # Anything else is a defect in the model or its caller. It is
            # attributed, never converted into a valid absence of relationship.
            outcomes.append(RelationshipOutcome.MODEL_ERROR)
            rejections.append(
                f"candidate {index}: model_error: "
                f"{RelationshipModelError('classification', exc)}"
            )
            continue

        relationship_id = relationship.relationship_id
        assert relationship_id is not None  # set in __post_init__
        if relationship_id in accepted:
            outcomes.append(RelationshipOutcome.DUPLICATE)
            rejections.append(f"candidate {index}: duplicate: {relationship_id}")
            # The outcome per candidate is positional -- the first arrival of an
            # identity is VALID and later ones are DUPLICATE -- but which record
            # is retained is not: duplicates are folded so the canonical record
            # is the same whatever order the batch arrived in.
            accepted[relationship_id] = _canonical_of(
                accepted[relationship_id], relationship
            )
            continue
        accepted[relationship_id] = relationship
        outcomes.append(RelationshipOutcome.VALID)

    return RelationshipCollection(
        relationships=deduplicate_relationships(accepted.values()),
        outcomes=tuple(outcomes),
        rejections=tuple(rejections),
    )


def _require_text(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise MalformedRelationshipError(
            f"{label} must be a string: {type(value).__name__}"
        )
    text = value.strip()
    if not text:
        raise MalformedRelationshipError(f"{label} is required")
    if len(text) > MAX_TEXT_FIELD_CHARS:
        raise MalformedRelationshipError(
            f"{label} exceeds {MAX_TEXT_FIELD_CHARS} characters"
        )
    if not text.isprintable():
        raise MalformedRelationshipError(f"{label} contains non-printable characters")
    for marker in _RAW_MATERIAL_MARKERS:
        if marker in text:
            raise MalformedRelationshipError(
                f"{label} contains raw cryptographic material"
            )
    return text


def _require_evidence(value: Any) -> str:
    text = _require_text(value, "evidence")
    lowered = text.lower()
    # The matched term is not quoted either: it is a substring of the rejected
    # evidence, so echoing it would echo part of the candidate.
    for term in _PROHIBITED_CLAIM_TERMS:
        if term in lowered:
            raise MalformedRelationshipError(
                "evidence must describe only what was observed, not an assessment "
                "claim"
            )
    for term in _PROHIBITED_INFERENCE_TERMS:
        if term in lowered:
            raise MalformedRelationshipError(
                "evidence must be directly observed structural evidence, not "
                "inference wording"
            )
    return text


def _require_confidence(value: Any) -> str:
    if value not in SUPPORTED_RELATIONSHIP_CONFIDENCE:
        raise MalformedRelationshipError(
            f"confidence must be one of {list(SUPPORTED_RELATIONSHIP_CONFIDENCE)}"
        )
    return value


def _require_identifier(value: Any, label: str) -> str:
    text = _require_text(value, label)
    if not _IDENTIFIER_PATTERN.match(text):
        raise MalformedRelationshipError(f"{label} must be a machine identifier")
    return text


def _require_finding_id(value: Any, label: str) -> str:
    text = _require_text(value, label)
    if not _FINDING_ID_PATTERN.match(text):
        raise MalformedRelationshipError(f"{label} must be a stable finding id")
    return text


def _safe_text_tuple(value: Any, label: str) -> tuple[str, ...]:
    if isinstance(value, str) or isinstance(value, Mapping):
        raise MalformedRelationshipError(f"{label} must be a sequence of strings")
    try:
        items = list(value)
    except TypeError as exc:
        raise MalformedRelationshipError(
            f"{label} must be a sequence of strings"
        ) from exc
    return tuple(_require_text(item, label) for item in items)


def _normalize_observed_at(value: str | datetime | None) -> str:
    """The collection timestamp, normalized the way findings normalize theirs.

    Defaults to now: provenance must record *when* HarvestGuard collected the
    relationship evidence, so this field is always populated. A supplied value
    must be an actual point in time -- a ``datetime``, or an ISO-8601 date-time
    string of the shape ``datetime.isoformat()`` produces -- and is normalized to
    a timezone-aware, whole-second string (a naive value is read as UTC, matching
    ``findings._normalize_timestamp``). Arbitrary text is rejected: a string that
    is not a timestamp is a malformed relationship, not a collection time.

    The timestamp is never part of identity, so a new one on every observation
    cannot churn relationship IDs.
    """
    if value is None:
        value = datetime.now(timezone.utc)
    if isinstance(value, datetime):
        return _format_observed_at(value)
    text = _require_text(value, "observed_at")
    # `fromisoformat` accepts a bare date, which is not a collection time;
    # requiring the date/time separator keeps the accepted shape the same as the
    # emitted one. Python 3.10's parser also predates 'Z' support.
    normalized = (text[:-1] + "+00:00") if text.endswith("Z") else text
    if "T" not in normalized:
        raise MalformedRelationshipError("observed_at must be an ISO-8601 date-time")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise MalformedRelationshipError("observed_at must be an ISO-8601 date-time") from exc
    return _format_observed_at(parsed)


def _format_observed_at(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.replace(microsecond=0).isoformat()


def _check_vocabulary_partition() -> None:
    """Every relationship type must declare exactly one direction behavior.

    Import-time, so adding a vocabulary member without deciding whether it is
    directional or symmetric fails immediately rather than defaulting silently to
    directional at the first call site.
    """
    declared = DIRECTIONAL_RELATIONSHIP_TYPES | SYMMETRIC_RELATIONSHIP_TYPES
    overlap = DIRECTIONAL_RELATIONSHIP_TYPES & SYMMETRIC_RELATIONSHIP_TYPES
    missing = set(RelationshipType) - declared
    if overlap or missing:
        raise RuntimeError(
            "relationship direction declarations must partition the vocabulary: "
            f"overlap={sorted(t.value for t in overlap)} "
            f"missing={sorted(t.value for t in missing)}"
        )


def _check_no_mapping_fields() -> None:
    """No relationship field may be a mapping.

    The privacy boundary is structural: with no dictionary field there is no
    generic channel for arbitrary metadata, raw config, parser payloads, or key
    material to be attached to a relationship. This asserts that at import time
    so a future field addition cannot quietly reopen one.
    """
    for model_field in fields(CryptoRelationship):
        annotation = str(model_field.type)
        if "dict" in annotation or "Mapping" in annotation or "Any" in annotation:
            raise RuntimeError(
                "CryptoRelationship must not carry a mapping or free-form field: "
                f"{model_field.name}"
            )


_check_vocabulary_partition()
_check_no_mapping_fields()
