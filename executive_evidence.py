"""The one derived executive view of a stored HarvestGuard scan run.

Why this exists: an executive Markdown renderer and an executive JSON export
must never disagree about what a stored run means. If each renderer decided on
its own what "verified" was, what counted as an evidence record, or which
scanner failures mattered, the same stored scan would carry two meanings. This
module is the single place where a verified stored run becomes a status, a set
of identified checks, observations and bounded technical derivations. Renderers
consume this projection; they do not re-derive any of it.

What this module is, and is not:

- It is a *derived* read model. `NormalizedFinding` snapshots, the evidence
  store, the digest contract and the reporting helpers are untouched; this
  module reads them and adds nothing to storage.
- It is not a verifier. Integrity is established by `evidence_store`'s existing
  verified load path, which fails closed. A run this module cannot obtain
  through that path produces no view at all -- never an evidence-bearing view
  with a "failed" integrity row.
- It is not an assessment. There are no risk scores, no trust scores, no
  remediation, no compliance verdicts and no business judgment. Every statement
  is labelled as an observation, a check result, or a bounded derivation, and
  every one is produced from a fixed template, never generated prose.

Time: historical derivations use the run's *recorded* scan time and nothing
else. Export time is an explicit, required argument. This module never reads the
clock, so a fixed stored run plus a fixed export time always produces an
identical projection, and re-exporting an old run next year does not change what
that run's evidence supported.

Evidence identity: a reference is `(scan_id, ordinal, finding_id)`, where the
ordinal is the snapshot occurrence in canonical stored order. Two snapshots that
share a `finding_id` stay two occurrences: evidence is never deduplicated by
finding ID, and stored order is never re-sorted.

See docs/EXECUTIVE_EVIDENCE_VIEW.md for the policy, the check catalogue, the
supported scanner/version mapping and the executive JSON schema this projection
is designed to serialize into (serialization itself is not implemented here).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Any

from evidence_store import StoredScanRun, load_scan_run
from findings import SCHEMA_VERSION as CURRENT_FINDING_SCHEMA_VERSION
from findings import NormalizedFinding
from harvestguard_version import __version__ as HARVESTGUARD_VERSION
from reports import (
    CATEGORY_COVERAGE_LIMITATION,
    CATEGORY_LABELS,
    CATEGORY_SKIPPED_OR_INACCESSIBLE,
    SUMMARY_CATEGORIES,
    ScanReportContext,
    classify_finding,
    summarize_findings,
)

# Versioned independently of the finding schema, the evidence-store schema and
# the HarvestGuard release. A policy change (which checks are required, how a
# state is decided) bumps the policy version; a change to the shape of the
# projection bumps the schema version.
EXECUTIVE_SCHEMA_VERSION = "0.1.0"
EXECUTIVE_POLICY_VERSION = "0.1.0"

# --- Status vocabulary -----------------------------------------------------

STATUS_FAILED = "FAILED"
STATUS_INCOMPLETE = "INCOMPLETE"
STATUS_WARNING = "WARNING"
STATUS_VERIFIED = "VERIFIED"

# Highest precedence first. All individual results survive regardless of which
# status wins: precedence decides the headline, never what is retained.
STATUS_PRECEDENCE = (STATUS_FAILED, STATUS_INCOMPLETE, STATUS_WARNING, STATUS_VERIFIED)

STATUS_STATEMENTS = MappingProxyType({
    STATUS_VERIFIED: (
        "Evidence evaluation: VERIFIED. Every required evidence-integrity and "
        "evaluation check explicitly listed in this view completed and passed "
        "for the declared scope, with no outcome-affecting exception. No "
        "required check is failed, unknown, or unperformed. This does not "
        "establish source authenticity, complete environmental coverage, "
        "organizational security, regulatory compliance, or business safety."
    ),
    STATUS_WARNING: (
        "Evidence evaluation: WARNING. Every required check listed in this view "
        "passed for the declared scope, but at least one specifically defined "
        "exception needs attention. This does not establish source "
        "authenticity, complete environmental coverage, organizational "
        "security, regulatory compliance, or business safety."
    ),
    STATUS_INCOMPLETE: (
        "Evidence evaluation: INCOMPLETE. At least one required check or "
        "requested evaluation could not be completed or established for the "
        "declared scope. Retained evidence remains valid for what it records; "
        "what could not be established is listed as an unknown."
    ),
    STATUS_FAILED: (
        "Evidence evaluation: FAILED. At least one required check completed and "
        "failed for the declared scope. Individual passed checks and retained "
        "evidence are still listed; they do not offset the failed check."
    ),
})

# --- Check states ----------------------------------------------------------

CHECK_PASSED = "passed"
CHECK_FAILED = "failed"
CHECK_UNKNOWN = "unknown"
CHECK_UNPERFORMED = "unperformed"
CHECK_NOT_APPLICABLE = "not_applicable"

CHECK_STATES = (
    CHECK_PASSED,
    CHECK_FAILED,
    CHECK_UNKNOWN,
    CHECK_UNPERFORMED,
    CHECK_NOT_APPLICABLE,
)

# --- Explanation kinds -----------------------------------------------------

EXPLANATION_OBSERVATION = "observation"
EXPLANATION_CHECK_RESULT = "check_result"
EXPLANATION_BOUNDED_DERIVATION = "bounded_derivation"

# --- Policy tables ---------------------------------------------------------

# Finding-schema versions this policy version knows how to interpret. An
# unrecognized version is not rejected as evidence -- the stored snapshot is
# still retained and referenced -- but it cannot silently pass the supported
# interpretation check.
SUPPORTED_FINDING_SCHEMA_VERSIONS = frozenset({CURRENT_FINDING_SCHEMA_VERSION})

# Scanner/version pairs whose *collection contract* is documented well enough
# for this policy to interpret an empty result or an empty scanner-error list.
# The value is the evidence basis for including the pair. A pair that is absent
# is unknown, never passing by default: an empty error list from a scanner whose
# failure semantics are undocumented does not establish that the scanner ran to
# completion. New pairs are added only once their contract is documented (see
# docs/EXECUTIVE_EVIDENCE_VIEW.md).
SUPPORTED_COLLECTION_CONTRACTS = MappingProxyType({
    ("semgrep_crypto_rules", "0.2.0"): (
        "Collection contract 0.2.0 propagates execution and output failures "
        "through LocalScanError into the run's recorded scanner_errors, "
        "retaining usable partial findings "
        "(docs/DETECTION_CHARACTERIZATION.md, execution provenance)."
    ),
})

# Rule families that record scope deliberately not inspected by design or by
# configuration. They bound coverage and are disclosed as observations; they do
# not by themselves make scope observability unknown.
BY_DESIGN_SCOPE_RULE_IDS = frozenset({"max_depth_boundary", "skipped_special_file"})

# Keys a stored finding snapshot is expected to carry: every NormalizedFinding
# constructor field plus the nested provenance view `to_dict()` emits. Anything
# else is retained and named rather than silently dropped.
_KNOWN_SNAPSHOT_KEYS = frozenset(NormalizedFinding.__dataclass_fields__) | {"provenance"}

_OPTIONAL_PROVENANCE_FIELDS = (
    "collection_method",
    "collection_source",
    "repeatable",
    "verification_rationale",
)

# Fixed limits on what this view can support, stated unconditionally. These are
# not conclusions about a particular run; they bound every run.
STANDING_LIMITS = (
    "A matching stored digest establishes internal consistency of the stored "
    "run only. It is not a signature, not proof of source authenticity, and no "
    "protection against deliberate modification of both the payload and the "
    "digest by anyone who can write to the evidence database.",
    "This view describes retained normalized evidence from one scan run. It "
    "does not establish that a scanned asset is deployed, in use, trusted, or "
    "reachable.",
    "Absence of a record is not evidence of absence: each scanner has a "
    "deliberately narrow detection surface (docs/DETECTION_CHARACTERIZATION.md).",
    "No conflict assessment ran, so conflicts between records are not assessed. "
    "This view does not state that there are no conflicts.",
    "Certificate expiration is a dated technical derivation against the "
    "recorded scan time. It is not a risk rating, a remediation verdict, or a "
    "statement of business impact.",
    "This view establishes evidence. It does not establish organizational "
    "security, regulatory compliance, quantum readiness, or business safety; "
    "those remain human judgment.",
)


class ExecutiveEvidenceError(Exception):
    """The projection could not be built from the inputs as given.

    Integrity and storage failures are *not* raised here: they propagate
    unchanged from `evidence_store` so there is exactly one verifier and one
    bounded failure vocabulary.
    """


# --- Model -----------------------------------------------------------------


@dataclass(frozen=True)
class EvidenceReference:
    """A resolvable pointer to one retained snapshot occurrence.

    `ordinal` is the snapshot's position in canonical stored order and is the
    identity: `finding_id` is carried for readability and traceability but is
    deliberately not the key, because the same finding ID can legitimately
    occur more than once within a run and across runs.
    """

    scan_id: str
    ordinal: int
    finding_id: str | None = None

    def to_reference_string(self) -> str:
        return f"{self.scan_id}#{self.ordinal}"


@dataclass(frozen=True)
class FindingOccurrence:
    """One retained snapshot occurrence, in canonical stored order.

    `raw_snapshot` is the exact stored payload, including any key this release
    does not recognize, so a projection built by a newer or older reader does
    not silently discard what was stored. `finding` is the reconstructed
    immutable `NormalizedFinding`, unchanged.
    """

    ordinal: int
    finding: NormalizedFinding
    raw_snapshot: Mapping[str, Any]

    @property
    def reference(self) -> EvidenceReference:
        return EvidenceReference(
            scan_id=self.finding.scan_id or "",
            ordinal=self.ordinal,
            finding_id=self.finding.finding_id,
        )


@dataclass(frozen=True)
class CheckRecord:
    """One identified check: what was checked, how, on what, and its state.

    `required` is decided by the policy version from the declared scope and the
    supported collection contract *before* any result is examined, so a status
    can never be assembled by cherry-picking whichever checks happened to pass.
    """

    check_id: str
    name: str
    title: str
    required: bool
    applicable: bool
    state: str
    method: str
    statement: str
    references: tuple[EvidenceReference, ...] = ()
    source_references: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()
    not_applicable_reason: str | None = None


@dataclass(frozen=True)
class ExceptionRecord:
    """A specifically defined, named exception that needs attention.

    Only exceptions defined by this policy version exist; there is no open-ended
    "something looked odd" channel, and an exception never carries a severity,
    priority or recommendation.
    """

    exception_id: str
    name: str
    statement: str
    outcome_affecting: bool
    references: tuple[EvidenceReference, ...] = ()
    details: tuple[str, ...] = ()


@dataclass(frozen=True)
class ExplanationRecord:
    """One bounded technical statement, labelled by its nature.

    `nature` is exactly one of observation, check result, or bounded
    derivation, so a reader can always tell what a sentence is: something a
    scanner recorded, the result of an identified check, or a derivation this
    view computed from retained evidence by a stated method.
    """

    explanation_id: str
    nature: str
    statement: str
    method: str
    references: tuple[EvidenceReference, ...] = ()
    check_ids: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()


@dataclass(frozen=True)
class StatusReason:
    """Why the overall status is what it is, with its supporting references."""

    reason_id: str
    statement: str
    check_ids: tuple[str, ...] = ()
    exception_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class ScanScope:
    """The declared scope of the stored run, copied, never re-derived."""

    target_path: str
    scan_type: str | None
    scanners: tuple[str, ...]
    scanner_versions: Mapping[str, str]
    excluded_paths: tuple[str, ...]
    scope_constraints: tuple[str, ...]
    crypto_files_inspected: int | None


@dataclass(frozen=True)
class ExecutiveEvidenceView:
    """The immutable executive projection of exactly one stored scan run."""

    schema_version: str
    policy_version: str
    scan_id: str
    scan_time: str | None
    scan_time_basis: str
    export_time: str
    producing_harvestguard_version: str
    exporting_harvestguard_version: str
    finding_schema_version: str
    evidence_digest: str
    scope: ScanScope
    status: str
    status_statement: str
    status_reasons: tuple[StatusReason, ...]
    checks: tuple[CheckRecord, ...]
    exceptions: tuple[ExceptionRecord, ...]
    observations: tuple[ExplanationRecord, ...]
    conclusions: tuple[ExplanationRecord, ...]
    unknowns: tuple[str, ...]
    limits: tuple[str, ...]
    counts: Mapping[str, int]
    scanner_errors: tuple[str, ...]
    occurrences: tuple[FindingOccurrence, ...]

    def check(self, check_id: str) -> CheckRecord:
        """The check with this stable policy ID."""
        for record in self.checks:
            if record.check_id == check_id:
                return record
        raise KeyError(check_id)

    def resolve(self, reference: EvidenceReference) -> FindingOccurrence:
        """The exact snapshot occurrence a reference points at.

        Resolution is by ordinal, so two occurrences sharing a `finding_id`
        resolve to their own distinct snapshots.
        """
        if reference.scan_id and reference.scan_id != self.scan_id:
            raise KeyError(reference.to_reference_string())
        for occurrence in self.occurrences:
            if occurrence.ordinal == reference.ordinal:
                return occurrence
        raise KeyError(reference.to_reference_string())


# --- Construction ----------------------------------------------------------


def build_executive_evidence_view(
    run: StoredScanRun,
    export_time: str | datetime,
    exporting_harvestguard_version: str = HARVESTGUARD_VERSION,
) -> ExecutiveEvidenceView:
    """Project one already-verified stored run into the executive view.

    `run` must come from `evidence_store`'s verified load path (see
    `load_executive_evidence_view`): a run that fails integrity verification
    never reaches this function, because the loader raises instead of returning
    a payload. `export_time` is required and explicit -- this module never reads
    the clock, so the same stored run and export time always project identically.
    """
    if not isinstance(run, StoredScanRun):
        raise ExecutiveEvidenceError(
            "an executive evidence view is built from a verified StoredScanRun, "
            f"got {type(run).__name__}"
        )
    export_stamp = _normalize_export_time(export_time)
    context = run.context
    occurrences = _occurrences(run)
    scan_dt = _parse_timestamp(context.scan_time)

    counts = _counts(run.findings, scan_dt)
    checks = _evaluate_checks(run, occurrences, scan_dt)
    exceptions = _evaluate_exceptions(occurrences)
    status, reasons = _resolve_status(checks, exceptions)

    observations = _observations(run, occurrences, counts)
    conclusions = _conclusions(run, occurrences, counts, scan_dt, checks)
    unknowns = _unknowns(checks, scan_dt)

    return ExecutiveEvidenceView(
        schema_version=EXECUTIVE_SCHEMA_VERSION,
        policy_version=EXECUTIVE_POLICY_VERSION,
        scan_id=run.scan_id,
        scan_time=context.scan_time if scan_dt is not None else None,
        scan_time_basis=(
            "recorded scan time" if scan_dt is not None else "unknown: not recorded or unreadable"
        ),
        export_time=export_stamp,
        producing_harvestguard_version=run.harvestguard_version,
        exporting_harvestguard_version=str(exporting_harvestguard_version),
        finding_schema_version=run.finding_schema_version,
        evidence_digest=run.evidence_digest,
        scope=_scope(context),
        status=status,
        status_statement=STATUS_STATEMENTS[status],
        status_reasons=reasons,
        checks=checks,
        exceptions=exceptions,
        observations=observations,
        conclusions=conclusions,
        unknowns=unknowns,
        limits=STANDING_LIMITS,
        counts=MappingProxyType(dict(counts)),
        scanner_errors=tuple(str(error) for error in context.scanner_errors),
        occurrences=occurrences,
    )


def load_executive_evidence_view(
    db_path: str | Path,
    scan_id: str,
    export_time: str | datetime,
    exporting_harvestguard_version: str = HARVESTGUARD_VERSION,
) -> ExecutiveEvidenceView:
    """Load a stored run through the existing verified path and project it.

    Deliberately a thin wrapper: `evidence_store.load_scan_run` remains the only
    verifier. Its `EvidenceIntegrityError`, `ScanRunNotFoundError` and
    `EvidenceStoreError` propagate unchanged, so a rejected run yields that
    bounded failure and no view at all -- never a view carrying the rejected
    payload.
    """
    return build_executive_evidence_view(
        load_scan_run(db_path, scan_id),
        export_time=export_time,
        exporting_harvestguard_version=exporting_harvestguard_version,
    )


def _scope(context: ScanReportContext) -> ScanScope:
    return ScanScope(
        target_path=context.target_path,
        scan_type=context.scan_type,
        scanners=tuple(str(name) for name in context.scanners),
        scanner_versions=MappingProxyType(
            {str(name): str(version) for name, version in context.scanner_versions.items()}
        ),
        excluded_paths=tuple(str(item) for item in context.excluded_paths),
        scope_constraints=tuple(str(item) for item in context.scope_constraints),
        crypto_files_inspected=context.crypto_files_inspected,
    )


def _occurrences(run: StoredScanRun) -> tuple[FindingOccurrence, ...]:
    """Snapshot occurrences in canonical stored order, never re-sorted.

    The stored order *is* the canonical report order (`reports.sort_findings`
    at write time), so re-sorting here could only introduce disagreement. Raw
    snapshots come from the loader when it supplied them; a run constructed
    without them falls back to re-serializing the reconstructed finding, which
    is exact for every schema version this release recognizes.
    """
    raw = tuple(getattr(run, "raw_finding_snapshots", ()) or ())
    occurrences = []
    for ordinal, finding in enumerate(run.findings):
        payload = raw[ordinal] if ordinal < len(raw) else finding.to_dict()
        occurrences.append(
            FindingOccurrence(
                ordinal=ordinal,
                finding=finding,
                raw_snapshot=_freeze(dict(payload)),
            )
        )
    return tuple(occurrences)


def _counts(findings: list[NormalizedFinding], scan_dt: datetime | None) -> dict[str, int]:
    """Existing report counts, dated against the recorded scan time.

    `reports.summarize_findings` is reused rather than reimplemented so the
    executive view can never disagree with the technical report about how many
    records of each category a run retained. Its expiration figure is the one
    clock-dependent entry, so it is computed against the scan time; when the run
    has no usable scan time the key is omitted entirely rather than dated
    against an invented time.
    """
    counts = summarize_findings(findings, reference_time=scan_dt or _UNDATABLE_REFERENCE)
    if scan_dt is None:
        counts.pop("expired_certificates", None)
    return counts


# Only ever used to keep `summarize_findings` deterministic for a run with no
# usable scan time; the resulting expiration figure is discarded, not reported.
_UNDATABLE_REFERENCE = datetime(1, 1, 1, tzinfo=timezone.utc)


# --- Checks ----------------------------------------------------------------


def _evaluate_checks(
    run: StoredScanRun,
    occurrences: tuple[FindingOccurrence, ...],
    scan_dt: datetime | None,
) -> tuple[CheckRecord, ...]:
    """Every check this policy version defines, ordered by stable policy ID.

    The set and its required/applicable classification are fixed by the policy
    and the declared scope before any result is read; evaluation only fills in
    the state. The set is never empty, so no run can reach VERIFIED through an
    empty required-check set.
    """
    contract = _contract_check(run)
    checks = [
        _integrity_check(run),
        _schema_check(run, occurrences),
        contract,
        _execution_check(run, contract),
        _reference_check(run, occurrences),
        _scan_time_check(run, scan_dt),
        _scope_observability_check(occurrences),
        _expiration_basis_check(run, occurrences, scan_dt),
    ]
    return tuple(sorted(checks, key=lambda record: record.check_id))


def _integrity_check(run: StoredScanRun) -> CheckRecord:
    method = (
        "evidence_store.load_scan_run() recomputed the stored run's SHA-256 "
        "digest over its canonical run payload and ordered finding snapshots "
        "and compared it with the stored digest before this projection was "
        "built. A mismatch fails closed in the loader, so no view is produced."
    )
    limitations = (
        "Internal consistency of the stored run only: not a signature, not "
        "source authenticity, and no protection against modification of both "
        "the payload and the digest.",
    )
    if not run.evidence_digest:
        return CheckRecord(
            check_id="EV-CHK-001",
            name="evidence_integrity",
            title="Stored evidence integrity",
            required=True,
            applicable=True,
            state=CHECK_UNPERFORMED,
            method=method,
            statement=(
                "The run carries no stored evidence digest, so digest "
                "verification was not performed for it."
            ),
            source_references=("evidence_store.load_scan_run",),
            limitations=limitations,
        )
    return CheckRecord(
        check_id="EV-CHK-001",
        name="evidence_integrity",
        title="Stored evidence integrity",
        required=True,
        applicable=True,
        state=CHECK_PASSED,
        method=method,
        statement=(
            f"The stored run's recomputed digest matched the stored digest "
            f"{run.evidence_digest}."
        ),
        source_references=("evidence_store.load_scan_run",),
        limitations=limitations,
    )


def _schema_check(
    run: StoredScanRun, occurrences: tuple[FindingOccurrence, ...]
) -> CheckRecord:
    method = (
        "Compared the run's recorded normalized-finding schema version, and "
        "each retained snapshot's own schema version, with the schema versions "
        f"executive policy {EXECUTIVE_POLICY_VERSION} is defined to interpret: "
        + ", ".join(sorted(SUPPORTED_FINDING_SCHEMA_VERSIONS))
        + "."
    )
    observed = {str(run.finding_schema_version)}
    unsupported_refs = []
    for occurrence in occurrences:
        version = str(occurrence.finding.schema_version)
        observed.add(version)
        if version not in SUPPORTED_FINDING_SCHEMA_VERSIONS:
            unsupported_refs.append(occurrence.reference)
    unsupported = sorted(observed - set(SUPPORTED_FINDING_SCHEMA_VERSIONS))
    if unsupported:
        return CheckRecord(
            check_id="EV-CHK-002",
            name="supported_evidence_schema",
            title="Supported evidence interpretation",
            required=True,
            applicable=True,
            state=CHECK_UNKNOWN,
            method=method,
            statement=(
                "Unsupported normalized-finding schema version(s) "
                + ", ".join(unsupported)
                + f" are present; executive policy {EXECUTIVE_POLICY_VERSION} "
                "cannot establish that this evidence means what it appears to "
                "mean. The stored records are retained unchanged."
            ),
            references=tuple(unsupported_refs),
            limitations=(
                "An unsupported schema version is not a defect in the stored "
                "evidence; it means this policy version does not define how to "
                "interpret it.",
            ),
        )
    return CheckRecord(
        check_id="EV-CHK-002",
        name="supported_evidence_schema",
        title="Supported evidence interpretation",
        required=True,
        applicable=True,
        state=CHECK_PASSED,
        method=method,
        statement=(
            "Every retained record uses normalized-finding schema version "
            + ", ".join(sorted(observed))
            + ", which this policy version interprets."
        ),
    )


def _scanner_pairs(run: StoredScanRun) -> tuple[tuple[str, str], ...]:
    """Scanner/version pairs the run declared, plus any pair its records carry.

    A record produced by a scanner the run did not declare still counts: the
    contract question is about every scanner whose output is being interpreted,
    not only the declared list.
    """
    pairs = {
        (str(name), str(version)) for name, version in run.context.scanner_versions.items()
    }
    pairs.update(
        (str(finding.scanner_name), str(finding.scanner_version)) for finding in run.findings
    )
    return tuple(sorted(pairs))


def _contract_check(run: StoredScanRun) -> CheckRecord:
    method = (
        "Matched every scanner/version pair recorded for this run against the "
        f"collection contracts executive policy {EXECUTIVE_POLICY_VERSION} "
        "documents an evidence basis for. A pair with no documented contract is "
        "unknown; it does not pass by default."
    )
    limitations = (
        "The supported-contract mapping names scanner/version pairs whose "
        "execution-failure semantics are documented. It says nothing about "
        "detection quality or coverage for those scanners.",
    )
    pairs = _scanner_pairs(run)
    if not pairs:
        return CheckRecord(
            check_id="EV-CHK-003",
            name="supported_collection_contract",
            title="Supported collection contract",
            required=True,
            applicable=True,
            state=CHECK_UNKNOWN,
            method=method,
            statement=(
                "The stored run records no scanner/version pair, so no "
                "collection contract could be identified for it."
            ),
            limitations=limitations,
        )
    unsupported = [pair for pair in pairs if pair not in SUPPORTED_COLLECTION_CONTRACTS]
    if unsupported:
        return CheckRecord(
            check_id="EV-CHK-003",
            name="supported_collection_contract",
            title="Supported collection contract",
            required=True,
            applicable=True,
            state=CHECK_UNKNOWN,
            method=method,
            statement=(
                "No documented collection contract for scanner/version pair(s) "
                + ", ".join(f"{name} {version}" for name, version in unsupported)
                + ". Their execution-failure semantics are unknown to executive "
                f"policy {EXECUTIVE_POLICY_VERSION}."
            ),
            source_references=tuple(f"{name} {version}" for name, version in pairs),
            limitations=limitations,
        )
    return CheckRecord(
        check_id="EV-CHK-003",
        name="supported_collection_contract",
        title="Supported collection contract",
        required=True,
        applicable=True,
        state=CHECK_PASSED,
        method=method,
        statement=(
            "Every scanner/version pair recorded for this run has a documented "
            "collection contract: "
            + ", ".join(f"{name} {version}" for name, version in pairs)
            + "."
        ),
        source_references=tuple(
            SUPPORTED_COLLECTION_CONTRACTS[pair] for pair in pairs
        ),
        limitations=limitations,
    )


def _execution_check(run: StoredScanRun, contract: CheckRecord) -> CheckRecord:
    method = (
        "Read the run's recorded scanner_errors, and required every recorded "
        "scanner/version pair to have a documented collection contract "
        "(EV-CHK-003) before an empty error list could be read as successful "
        "execution."
    )
    limitations = (
        "An empty scanner-error list establishes execution completeness only "
        "for scanner/version pairs whose collection contract persists execution "
        "failures. Stored integrity verification never establishes scanner "
        "success.",
    )
    errors = [str(error) for error in run.context.scanner_errors]
    if errors:
        return CheckRecord(
            check_id="EV-CHK-004",
            name="execution_completeness",
            title="Execution completeness",
            required=True,
            applicable=True,
            state=CHECK_UNKNOWN,
            method=method,
            statement=(
                f"The run recorded {len(errors)} scanner error(s), so execution "
                "completeness cannot be established. Findings collected before "
                "the failure are retained and remain visible."
            ),
            source_references=tuple(errors),
            limitations=limitations,
        )
    if contract.state != CHECK_PASSED:
        return CheckRecord(
            check_id="EV-CHK-004",
            name="execution_completeness",
            title="Execution completeness",
            required=True,
            applicable=True,
            state=CHECK_UNKNOWN,
            method=method,
            statement=(
                "The run recorded no scanner errors, but at least one "
                "scanner/version pair has no documented collection contract "
                "(EV-CHK-003), so an empty error list does not establish that "
                "every scanner ran to completion."
            ),
            limitations=limitations,
        )
    return CheckRecord(
        check_id="EV-CHK-004",
        name="execution_completeness",
        title="Execution completeness",
        required=True,
        applicable=True,
        state=CHECK_PASSED,
        method=method,
        statement=(
            "Every recorded scanner/version pair persists execution failures "
            "into scanner_errors, and this run recorded none."
        ),
        limitations=limitations,
    )


def _reference_check(
    run: StoredScanRun, occurrences: tuple[FindingOccurrence, ...]
) -> CheckRecord:
    """Do this view's evidence references resolve to exactly one snapshot each?

    This is the check that can complete and *fail*: a run whose stored snapshots
    disagree with the run they are stored under, or whose reconstructed
    identities disagree with the stored payload, cannot carry resolvable
    references, and that is a determinate negative result rather than an unknown.
    """
    method = (
        "Resolved every evidence reference (scan_id, snapshot ordinal, "
        "finding_id) against the stored snapshots in canonical stored order, "
        "and compared each snapshot's recorded scan_id and finding_id with the "
        "run identity and the reconstructed record. Occurrences sharing a "
        "finding_id are not deduplicated."
    )
    limitations = (
        "Reference consistency is an identity check over stored records. It is "
        "not a content-integrity check and does not re-hash stored evidence.",
    )
    problems: list[str] = []
    failing: list[EvidenceReference] = []
    context_scan_id = run.context.scan_id
    if context_scan_id and context_scan_id != run.scan_id:
        problems.append(
            f"the stored scan context records scan_id {context_scan_id}, "
            f"but the run is stored under {run.scan_id}"
        )
    for occurrence in occurrences:
        reference = EvidenceReference(
            scan_id=run.scan_id,
            ordinal=occurrence.ordinal,
            finding_id=occurrence.finding.finding_id,
        )
        snapshot_scan_id = occurrence.raw_snapshot.get("scan_id")
        if snapshot_scan_id is not None and str(snapshot_scan_id) != run.scan_id:
            problems.append(
                f"snapshot {reference.to_reference_string()} records scan_id "
                f"{snapshot_scan_id}"
            )
            failing.append(reference)
        snapshot_finding_id = occurrence.raw_snapshot.get("finding_id")
        if (
            snapshot_finding_id is not None
            and str(snapshot_finding_id) != str(occurrence.finding.finding_id)
        ):
            problems.append(
                f"snapshot {reference.to_reference_string()} records finding_id "
                f"{snapshot_finding_id}, which is not the reconstructed record's ID"
            )
            failing.append(reference)
    if problems:
        return CheckRecord(
            check_id="EV-CHK-005",
            name="reference_consistency",
            title="Evidence reference consistency",
            required=True,
            applicable=True,
            state=CHECK_FAILED,
            method=method,
            statement=(
                f"{len(problems)} stored reference inconsistency(ies) were "
                "found: " + "; ".join(problems) + "."
            ),
            references=tuple(failing),
            limitations=limitations,
        )
    duplicates = _duplicate_finding_ids(occurrences)
    duplicate_note = (
        f" {len(duplicates)} finding ID(s) occur more than once and are retained "
        "as separate occurrences."
        if duplicates
        else ""
    )
    return CheckRecord(
        check_id="EV-CHK-005",
        name="reference_consistency",
        title="Evidence reference consistency",
        required=True,
        applicable=True,
        state=CHECK_PASSED,
        method=method,
        statement=(
            f"All {len(occurrences)} evidence reference(s) resolve to exactly "
            f"one stored snapshot occurrence of run {run.scan_id}."
            + duplicate_note
        ),
        limitations=limitations,
    )


def _scan_time_check(run: StoredScanRun, scan_dt: datetime | None) -> CheckRecord:
    method = (
        "Parsed the run's recorded scan_time as an ISO-8601 timestamp. Time-based "
        "derivations use that recorded time; no current-clock value is "
        "substituted when it is missing or unreadable."
    )
    if scan_dt is None:
        return CheckRecord(
            check_id="EV-CHK-006",
            name="scan_time_basis",
            title="Recorded scan-time basis",
            required=True,
            applicable=True,
            state=CHECK_UNKNOWN,
            method=method,
            statement=(
                "The run's recorded scan time is missing or unreadable, so when "
                "the observations were collected cannot be established and no "
                "time-based derivation is available."
            ),
            limitations=(
                "A collection time is never invented for a run that did not "
                "record a usable one.",
            ),
        )
    return CheckRecord(
        check_id="EV-CHK-006",
        name="scan_time_basis",
        title="Recorded scan-time basis",
        required=True,
        applicable=True,
        state=CHECK_PASSED,
        method=method,
        statement=(
            f"The run recorded scan time {run.context.scan_time}, which is the "
            "basis for every time-based derivation in this view."
        ),
        limitations=(
            "The recorded scan time is the collecting host's clock reading. It "
            "is not independently attested or externally timestamped.",
        ),
    )


def _scope_observability_check(
    occurrences: tuple[FindingOccurrence, ...],
) -> CheckRecord:
    method = (
        "Classified every retained record with reports.classify_finding() and "
        "separated coverage and skipped/inaccessible records that are by design "
        "or configured ("
        + ", ".join(sorted(BY_DESIGN_SCOPE_RULE_IDS))
        + ") from records showing requested scope that could not be read."
    )
    limitations = (
        "Only scope the scanners recorded is considered. Scope that was never "
        "requested, and scope no scanner can enumerate, is outside this check.",
    )
    unexpected = []
    for occurrence in occurrences:
        category = classify_finding(occurrence.finding)
        if category not in (CATEGORY_COVERAGE_LIMITATION, CATEGORY_SKIPPED_OR_INACCESSIBLE):
            continue
        if (occurrence.finding.rule_id or "") in BY_DESIGN_SCOPE_RULE_IDS:
            continue
        unexpected.append(occurrence)
    if unexpected:
        kinds = sorted({occ.finding.rule_id or occ.finding.source_type for occ in unexpected})
        return CheckRecord(
            check_id="EV-CHK-007",
            name="scope_observability",
            title="Requested scope observability",
            required=True,
            applicable=True,
            state=CHECK_UNKNOWN,
            method=method,
            statement=(
                f"{len(unexpected)} record(s) show requested scope that could "
                "not be read (" + ", ".join(kinds) + "), so whether the declared "
                "scope was fully observed cannot be established."
            ),
            references=tuple(occ.reference for occ in unexpected),
            limitations=limitations,
        )
    return CheckRecord(
        check_id="EV-CHK-007",
        name="scope_observability",
        title="Requested scope observability",
        required=True,
        applicable=True,
        state=CHECK_PASSED,
        method=method,
        statement=(
            "No retained record shows requested scope that could not be read. "
            "Configured exclusions and depth limits are reported as scope "
            "disclosures, not as observability failures."
        ),
        limitations=limitations,
    )


def _certificate_occurrences(
    occurrences: tuple[FindingOccurrence, ...],
) -> tuple[FindingOccurrence, ...]:
    return tuple(
        occurrence
        for occurrence in occurrences
        if "Certificate" in occurrence.finding.asset_type
    )


def _expiration_basis_check(
    run: StoredScanRun,
    occurrences: tuple[FindingOccurrence, ...],
    scan_dt: datetime | None,
) -> CheckRecord:
    """Can the dated certificate-expiration derivation be made at all?

    Not applicable when the declared scope contains no scanner that observes
    certificate validity metadata -- a scope-based reason, never "we found
    nothing so we skipped it".
    """
    method = (
        "Established whether the declared scope includes a scanner that records "
        "certificate validity metadata and whether a recorded scan time "
        "(EV-CHK-006) is available to date it against."
    )
    certificates = _certificate_occurrences(occurrences)
    scanners = {name for name, _ in _scanner_pairs(run)}
    in_scope = bool(scanners & {"crypto_inventory", "filesystem"}) or bool(certificates)
    if not in_scope:
        return CheckRecord(
            check_id="EV-CHK-008",
            name="dated_expiration_basis",
            title="Dated certificate-expiration basis",
            required=True,
            applicable=False,
            state=CHECK_NOT_APPLICABLE,
            method=method,
            statement=(
                "No dated certificate-expiration derivation was attempted for "
                "this run."
            ),
            not_applicable_reason=(
                "The declared scope includes no scanner that observes "
                "certificate validity metadata: "
                + (", ".join(sorted(scanners)) if scanners else "no scanner recorded")
                + "."
            ),
        )
    if scan_dt is None:
        return CheckRecord(
            check_id="EV-CHK-008",
            name="dated_expiration_basis",
            title="Dated certificate-expiration basis",
            required=True,
            applicable=True,
            state=CHECK_UNKNOWN,
            method=method,
            statement=(
                f"{len(certificates)} certificate record(s) are in scope, but the "
                "run has no usable recorded scan time to date them against, so "
                "no expiration derivation is available."
            ),
            references=tuple(occ.reference for occ in certificates),
            limitations=(
                "Expiration is never dated against the exporting clock.",
            ),
        )
    return CheckRecord(
        check_id="EV-CHK-008",
        name="dated_expiration_basis",
        title="Dated certificate-expiration basis",
        required=True,
        applicable=True,
        state=CHECK_PASSED,
        method=method,
        statement=(
            f"{len(certificates)} certificate record(s) can be dated against the "
            f"recorded scan time {run.context.scan_time}."
        ),
        references=tuple(occ.reference for occ in certificates),
        limitations=(
            "Certificate records whose retained metadata carries no readable "
            "expiration timestamp are not counted as expired; their expiration "
            "is simply not established.",
        ),
    )


# --- Exceptions ------------------------------------------------------------


def _evaluate_exceptions(
    occurrences: tuple[FindingOccurrence, ...],
) -> tuple[ExceptionRecord, ...]:
    """Named exceptions, ordered by stable policy ID then evidence occurrence."""
    records = [
        record
        for record in (
            _optional_provenance_exception(occurrences),
            _finding_error_exception(occurrences),
            _unrecognized_field_exception(occurrences),
        )
        if record is not None
    ]
    return tuple(sorted(records, key=lambda record: record.exception_id))


def _optional_provenance_exception(
    occurrences: tuple[FindingOccurrence, ...],
) -> ExceptionRecord | None:
    affected = [
        occurrence
        for occurrence in occurrences
        if any(
            getattr(occurrence.finding, field_name) is None
            for field_name in _OPTIONAL_PROVENANCE_FIELDS
        )
    ]
    if not affected:
        return None
    return ExceptionRecord(
        exception_id="EV-EXC-001",
        name="optional_provenance_incomplete",
        statement=(
            f"{len(affected)} retained record(s) omit one or more optional "
            "provenance details ("
            + ", ".join(_OPTIONAL_PROVENANCE_FIELDS)
            + "). The records remain usable evidence; independent reproduction "
            "of those specific observations is less directly documented."
        ),
        outcome_affecting=True,
        references=tuple(occurrence.reference for occurrence in affected),
        details=(
            "Optional provenance omissions are a named warning. Provenance "
            "required to establish execution completeness is handled by "
            "EV-CHK-003 and EV-CHK-004 and is incomplete, not a warning.",
        ),
    )


def _finding_error_exception(
    occurrences: tuple[FindingOccurrence, ...],
) -> ExceptionRecord | None:
    affected = [occurrence for occurrence in occurrences if occurrence.finding.errors]
    if not affected:
        return None
    return ExceptionRecord(
        exception_id="EV-EXC-002",
        name="record_level_errors_recorded",
        statement=(
            f"{len(affected)} retained record(s) carry their own recorded "
            "errors. The record is retained with its error; what that record "
            "could not establish is bounded by the error it carries."
        ),
        outcome_affecting=True,
        references=tuple(occurrence.reference for occurrence in affected),
        details=tuple(
            sorted({error for occurrence in affected for error in occurrence.finding.errors})
        ),
    )


def _unrecognized_field_exception(
    occurrences: tuple[FindingOccurrence, ...],
) -> ExceptionRecord | None:
    """Stored snapshot keys this release does not recognize.

    Named rather than dropped: a payload written by a different schema version
    keeps its unrecognized keys in `FindingOccurrence.raw_snapshot`, and their
    presence is reported so a reader knows the reconstructed record is not the
    whole stored payload. Key *names* are reported; values are not, because
    an unrecognized field's content has no established privacy classification.
    """
    affected = []
    names: set[str] = set()
    for occurrence in occurrences:
        extra = set(occurrence.raw_snapshot) - _KNOWN_SNAPSHOT_KEYS
        if extra:
            affected.append(occurrence)
            names.update(str(key) for key in extra)
    if not affected:
        return None
    return ExceptionRecord(
        exception_id="EV-EXC-003",
        name="unrecognized_stored_fields",
        statement=(
            f"{len(affected)} stored snapshot(s) carry field(s) this release "
            "does not interpret: "
            + ", ".join(sorted(names))
            + ". They are retained in the stored payload rather than discarded, "
            "and are not interpreted by this view."
        ),
        outcome_affecting=True,
        references=tuple(occurrence.reference for occurrence in affected),
        details=tuple(sorted(names)),
    )


# --- Status ----------------------------------------------------------------


def _resolve_status(
    checks: tuple[CheckRecord, ...], exceptions: tuple[ExceptionRecord, ...]
) -> tuple[str, tuple[StatusReason, ...]]:
    """Apply FAILED > INCOMPLETE > WARNING > VERIFIED to the evaluated checks.

    Every outcome carries reasons that name the checks or exceptions that
    produced it, and all individual results are retained regardless of which
    status wins.
    """
    required = [check for check in checks if check.required and check.applicable]
    if not required:
        # Defensive: this policy version always selects required checks. An
        # empty required set must never read as VERIFIED.
        return STATUS_INCOMPLETE, (
            StatusReason(
                reason_id="EV-RSN-000",
                statement=(
                    "No required check applied to this run, so no evidence "
                    "evaluation could be established."
                ),
            ),
        )
    failed = [check for check in required if check.state == CHECK_FAILED]
    unresolved = [
        check for check in required if check.state in (CHECK_UNKNOWN, CHECK_UNPERFORMED)
    ]
    outcome_affecting = [record for record in exceptions if record.outcome_affecting]

    reasons: list[StatusReason] = []
    if failed:
        status = STATUS_FAILED
        reasons.append(
            StatusReason(
                reason_id="EV-RSN-001",
                statement=(
                    f"{len(failed)} required check(s) completed and failed: "
                    + ", ".join(f"{check.check_id} {check.name}" for check in failed)
                    + "."
                ),
                check_ids=tuple(check.check_id for check in failed),
            )
        )
    elif unresolved:
        status = STATUS_INCOMPLETE
        reasons.append(
            StatusReason(
                reason_id="EV-RSN-002",
                statement=(
                    f"{len(unresolved)} required check(s) could not be completed "
                    "or established: "
                    + ", ".join(
                        f"{check.check_id} {check.name} ({check.state})"
                        for check in unresolved
                    )
                    + "."
                ),
                check_ids=tuple(check.check_id for check in unresolved),
            )
        )
    elif outcome_affecting:
        status = STATUS_WARNING
        reasons.append(
            StatusReason(
                reason_id="EV-RSN-003",
                statement=(
                    "Every required check passed, and "
                    f"{len(outcome_affecting)} defined exception(s) need "
                    "attention: "
                    + ", ".join(
                        f"{record.exception_id} {record.name}" for record in outcome_affecting
                    )
                    + "."
                ),
                check_ids=tuple(check.check_id for check in required),
                exception_ids=tuple(record.exception_id for record in outcome_affecting),
            )
        )
    else:
        status = STATUS_VERIFIED
        reasons.append(
            StatusReason(
                reason_id="EV-RSN-004",
                statement=(
                    f"All {len(required)} required check(s) passed for the "
                    "declared scope with no outcome-affecting exception: "
                    + ", ".join(f"{check.check_id} {check.name}" for check in required)
                    + "."
                ),
                check_ids=tuple(check.check_id for check in required),
            )
        )

    if failed and status != STATUS_FAILED:  # pragma: no cover - precedence invariant
        raise ExecutiveEvidenceError("failed required checks must take precedence")
    if unresolved and status not in (  # pragma: no cover - precedence invariant
        STATUS_FAILED,
        STATUS_INCOMPLETE,
    ):
        raise ExecutiveEvidenceError("unresolved required checks must take precedence")
    # Retained regardless of precedence: a lower-precedence result is still a
    # result, and hiding it would make the headline the only visible fact.
    if status == STATUS_FAILED and unresolved:
        reasons.append(
            StatusReason(
                reason_id="EV-RSN-005",
                statement=(
                    f"{len(unresolved)} further required check(s) also could not "
                    "be completed or established: "
                    + ", ".join(check.check_id for check in unresolved)
                    + "."
                ),
                check_ids=tuple(check.check_id for check in unresolved),
            )
        )
    if status in (STATUS_FAILED, STATUS_INCOMPLETE) and outcome_affecting:
        reasons.append(
            StatusReason(
                reason_id="EV-RSN-006",
                statement=(
                    f"{len(outcome_affecting)} defined exception(s) were also "
                    "recorded and remain listed: "
                    + ", ".join(record.exception_id for record in outcome_affecting)
                    + "."
                ),
                exception_ids=tuple(record.exception_id for record in outcome_affecting),
            )
        )
    not_applicable = [check for check in checks if check.state == CHECK_NOT_APPLICABLE]
    if not_applicable:
        reasons.append(
            StatusReason(
                reason_id="EV-RSN-007",
                statement=(
                    f"{len(not_applicable)} check(s) did not apply to the "
                    "declared scope: "
                    + ", ".join(check.check_id for check in not_applicable)
                    + "."
                ),
                check_ids=tuple(check.check_id for check in not_applicable),
            )
        )
    return status, tuple(reasons)


# --- Explanations ----------------------------------------------------------


def _observations(
    run: StoredScanRun,
    occurrences: tuple[FindingOccurrence, ...],
    counts: Mapping[str, int],
) -> tuple[ExplanationRecord, ...]:
    """What HarvestGuard recorded, stated from fixed templates only."""
    records = [
        ExplanationRecord(
            explanation_id="EV-OBS-001",
            nature=EXPLANATION_OBSERVATION,
            statement=(
                f"The run retained {counts['total_records']} normalized record(s), "
                "of which "
                f"{counts['material_evidence']} are material evidence records. "
                "By category: "
                + "; ".join(
                    f"{CATEGORY_LABELS[category]}: {counts[category]}"
                    for category in SUMMARY_CATEGORIES
                )
                + "."
            ),
            method=(
                "reports.count_by_category()/summarize_findings() over the "
                "retained snapshots, in canonical stored order."
            ),
            limitations=(
                "Category counts are record counts. Aggregate context, coverage "
                "and skipped/inaccessible records are counted separately from "
                "material evidence and are never summed into one total.",
            ),
        ),
        ExplanationRecord(
            explanation_id="EV-OBS-002",
            nature=EXPLANATION_OBSERVATION,
            statement=(
                "Scanner(s) recorded for this run: "
                + (
                    ", ".join(
                        f"{name} {version}" for name, version in _scanner_pairs(run)
                    )
                    or "none recorded"
                )
                + "."
            ),
            method="Recorded scanner/version pairs from the stored scan context.",
            check_ids=("EV-CHK-003",),
        ),
        ExplanationRecord(
            explanation_id="EV-OBS-003",
            nature=EXPLANATION_OBSERVATION,
            statement=(
                "Declared scope: target "
                f"{run.context.target_path}; scan type "
                f"{run.context.scan_type or 'not recorded'}; "
                + (
                    "configured scope constraints: "
                    + "; ".join(_configured_scope_statements(run.context))
                    if _configured_scope_statements(run.context)
                    else "no configured scope constraint recorded"
                )
                + "."
            ),
            method="Declared scope copied from the stored scan context.",
            limitations=(
                "A configured exclusion or depth limit bounds what the scan "
                "could observe. It is a disclosure, not a failure.",
            ),
        ),
    ]
    errors = [str(error) for error in run.context.scanner_errors]
    if errors:
        records.append(
            ExplanationRecord(
                explanation_id="EV-OBS-004",
                nature=EXPLANATION_OBSERVATION,
                statement=(
                    f"The run recorded {len(errors)} scanner error(s): "
                    + "; ".join(errors)
                    + "."
                ),
                method=(
                    "Bounded scanner diagnostics as stored, unchanged. No raw "
                    "analyzer output, exception object, or file content is "
                    "included."
                ),
                check_ids=("EV-CHK-004",),
            )
        )
    duplicates = _duplicate_finding_ids(occurrences)
    if duplicates:
        records.append(
            ExplanationRecord(
                explanation_id="EV-OBS-005",
                nature=EXPLANATION_OBSERVATION,
                statement=(
                    f"{len(duplicates)} finding ID(s) occur at more than one "
                    "snapshot occurrence in this run. Each occurrence is "
                    "retained and referenced separately."
                ),
                method=(
                    "Counted repeated finding_id values across snapshot "
                    "occurrences without deduplicating them."
                ),
                references=tuple(
                    occurrence.reference
                    for occurrence in occurrences
                    if occurrence.finding.finding_id in duplicates
                ),
                check_ids=("EV-CHK-005",),
            )
        )
    return tuple(records)


def _conclusions(
    run: StoredScanRun,
    occurrences: tuple[FindingOccurrence, ...],
    counts: Mapping[str, int],
    scan_dt: datetime | None,
    checks: tuple[CheckRecord, ...],
) -> tuple[ExplanationRecord, ...]:
    """Supported conclusions and limits: bounded derivations and check results.

    Every entry is either a restatement of an identified check result or a
    derivation whose method and limitations are stated. Nothing here is a
    business conclusion, a risk statement or a recommendation.
    """
    by_id = {check.check_id: check for check in checks}
    records: list[ExplanationRecord] = [
        ExplanationRecord(
            explanation_id="EV-CON-001",
            nature=EXPLANATION_CHECK_RESULT,
            statement=by_id["EV-CHK-001"].statement,
            method=by_id["EV-CHK-001"].method,
            check_ids=("EV-CHK-001",),
            limitations=by_id["EV-CHK-001"].limitations,
        ),
        ExplanationRecord(
            explanation_id="EV-CON-002",
            nature=EXPLANATION_CHECK_RESULT,
            statement=by_id["EV-CHK-004"].statement,
            method=by_id["EV-CHK-004"].method,
            check_ids=("EV-CHK-004", "EV-CHK-003"),
            limitations=by_id["EV-CHK-004"].limitations,
        ),
    ]
    if not occurrences:
        empty_check = by_id["EV-CHK-004"]
        if empty_check.state == CHECK_PASSED:
            statement = (
                "This run retained zero records from scanner(s) whose collection "
                "contract persists execution failures, and recorded no scanner "
                "error: a valid empty result for the declared scope, not absent "
                "output, a scanner failure, or an unknown collection contract."
            )
        else:
            statement = (
                "This run retained zero records, and execution completeness "
                "could not be established, so an empty result cannot be "
                "distinguished from output that was never produced."
            )
        records.append(
            ExplanationRecord(
                explanation_id="EV-CON-003",
                nature=EXPLANATION_BOUNDED_DERIVATION,
                statement=statement,
                method=(
                    "Combined the retained record count with the execution "
                    "completeness check (EV-CHK-004), which is independent of "
                    "the record count."
                ),
                check_ids=("EV-CHK-004",),
                limitations=(
                    "A valid empty result bounds only the declared scope and the "
                    "scanners' documented detection surface.",
                ),
            )
        )
    certificates = _certificate_occurrences(occurrences)
    if certificates and scan_dt is not None:
        expired = counts.get("expired_certificates", 0)
        records.append(
            ExplanationRecord(
                explanation_id="EV-CON-004",
                nature=EXPLANATION_BOUNDED_DERIVATION,
                statement=(
                    f"As of the recorded scan time {run.context.scan_time}, "
                    f"{expired} of {len(certificates)} retained certificate "
                    "record(s) carried an expiration timestamp earlier than that "
                    "time."
                ),
                method=(
                    "reports.summarize_findings() with the recorded scan time as "
                    "the explicit reference time; the exporting clock is never "
                    "used."
                ),
                references=tuple(occ.reference for occ in certificates),
                check_ids=("EV-CHK-006", "EV-CHK-008"),
                limitations=(
                    "A dated derivation against the recorded scan time. It does "
                    "not describe the certificate's state today, whether it is "
                    "deployed, or whether it was replaced after the scan.",
                    "Certificate records with no readable expiration timestamp "
                    "are not counted as expired.",
                ),
            )
        )
    elif certificates:
        records.append(
            ExplanationRecord(
                explanation_id="EV-CON-004",
                nature=EXPLANATION_BOUNDED_DERIVATION,
                statement=(
                    f"{len(certificates)} certificate record(s) were retained, "
                    "but with no usable recorded scan time their expiration is "
                    "not dated and remains unknown."
                ),
                method=(
                    "Withheld the dated expiration derivation because "
                    "EV-CHK-006 could not establish a recorded scan time."
                ),
                references=tuple(occ.reference for occ in certificates),
                check_ids=("EV-CHK-006", "EV-CHK-008"),
            )
        )
    return tuple(records)


def _unknowns(checks: tuple[CheckRecord, ...], scan_dt: datetime | None) -> tuple[str, ...]:
    """Everything this view could not establish, stated plainly."""
    unknowns = [
        f"{check.check_id} {check.name}: {check.statement}"
        for check in checks
        if check.state in (CHECK_UNKNOWN, CHECK_UNPERFORMED)
    ]
    unknowns.append(
        "Conflicts between records: not assessed. No conflict assessment ran "
        "for this run."
    )
    if scan_dt is None:
        unknowns.append(
            "Time-based derivations: unavailable. The run recorded no usable "
            "scan time and none is substituted."
        )
    return tuple(unknowns)


# --- Small helpers ---------------------------------------------------------


def _configured_scope_statements(context: ScanReportContext) -> list[str]:
    statements = [str(item) for item in context.scope_constraints]
    if context.excluded_paths:
        statements.append(
            "excluded patterns: " + ", ".join(str(item) for item in context.excluded_paths)
        )
    return statements


def _duplicate_finding_ids(occurrences: tuple[FindingOccurrence, ...]) -> tuple[str, ...]:
    seen: dict[str, int] = {}
    for occurrence in occurrences:
        finding_id = occurrence.finding.finding_id
        if finding_id is None:
            continue
        seen[finding_id] = seen.get(finding_id, 0) + 1
    return tuple(sorted(key for key, count in seen.items() if count > 1))


def _parse_timestamp(value: Any) -> datetime | None:
    """An ISO-8601 timestamp, or None. Never a substituted current time."""
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.strip())
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _normalize_export_time(value: str | datetime) -> str:
    """The caller's explicit export time, normalized but never invented."""
    if isinstance(value, datetime):
        stamp = value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
        return stamp.replace(microsecond=0).isoformat()
    if isinstance(value, str) and value.strip():
        return value.strip()
    raise ExecutiveEvidenceError(
        "export time must be an explicit timestamp string or datetime; this "
        "projection never reads the current clock"
    )


def _freeze(value: Any) -> Any:
    """Recursively immutable copy, so a projection cannot be mutated in place."""
    if isinstance(value, (dict, MappingProxyType)):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    if isinstance(value, (set, frozenset)):
        return frozenset(_freeze(item) for item in value)
    return value
