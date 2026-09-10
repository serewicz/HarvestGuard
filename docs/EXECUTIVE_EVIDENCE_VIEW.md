# Executive Evidence View

The policy, schema and meaning contract for HarvestGuard's shared executive
projection (`executive_evidence.py`).

**Availability.** This document describes a derived read model that exists in
the codebase and is covered by tests. No executive Markdown renderer, executive
JSON export, or CLI mode ships against it yet. Nothing here should be read as a
statement that a user-facing executive export is available.

HarvestGuard establishes evidence. Humans establish meaning. This view answers
exactly three questions:

1. What did HarvestGuard observe?
2. What evidence supports those observations?
3. What can and cannot be concluded from that evidence?

It contains no risk score, no trust score, no remediation, no compliance
verdict, no business materiality and no recommendation.

## Why a shared projection

An executive Markdown renderer and an executive JSON export must not invent
different meanings for the same stored scan. The flow is:

```
existing stored scan run
  -> existing verified load path (evidence_store.load_scan_run)
    -> one deterministic executive projection (executive_evidence.py)
      -> Markdown renderer / executive JSON export
```

Renderers consume the projection. No renderer derives status, counts,
conclusions or references independently. The projection reuses
`ScanReportContext`, `scanner_errors`, the existing evidence store, the existing
verified loading path and the existing reporting/count helpers; it adds no
storage, no verifier, no scanner and no scanning at export time.

## Versioning

Three version numbers are deliberately separate:

| Version | Meaning |
| --- | --- |
| `EXECUTIVE_SCHEMA_VERSION` (`0.1.0`) | The shape of the projection and of the executive JSON documented below. |
| `EXECUTIVE_POLICY_VERSION` (`0.1.0`) | Which checks exist, which are required, and how each state is decided. |
| `finding_schema_version`, evidence-store schema version, HarvestGuard release | Unchanged, owned by their existing modules. |

The projection records the HarvestGuard version that **produced** the stored
run separately from the version **exporting** it. A newer exporter never infers
missing collection facts about an older run.

## Inputs and determinism

`build_executive_evidence_view(run, export_time, exporting_harvestguard_version)`
takes a `StoredScanRun` that came from the existing verified load path, plus an
**explicit** export time. `load_executive_evidence_view(db_path, scan_id,
export_time)` is the thin convenience wrapper around
`evidence_store.load_scan_run`.

The module never reads the clock. For fixed stored evidence and a fixed export
time, the projection is identical every time, including its ordering. Passing no
export time is an error, not a reason to substitute "now".

## Time basis

- Historical technical derivations use the run's **recorded scan time** and
  nothing else.
- Export time is separate, explicit and never used for a derivation.
- A missing or unreadable recorded scan time produces an unknown
  (`EV-CHK-006`), never an invented collection time. Time-based derivations are
  then withheld, and the `expired_certificates` count is omitted rather than
  dated against a substituted instant.
- Re-exporting a run years later does not change what that run's evidence
  supported.

`reports._is_expired_certificate` and `reports.summarize_findings` gained an
explicit `reference_time` argument for this. Its default is `None`, which keeps
the previous current-clock behaviour, so live console and Markdown output is
unchanged; only stored-run readers pass the recorded scan time.

## Evidence references

A reference is `(scan_id, ordinal, finding_id)`:

- `ordinal` is the snapshot's occurrence index in canonical stored order, and is
  the identity;
- `finding_id` is carried for traceability, and is **not** the key.

Two snapshots that share a `finding_id` — within a run or across runs — remain
two occurrences. Evidence is never deduplicated by finding ID, stored order is
never re-sorted, and `ExecutiveEvidenceView.resolve()` resolves a reference to
exactly one snapshot occurrence.

`FindingOccurrence.raw_snapshot` is the exact stored payload as it was digested,
so a field written by a different schema version is retained rather than
silently dropped by reconstruction (`EV-EXC-003` names such fields). To supply
it, `evidence_store.StoredScanRun` gained a `raw_finding_snapshots` field,
populated by the existing verified read path; every pre-existing attribute is
unchanged.

## Status contract

**VERIFIED means that every required evidence-integrity and evaluation check
explicitly listed in this view completed and passed for the declared scope. No
required check is failed, unknown, or unperformed. It does not establish source
authenticity, complete environmental coverage, organizational security,
regulatory compliance, or business safety.**

User-facing label: **Evidence evaluation: VERIFIED** (likewise for the others).

| Status | Meaning |
| --- | --- |
| `FAILED` | A required check completed and failed. |
| `INCOMPLETE` | A required check or requested evaluation could not be completed or established. |
| `WARNING` | Required checks passed, but a specifically defined exception needs attention. |
| `VERIFIED` | Required checks passed without an outcome-affecting exception. |

Precedence is `FAILED > INCOMPLETE > WARNING > VERIFIED`. Precedence decides the
headline only: every individual check result, exception and scope limitation is
retained and listed regardless of which status wins, and a `FAILED` view still
names the checks that could not be established (`EV-RSN-005`) and the exceptions
that were recorded (`EV-RSN-006`).

The required-check set is selected by the policy version from the declared scope
and the supported collection contract **before** any result is examined. It is
never assembled from whichever checks happened to pass, and an empty required
set can never yield `VERIFIED`.

### Check states

`passed`, `failed`, `unknown`, `unperformed`, `not_applicable`. A
`not_applicable` state must carry a scope-based reason
(`CheckRecord.not_applicable_reason`); "we found nothing, so we skipped it" is
not such a reason.

## Check catalogue (policy 0.1.0)

All eight checks are required. `EV-CHK-008` is the one whose applicability
depends on declared scope.

| ID | Name | Method | States it can reach |
| --- | --- | --- | --- |
| `EV-CHK-001` | `evidence_integrity` | The existing loader recomputed the stored SHA-256 digest over the canonical run payload and ordered snapshots before the projection was built. | `passed`; `unperformed` when the run carries no stored digest. A mismatch never reaches this check — the loader fails closed. |
| `EV-CHK-002` | `supported_evidence_schema` | Compares the run's and each snapshot's normalized-finding schema version with the versions this policy interprets. | `passed`, `unknown` |
| `EV-CHK-003` | `supported_collection_contract` | Matches every recorded scanner/version pair against the supported-contract mapping below. | `passed`, `unknown` |
| `EV-CHK-004` | `execution_completeness` | Reads recorded `scanner_errors`, and requires `EV-CHK-003` to have passed before an empty error list may be read as successful execution. | `passed`, `unknown` |
| `EV-CHK-005` | `reference_consistency` | Resolves every reference against stored snapshots in stored order and compares each snapshot's recorded `scan_id`/`finding_id` with the run identity and the reconstructed record. | `passed`, `failed` |
| `EV-CHK-006` | `scan_time_basis` | Parses the recorded `scan_time` as ISO-8601. | `passed`, `unknown` |
| `EV-CHK-007` | `scope_observability` | Separates by-design/configured coverage records (`max_depth_boundary`, `skipped_special_file`) from records showing requested scope that could not be read. | `passed`, `unknown` |
| `EV-CHK-008` | `dated_expiration_basis` | Establishes whether the declared scope includes a scanner that records certificate validity metadata, and whether a recorded scan time is available to date it against. | `passed`, `unknown`, `not_applicable` |

Checks are ordered by stable policy ID.

### What the checks deliberately do not do

- No check re-hashes stored evidence or creates a second verifier.
- `EV-CHK-005` is an identity check over stored records, not a content-integrity
  check.
- No conflict-detection check exists. Where no explicit conflict assessment ran,
  this view says **not assessed** — never "no conflicts".

## Supported collection contracts

A scanner/version pair is *supported* only when its execution-failure semantics
are documented well enough for this policy to interpret an empty result or an
empty error list. Unknown pairs stay unknown; they never pass by default.

| Scanner | Version | Evidence basis |
| --- | --- | --- |
| `semgrep_crypto_rules` | `0.2.0` | Collection contract 0.2.0 propagates execution and output failures through `LocalScanError` into the run's recorded `scanner_errors`, retaining usable partial findings — see [DETECTION_CHARACTERIZATION.md](DETECTION_CHARACTERIZATION.md#execution-provenance-collection-contract-020). |

Every other pair — including `semgrep_crypto_rules 0.1.0`, a run that recorded
no scanner/version pair at all, and pairs whose contracts are simply not yet
documented — makes `EV-CHK-003` and therefore `EV-CHK-004` `unknown`, so the
view is `INCOMPLETE`. This is deliberate: an empty `scanner_errors` list from a
scanner whose failure semantics are undocumented does not establish that the
scanner ran to completion. Adding a pair to this table is a policy change and
requires the contract to be documented first.

Being listed here says nothing about detection quality or coverage. It says only
that the scanner's failure semantics are known.

## Execution, scope and emptiness

- A recorded scanner failure makes execution completeness **unknown**
  (`INCOMPLETE`), even when stored integrity passes. `--no-fail-on-error` cannot
  erase a recorded failure: the stored errors, the check state and the
  observation that lists them all survive.
- Partial findings collected before a failure remain retained, referenced and
  counted.
- A valid empty result from a supported contract is stated as such
  (`EV-CON-003`) and is never confused with absent output, scanner failure, an
  unsupported contract, or unknown history. Any selected supported scanner with
  valid zero results is handled independently of record counts.
- Ordinary configured exclusions and depth limits are **disclosures**, reported
  as observations; they do not warn and do not make scope observability unknown.
- Requested scope that could not be read (for example `directory_traversal_error`,
  `metadata_unavailable`) stays visible and makes `EV-CHK-007` unknown.

## Defined exceptions

Exceptions are a closed set. There is no open-ended "something looked odd"
channel, and an exception never carries a severity, priority or recommendation.
Exceptions are ordered by stable ID, then by evidence occurrence.

| ID | Name | Raised when |
| --- | --- | --- |
| `EV-EXC-001` | `optional_provenance_incomplete` | A retained record omits one or more *optional* provenance details (`collection_method`, `collection_source`, `repeatable`, `verification_rationale`). Provenance required to establish completion is handled by `EV-CHK-003`/`EV-CHK-004` and is incomplete, not a warning. |
| `EV-EXC-002` | `record_level_errors_recorded` | A retained record carries its own recorded errors. |
| `EV-EXC-003` | `unrecognized_stored_fields` | A stored snapshot carries a field this release does not interpret. Field *names* are reported; values are not, because an unrecognized field's content has no established privacy classification. |

## Observations, conclusions and unknowns

Every statement is produced from a fixed template and labelled with its nature:

- `observation` — what a scanner read, parsed or detected in declared scope
  (record counts by existing category, recorded scanner/version pairs, declared
  scope, recorded scanner errors, repeated finding IDs).
- `check_result` — a restatement of an identified check, with its method.
- `bounded_derivation` — a technical derivation directly supported by retained
  evidence, with its method and limitations (the valid-empty-result statement;
  the dated certificate-expiration statement).

Counts come from `reports.summarize_findings()`/`count_by_category()`, so the
executive view can never disagree with the technical report. Aggregate context,
coverage, skipped/inaccessible and material evidence records stay distinct and
are never summed into one total. `unknowns` lists every check that could not be
completed, plus the standing "conflicts: not assessed" entry.

`limits` is a fixed list restating what this view cannot support: digest limits,
no deployment/trust/reachability claims, absence of a record is not evidence of
absence, conflicts not assessed, expiration is a dated derivation rather than a
verdict, and no organizational-security/compliance/quantum-readiness/business
conclusion.

## Digest limitations

A matching stored digest is **internal consistency of the stored run**. It is
not a signature, not source authenticity, and no protection against deliberate
modification of both the payload and the digest by anyone who can write to the
evidence database. It never establishes that a scanner succeeded.

A digest mismatch fails closed in the existing loader: `EvidenceIntegrityError`,
`ScanRunNotFoundError` and `EvidenceStoreError` propagate unchanged, and **no**
view is constructed — neither a normal view nor one carrying the rejected
payload. A bounded failure diagnostic may name the requested run and the failed
check; nothing else about the rejected evidence is emitted.

## Privacy

The projection reads and emits only already-retained normalized observation
metadata: scanner identity, safe locations, timestamps, collection provenance,
technical metadata, existing bounded diagnostics, unknowns, limitations,
confidence and technical ownership signals. Technical ownership signals never
become business accountability.

Never present: raw source-file contents, matched sensitive values, credentials,
key material, ciphertext, raw configuration, and raw analyzer/provider output or
exception objects. Recorded scanner errors are carried through unchanged from
the existing already-sanitized `scanner_errors` strings. Paths and generated
reports are treated as potentially sensitive. Generation is local-only: no
service, account, telemetry or upload.

## Executive JSON schema (for the renderer issue)

Documented here, **not implemented here**: this issue adds no serializer. A
serializing consumer maps the projection field-for-field as below. Field order
in this table is the intended document order.

| JSON field | Source | Notes |
| --- | --- | --- |
| `executive_schema_version` | `schema_version` | Separate from finding/storage/product versions. |
| `executive_policy_version` | `policy_version` | Which check policy produced `status`. |
| `scan_id` | `scan_id` | Run identity. |
| `scan_time` | `scan_time` | `null` when unknown; never substituted. |
| `scan_time_basis` | `scan_time_basis` | Names the basis or says it is unknown. |
| `export_time` | `export_time` | Explicit caller input. |
| `producing_harvestguard_version` | `producing_harvestguard_version` | Release that executed the scan. |
| `exporting_harvestguard_version` | `exporting_harvestguard_version` | Release performing the export. |
| `finding_schema_version` | `finding_schema_version` | As stored. |
| `evidence_digest` | `evidence_digest` | Internal-consistency digest, as stored. |
| `scope` | `scope` | `target_path`, `scan_type`, `scanners`, `scanner_versions`, `excluded_paths`, `scope_constraints`, `crypto_files_inspected`. |
| `status` | `status` | One of the four qualified statuses. |
| `status_statement` | `status_statement` | The qualified sentence for that status; render verbatim. |
| `status_reasons[]` | `status_reasons` | `reason_id`, `statement`, `check_ids`, `exception_ids`. |
| `checks[]` | `checks` | `check_id`, `name`, `title`, `required`, `applicable`, `state`, `method`, `statement`, `references`, `source_references`, `limitations`, `not_applicable_reason`. Ordered by `check_id`. |
| `exceptions[]` | `exceptions` | `exception_id`, `name`, `statement`, `outcome_affecting`, `references`, `details`. Ordered by `exception_id`. |
| `observations[]` | `observations` | `explanation_id`, `nature`, `statement`, `method`, `references`, `check_ids`, `limitations`. |
| `conclusions[]` | `conclusions` | Same shape as `observations`. Render under **Supported conclusions and limits**. |
| `unknowns[]` | `unknowns` | Plain statements of what could not be established. |
| `limits[]` | `limits` | Standing limits; render with `conclusions`. |
| `counts` | `counts` | Existing report counts, unchanged. `expired_certificates` is absent when scan time is unknown. |
| `scanner_errors[]` | `scanner_errors` | As stored. |
| `evidence[]` | `occurrences` | `ordinal`, `finding_id`, and the stored snapshot. Canonical stored order; never deduplicated. |

An evidence reference serializes as `{"scan_id": ..., "ordinal": ..., "finding_id": ...}`.

### Renderer rules

- Use the heading **Supported conclusions and limits**, never "Decision
  implication".
- Use **Evidence checks and limitations**, never an overall "Trust assessment".
- Render the status as **Evidence evaluation: `<STATUS>`** together with
  `status_statement`; never as a bare word.
- Do not recompute status, counts, references or conclusions. If a renderer
  needs a fact this projection does not carry, extend the projection.

## Compatibility

Existing CLI options, exit codes, stdout/stderr separation, the bare
normalized-finding `--json` array, technical Markdown sections, console
summaries, DataFrame columns, Streamlit behaviour, `finding_id`/`rule_id`
stability, scanner versions, accounting semantics and stored snapshots are all
unchanged by this projection. The two narrow additions are the optional
`reference_time` argument described under [Time basis](#time-basis) and the
additive `StoredScanRun.raw_finding_snapshots` field described under
[Evidence references](#evidence-references).
