# Executive Evidence View

The policy, schema and meaning contract for HarvestGuard's shared executive
projection (`executive_evidence.py`).

**Availability.** The projection ships in `executive_evidence.py`, and its two
serializers ship in `executive_reports.py`, exposed as
`harvestguard evidence export SCAN-ID --evidence-db PATH --executive-markdown
[PATH]` and `--executive-json [PATH]` (see [CLI.md](CLI.md#executive-evidence-exports)).
Both require an already-stored run: there is no live-scan executive export, and
no HTML or PDF renderer.

**Worked examples.** One reproducible sample per evaluation outcome — plus a
zero-finding run, partial execution, unknown historical time, an unsupported
historical contract, duplicate finding IDs, withheld unrecognized field values
and a rejected corrupted run — is published in
[docs/examples/executive-evidence-view/](examples/executive-evidence-view/README.md),
together with the exact commands, versions and provenance behind each one.

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
- Export time is separate, explicit and never used for a derivation. ISO-8601
  strings and datetime inputs are validated and normalized to UTC; naive values
  are interpreted as UTC. Equivalent instants normalize identically, retaining
  supplied fractional seconds. Malformed or empty inputs are rejected.
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

- `scan_id` is always the containing stored run's identity, never inferred
  from the finding; resolution requires exact run identity, with no wildcard;
- `ordinal` is the snapshot's occurrence index in canonical stored order, and is
  the identity within that run;
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

Each occurrence exposes `finding: RetainedFinding`, an immutable projection of
the reconstructed finding fields, plus its exact `raw_snapshot`. The projected
`observed_at` comes only from that retained snapshot: absent/null means `None`
and is disclosed as unknown. The loader's historical clock default is never
exposed by the occurrence. The original reconstructed finding and raw snapshot
are not mutated. Consumers use the occurrence's retained fields or raw snapshot,
not a newly reconstructed `NormalizedFinding`.

Missing recorded finding scan IDs make reference consistency unknown; conflicting
IDs fail that check. Both conditions remain in the original evidence, while
every disclosure reference still resolves to the containing run and ordinal.

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
| `EV-CHK-005` | `reference_consistency` | Resolves every reference against stored snapshots in stored order and compares each snapshot's recorded `scan_id`/`finding_id` with the run identity and the reconstructed record. | `passed`, `failed`, `unknown` |
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

Every scanner declared in stored scope must have a recorded collection-version
mapping. Scope labels are reconciled to normalized scanner names without
inferring a version. A missing mapping is explicitly represented as
`<scanner> unknown`, making the collection-contract and execution-completeness
checks unknown, even with zero findings and no scanner errors. Undeclared
scanners do not acquire a missing-provenance requirement; existing recorded
pairs and finding provenance remain evaluated as before.

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
| `EV-EXC-003` | `unrecognized_stored_fields` | A stored snapshot carries a field this release does not recognize -- at the snapshot top level, or as a direct member of the recognized `provenance` object (reported as `provenance.<member-name>`), including an occurrence whose *only* unrecognized field is nested. Field *names* are reported; values are not, because an unrecognized field's content has no established privacy classification. The statement also records that those values were intentionally withheld from executive disclosure views and remain retained in the verified local evidence store, covered by the existing digest. |

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

The direct builder calls `evidence_store.verify_loaded_scan_run()` before
projecting. It uses the existing canonical run payload builder and
`compute_evidence_digest()`, plus an immutable baseline of the loader's
reconstructed fields, to reject changes to either the retained payload or its
in-memory reconstruction. This performs no storage writes and defines no new
digest algorithm. A missing digest remains unperformed, never passed.

A digest mismatch fails closed in the existing loader or in-memory check: `EvidenceIntegrityError`,
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

## Executive JSON schema

Executive schema version `0.1.0`, serialized by
`executive_reports.executive_json()`. The field mapping and the document order
below are binding: a serializer maps the projection field-for-field, and field
order in this table *is* the document order. Renaming, omitting, adding or
reinterpreting a field is a schema change, not an implementation detail.

This schema version had not shipped to users before the exports did, so its
evidence-item mapping was completed rather than migrated. There is no migration
from an earlier published executive schema, because there was no earlier
published executive schema.

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
| `evidence[]` | `occurrences` | One item per retained snapshot occurrence, in canonical stored order, never deduplicated. Members and disclosure boundary are defined below. |

An evidence reference serializes as `{"scan_id": ..., "ordinal": ..., "finding_id": ...}`.

### Evidence occurrences and the disclosure boundary

Each `evidence[]` item is an object with **exactly these members, in this
order**:

| Member | Meaning |
| --- | --- |
| `ordinal` | The occurrence identity within the containing scan run. |
| `finding_id` | Retained for readability and traceability. It is **not** the occurrence key. |
| `snapshot` | Recognized normalized-finding fields that were actually present in the stored snapshot. |
| `unrecognized_field_names` | Lexically sorted names of stored fields the exporting version does not recognize. Always present, `[]` when there are none. |

The complete reference to one occurrence is the containing document's `scan_id`
plus `ordinal` plus `finding_id`. Duplicate finding IDs produce separate
`evidence[]` items distinguished by `ordinal`.

`snapshot` rules:

- Values come from `FindingOccurrence.raw_snapshot` — the exact stored payload —
  never from a reconstructed `NormalizedFinding`, whose defaults would invent a
  value the stored snapshot never carried.
- Recognized members appear in the canonical field order established by
  `NormalizedFinding.to_dict()`, irrespective of the order the stored object
  lists them in. `provenance` keeps its documented object nesting, and its
  recognized members follow `Provenance.to_dict()` order. That order comes
  from two explicit tuples in `findings.py`
  (`NORMALIZED_FINDING_FIELD_ORDER`, `PROVENANCE_FIELD_ORDER`) that
  `to_dict()` itself is built from; the serializer imports them directly and
  never constructs a `NormalizedFinding` merely to discover field order --
  doing so would read the clock through `__post_init__`'s `observed_at`
  default the moment the module is imported.
- A recognized field absent from the stored snapshot **stays absent**. It is
  never invented, backfilled or defaulted. A historical run that recorded no
  `observed_at` therefore has no `observed_at` in its snapshot.

`unrecognized_field_names` rules:

- Names are disclosed; **values are not**, because an unrecognized field's
  content has no established privacy classification. A withheld value appears
  in no export, no stdout or stderr output, no log, no example and no generated
  artifact.
- A stored member of the nested `provenance` object that this release does not
  recognize is reported as `provenance.<name>`, on the same names-only basis --
  including when it is the *only* unrecognized field on that occurrence (no
  unrecognized top-level field need also be present).
- Names are lexically sorted per occurrence.
- A renderer never falls back to serializing `raw_snapshot` wholesale.

**Classification is owned by the shared projection, not by either renderer.**
`executive_evidence.py`'s `_classify_snapshot()` is the *only* place that
decides what is recognized; it populates `FindingOccurrence.disclosed_snapshot`
and `FindingOccurrence.unrecognized_field_names` once per occurrence, and both
`executive_json_document()` and `format_executive_markdown()` read those two
fields directly. Neither serializer implements its own recursive classifier or
disclosure policy, and neither reclassifies `raw_snapshot` on its own.

Only two structural levels are closed and participate in classification:

1. The stored snapshot's top level, against the fields `NormalizedFinding.
   to_dict()` defines.
2. The recognized `provenance` object's direct members: `scanner_name`,
   `scanner_version`, `collection_method`, `source`, `rule_id`, `collected_at`,
   `repeatable`, `verification_rationale`. Any other direct member is
   unrecognized.

`technical_metadata` and `ownership_signals` are recognized *open-content*
maps: they are disclosed by their exact stored value, and their nested keys are
retained observation data -- never classified as unknown schema fields merely
for being scanner-specific or unusual. No object nested any deeper than the two
levels above is recursively classified.

This is not silent data loss, and both formats say so through the existing
`EV-EXC-003` exception statement: when unrecognized fields are present, the
statement records that their values were intentionally withheld from the
disclosure view and remain retained, unchanged, in the verified local evidence
store. No new top-level export field and no check- or status-policy change is
involved.

**Disclosure view versus evidence store.** An executive export is a disclosure
view, not a replacement for the store:

- the exact raw snapshot, including unrecognized fields *and their values*,
  stays retained in the verified local evidence store and in the internal
  projection used for integrity and reference resolution;
- the existing evidence digest continues to cover the complete raw snapshot,
  including withheld values — digest serialization is unchanged, and the
  digested payload is *not* replaced by the disclosure snapshot. Changing only
  an unrecognized value without updating the digest therefore invalidates the
  run, which fails closed in the existing loader and produces no export;
- the local store remains the source for technical traceability. An export
  resolves a reference to an occurrence; reading the exact stored bytes of that
  occurrence means reading the database.

### Example (abridged)

```json
{
  "executive_schema_version": "0.1.0",
  "executive_policy_version": "0.1.0",
  "scan_id": "9f1c…",
  "scan_time": "2026-03-04T05:06:07+00:00",
  "scan_time_basis": "recorded scan time",
  "export_time": "2026-09-11T12:30:45+00:00",
  "status": "WARNING",
  "status_statement": "Evidence evaluation: WARNING. …",
  "evidence": [
    {
      "ordinal": 0,
      "finding_id": "18ad1f56…",
      "snapshot": {
        "finding_id": "18ad1f56…",
        "scan_id": "9f1c…",
        "source_type": "code_analysis",
        "location": "/target/src/hashing.py:5",
        "provenance": { "scanner_name": "semgrep_crypto_rules", "…": "…" },
        "schema_version": "1.0.0"
      },
      "unrecognized_field_names": ["future_field", "provenance.future_detail"]
    }
  ]
}
```

The Markdown document carries the same content: an overview with the qualified
status, its reasons and every defined exception; **What HarvestGuard observed**;
**Evidence checks and limitations**; **Defined exceptions**; **Supported
conclusions and limits** (including what could not be established and the
standing limits); and **Technical evidence detail**, one entry per occurrence
with the same recognized stored values and unrecognized names.

### Markdown renderer safety

- Every value read out of the projection is backslash-escaped, so a stored
  filename, identifier or scanner error cannot open a heading, a link, a table
  row or raw HTML. The escaped text still shows exactly what was stored, and no
  escaped value is placed at the start of a line.
- Occurrence anchors are derived from exact scan and snapshot identity
  (`evidence-<scan-id>-<ordinal>`) and are deterministic; every rendered
  reference link resolves to an occurrence the same document contains.
- Nothing in a generated document links stored text to an external resource,
  and no renderer fetches anything.

### Check limitations the exports do not change

Both formats render the check catalogue as it was evaluated. They add no check,
retire none, and never recompute a state: an export cannot turn an `unknown`
into a pass, and recording a signature algorithm is never a claim that a
signature was validated. `EV-CHK-001` remains internal consistency of the
stored run, not authenticity.

### Renderer rules

- Use the heading **Supported conclusions and limits**, never "Decision
  implication".
- Use **Evidence checks and limitations**, never an overall "Trust assessment".
- Render the status as **Evidence evaluation: `<STATUS>`** together with
  `status_statement`; never as a bare word.
- Do not recompute status, counts, references or conclusions. If a renderer
  needs a fact this projection does not carry, extend the projection.

## Usability and traceability evidence

What has actually been established about this view, as of the examples
collection ([issue #153](https://github.com/serewicz/HarvestGuard/issues/153)):

- **Established by automated checks.** Every required outcome is reproducible
  through the real store → verified load → projection → both serializers path;
  generation is deterministic for fixed evidence and an explicit export time;
  the published samples are reproducible byte-for-byte from a non-editable
  install, regenerated outside the checkout with no repository import
  override; both CLI export modes — the documented no-install entry point and
  the installed console script — reproduce the published samples for
  representative scenarios apart from the export time the CLI owns;
  every evidence reference in a published sample resolves to
  exactly one stored occurrence, with duplicate finding IDs staying separate;
  JSON and Markdown agree, including withheld unrecognized field names and the
  local-retention disclosure; no withheld value or secret-shaped canary appears
  in any generated artifact; a corrupted run yields a bounded diagnostic and no
  report; and generation needs no network, service or account.
- **Independent technical review recorded.** Codex reviewed implementation
  `c934e63c8c3c0d0b7150301e1942b7e76d0439b8` with verdict
  APPROVE WITH NON-BLOCKING FOLLOW-UP. This is technical evidence, not human
  validation; qualified test results and limitations are preserved in the
  acceptance records.
- **Not yet established.** Independent practitioner use of the published
  instructions and nontechnical-reader comprehension have not happened.
  Tim’s prior freeze remains historical; the asynchronous reader revision
  awaits explicit refreeze and tests independent comprehension without coaching,
  not reading speed. The practitioner procedure remains unchanged.
  Decisions and outstanding human requirements are recorded in
  [docs/examples/executive-evidence-view/acceptance-summary.md](examples/executive-evidence-view/acceptance-summary.md).
  Nothing in this document should be read as a claim that reader comprehension
  or independent usability has been demonstrated.

## Compatibility

Existing CLI options, exit codes, stdout/stderr separation, the bare
normalized-finding `--json` array, technical Markdown sections, console
summaries, DataFrame columns, Streamlit behaviour, `finding_id`/`rule_id`
stability, scanner versions, accounting semantics and stored snapshots are all
unchanged by this projection. The two narrow additions are the optional
`reference_time` argument described under [Time basis](#time-basis) and the
additive `StoredScanRun.raw_finding_snapshots` field described under
[Evidence references](#evidence-references).
