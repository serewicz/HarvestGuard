# Architecture

HarvestGuard is currently a small Python and Streamlit application for
cryptographic asset inventory and evidence collection, with local filesystem,
AWS S3, GCS, Azure Blob, sensitive-data classification, Semgrep-based code
crypto analysis, dashboard, and risk-analysis modules. The target architecture
keeps that implementation local-first while creating clearer boundaries for
scanner growth, reports, and future operations.

## Target Flow

```text
Scan adapters
  -> Normalized finding model
  -> Local evidence store
  -> CLI and service layer
  -> Built-in dashboard and reports
  -> Optional Prometheus and Grafana
  -> Future Executive Priority Index
```

## Conceptual Evidence Flow

```text
Observed evidence
  -> Ownership signals
  -> Unknowns and limitations
  -> Evidence confidence
  -> Evidence-based risk topology
  -> Executive questions
```

HarvestGuard collects verifiable cryptographic evidence, communicates
confidence and unknowns, surfaces ownership signals, and frames the questions
organizations must answer. It does not prescribe the answer.

The terms used throughout this flow — observed evidence, confidence, ownership
signal, unknown, coverage, partial scan, inference, exposure, HNDL exposure,
evidence-based risk topology, risk score, remediation priority, executive
question, and recommendation — are defined in
[TERMINOLOGY.md](TERMINOLOGY.md).

The stages in this conceptual flow have separate responsibilities:

- **Observed evidence:** scan adapters collect source-attributed evidence from
  local filesystems, object stores, source code, and cryptographic inventory
  targets.
- **Ownership signals:** ownership metadata remains attributed to its technical
  source, such as filesystem ownership, cloud tags, IAM metadata, repository
  metadata, CODEOWNERS, project labels, or namespaces. These signals are not
  confirmed business accountability without corroboration.
- **Unknowns and limitations:** unavailable metadata, permission gaps, scanner
  errors, unsupported assets, and partial-scan boundaries are represented
  explicitly.
- **Evidence confidence:** confidence measures the quality, directness, and
  completeness of the evidence. It does not measure business severity.
- **Evidence-based risk topology:** derived concentration views must remain
  traceable to underlying findings, source evidence, confidence, and coverage
  limits.
- **Executive questions:** questions for management and leadership may be
  generated from evidence, unknowns, confidence, and concentration patterns.
  Recommendations are outside the core product boundary.

## Boundaries

### Scan Adapters

Scan adapters collect observed evidence from a specific source. Current adapter
families include local filesystems, object storage metadata, local
sensitive-data pattern scanning, code crypto analysis, and local
cryptographic asset inventory.

Adapters should:

- produce source-specific raw evidence;
- avoid storing raw sensitive matched values;
- expose scanner errors and confidence;
- avoid business prioritization logic;
- support pagination, limits, and safe failure behavior.

#### Crypto-inventory detector framework

The crypto-inventory adapter has an internal structure the other adapters do
not yet need, because it recognizes many independent formats: each supported
format is a **detector** declared in a static registry
(`scanner/crypto_detectors.py` for the framework primitives,
`CRYPTO_DETECTORS` in `scanner/crypto_inventory.py` for the registry itself).
It is an implementation boundary only — it adds no detection capability and
changes no finding contract. Its properties:

- **Traversal stays with the scanner.** The scanner walks the target, applies
  exclusions and symlink rules, counts inspected files, and hands each
  discovered asset to the registry. Detectors receive one asset at a time and
  have no filesystem entry point; a root/directory detector receives a
  candidate root reached through a marker file the scanner already found, plus a
  fixed-name sibling check, and cannot list or recurse.
- **One read per file, shared.** A shared scan context offers leading bytes,
  full bytes, and a bounded text view over a single read, so a detector reads
  only the view it declared it needs and the registry does not grow into a
  detectors-times-full-file-read pattern.
- **Deterministic order, per-detector terminality.** Registry order comes from
  declared priorities alone, never import or filesystem order; priorities must be
  unique, so no pair of detectors can have their order decided by how they were
  listed. A result is a
  non-match, a match other evidence may coexist with, or a match that ends
  evaluation for that asset — not a general "first match wins" rule.
- **Detector-declared safe metadata allowlists.** Metadata a detector did not
  declare is omitted centrally, and there is no generic dictionary path from a
  parser into a finding's technical metadata, so key material, passphrases,
  salts, ciphertext, plaintext, raw config files, and parser payloads have no
  channel into normalized findings, JSON, or Markdown.
- **Accounting independent of detector count.** One regular file contributes at
  most one unit to `Crypto files inspected` regardless of how many detectors
  inspect it; classified directories are not counted as files.
- **Error isolation.** An expected non-match is a result, not an exception. An
  unexpected detector exception is never converted into a clean non-match: it
  surfaces through the existing scanner-error path with findings already
  collected preserved (including those earlier detectors produced for the same
  asset), and its message names the detector and asset path only.

See [CRYPTO_INVENTORY.md](CRYPTO_INVENTORY.md#detector-framework) for the
detector lifecycle and how a future detector is added.

### Normalized Finding Model

The normalized finding model is the contract between scanners and every
downstream feature. The current internal contract is documented in
[NORMALIZED_FINDINGS.md](NORMALIZED_FINDINGS.md).

A raw `NormalizedFinding` record is evidence and provenance only. It
contains:

- asset identity and source;
- observed evidence;
- provenance (scanner metadata, collection method and source, rule id,
  repeatability, verification rationale);
- confidence;
- technical ownership signals (filesystem/cloud/IAM metadata only, never
  confirmed business accountability);
- unknowns and limitations, distinct from per-finding errors;
- immutable technical metadata;
- a stable finding identity (`finding_id`, and `identity_key` where a
  scanner supplies one).

A raw `NormalizedFinding` record deliberately does **not** contain: risk
score, HNDL exposure, exposure probability, remediation priority, business
impact, confirmed business ownership or accountability, executive
questions, recommendations, compliance conclusions, or quantum-readiness
conclusions. See [TERMINOLOGY.md](TERMINOLOGY.md) for the evidence-versus-
inference vocabulary these boundaries use, and
[ADR-005: Evidence versus inference](DECISIONS/ADR-005-evidence-versus-inference.md)
for the rationale.

Derived exposure or risk fields, inference, executive questions, and
mutable assessment records are not responsibilities of the normalized
finding model. They belong to a separate, downstream (and, beyond the
existing heuristic risk score, currently future) assessment layer -- see
"Future Executive Priority Index" below -- that would consume normalized
findings by `finding_id` and stay traceable back to them, rather than
carrying that data inside the raw finding itself. This document does not
claim such a layer exists beyond what is actually implemented today.

Assessment concepts such as business impact, severity, remediation cost,
confirmed business ownership, quantum readiness, and executive priority are
deliberately excluded from the raw finding layer.

### Local Evidence Store

SQLite is the initial local system of record. It should store scan runs,
normalized findings, immutable raw details, and separate assessment records.

The store must support local-first operation, repeat scans, report generation,
and future drift comparison without requiring a server or external database.

### CLI and Service Layer

The CLI is the first stable user interface for scanner execution and export.
The service layer should let the CLI, dashboard, and reports reuse the same
scan and persistence paths. The current CLI is documented in [CLI.md](CLI.md)
and runs local scanners through normalized findings without adding storage,
dashboard behavior, or assessment models.

### Built-in Dashboard and Reports

The built-in dashboard is for local exploration and drill-down. Current reports
are evidence-only Markdown, JSON, and console outputs for sharing scanner
observations with technical, security, advisory, and CTO audiences. These
outputs contribute to the intended Technology Due Diligence Evidence Package
and other executive deliverables described in
[EXECUTIVE_DELIVERABLES.md](EXECUTIVE_DELIVERABLES.md). Technical evidence can
feed multiple report types, but reports must keep summary claims tied to
observed findings and must not add risk scores, executive priority,
remediation recommendations, ownership inference, or other assessment
conclusions.

### Optional Prometheus and Grafana

Prometheus is for aggregate operational metrics and trends only. Grafana is an
optional visualization pack for teams that already operate it. Neither should
be required for first use.

### Future Executive Priority Index

The Executive Priority Index is a future decision-support layer. It should be
built only after normalized findings, history, confidence, ownership horizon,
and migration-difficulty models exist.

## Current Repository Evidence

- `scanner/filesystem.py` performs local file-signature checks and volume-level
  encryption checks.
- `scanner/cloud.py`, `scanner/gcs.py`, and `scanner/azure_blob.py` inspect
  cloud object encryption metadata.
- `classifier/` identifies sensitive-data categories and returns category
  counts, not matched values.
- `code_analysis/` uses Semgrep with a vendored crypto rule set for local code
  crypto analysis of source text; its rules currently target Python source
  only, and an execution failure there returns an empty result on stderr rather
  than propagating through the `scanner_errors` path the cloud adapters use
  (see [CLAIMS_AUDIT.md](CLAIMS_AUDIT.md)).
- `scanner/crypto_inventory.py` parses local certificate and key assets into
  evidence-first inventory findings, owns the traversal and scan accounting for
  those scans, and declares the static detector registry.
- `scanner/crypto_detectors.py` holds the shared crypto-detector framework the
  registry is built from: scan contexts, detector declarations, detection
  results, safe metadata allowlisting, and detector error isolation.
- `findings.py` defines the versioned normalized finding model.
- `finding_adapters.py` maps current scanner DataFrames into normalized
  findings without changing existing scanner behavior.
- `harvestguard.py` provides the unified local CLI entry point.
- `reports.py` formats normalized findings into console summaries, JSON, and
  professional Markdown evidence reports without changing the normalized
  finding schema.
- `analyzer/risk.py` contains a simple heuristic risk score.
- `main.py` wires current scan types into Streamlit.
- `tests/` covers local scanning, classifier behavior, code analysis, risk
  scoring, crypto inventory, the normalized model and adapters, the CLI,
  reports, scanner-error handling, and all three cloud scanners (S3 included,
  in `tests/test_cloud.py`), plus the HG-008 end-to-end install/run/report
  validation and the HG-009 detection-characterization regression coverage.
