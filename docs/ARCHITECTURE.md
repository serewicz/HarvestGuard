# Architecture

HarvestGuard is currently a small Python and Streamlit application with local
filesystem, AWS S3, GCS, Azure Blob, sensitive-data classification, Semgrep-
based code crypto analysis, dashboard, and risk-analysis modules. The target
architecture keeps that implementation local-first while creating clearer
boundaries for scanner growth, reports, and future operations.

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

### Normalized Finding Model

The normalized finding model is the contract between scanners and every
downstream feature. The current internal contract is documented in
[NORMALIZED_FINDINGS.md](NORMALIZED_FINDINGS.md). It distinguishes:

- asset identity and source;
- observed evidence;
- scanner metadata;
- confidence and limitations;
- derived exposure or risk fields;
- immutable raw finding details;
- separately mutable assessment fields.

Assessment concepts such as business impact, severity, remediation cost,
ownership, quantum risk, and executive priority are deliberately excluded from
the normalized finding model.

### Local Evidence Store

SQLite is the initial local system of record. It should store scan runs,
normalized findings, immutable raw details, and separate assessment records.

The store must support local-first operation, repeat scans, report generation,
and future drift comparison without requiring a server or external database.

### CLI and Service Layer

The CLI is the first stable user interface for scanner execution and export.
The service layer should let the CLI, dashboard, and reports reuse the same
scan and persistence paths.

### Built-in Dashboard and Reports

The built-in dashboard is for local exploration and drill-down. Reports are for
sharing findings with executive and technical audiences. Both must link summary
claims back to technical evidence and show confidence where relevant.

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
  crypto analysis.
- `scanner/crypto_inventory.py` parses local certificate and key assets into
  evidence-first inventory findings.
- `findings.py` defines the versioned normalized finding model.
- `finding_adapters.py` maps current scanner DataFrames into normalized
  findings without changing existing scanner behavior.
- `analyzer/risk.py` contains a simple heuristic risk score.
- `main.py` wires current scan types into Streamlit.
- `tests/` covers local scanning, classifier behavior, code analysis, risk
  scoring, GCS, and Azure Blob behavior. S3 scanner coverage remains an open
  improvement.
