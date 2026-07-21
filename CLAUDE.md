# HarvestGuard — Project Context

Context for Claude Code (or any fresh agent) picking up this repo.

## What this is

Open-source cryptographic asset inventory and evidence-collection tool for technology due diligence and future cryptographic migration planning. Streamlit app, Apache-2.0, Python 3.10+. Target users: M&A/PE/legal due-diligence teams assessing a target company's encryption posture, sensitive-data placement, and cryptographic evidence. HarvestGuard complements existing security, cloud, asset-management, vulnerability-management, and governance tooling; it does not replace those platforms. Built by Timothy Serewicz.

## Product identity

HarvestGuard is:

- a focused cryptographic asset inventory and evidence-collection tool;
- intended to support technology due diligence and executive assessment;
- additive to existing enterprise security tooling.

HarvestGuard is not:

- a general-purpose vulnerability scanner;
- a SIEM;
- a CSPM platform;
- a GRC platform;
- an autonomous remediation product;
- a replacement for established enterprise security platforms.

When considering a change, ask: Does this change improve cryptographic asset
inventory, evidence quality, the Technology Due Diligence Evidence Package, or
standalone usability?

Do not broaden the product merely because an adjacent capability is technically
easy.

[ADR-006: Product boundary](docs/DECISIONS/ADR-006-product-boundary.md) is the
authoritative source for feature-boundary decisions. Consult it before adding a
new scanner category, introducing a new service or datastore, expanding the
dashboard, adding compliance frameworks, adding remediation behavior, or
duplicating functionality available from an established tool.

[Executive Deliverables](docs/EXECUTIVE_DELIVERABLES.md) is the canonical
reporting-vision document. New reporting features should support one or more
documented executive deliverables, and reports must preserve traceability from
executive statements back to technical evidence.

## Current state of the code

- `main.py` — Streamlit entry point. Sidebar selects one of six scan types (Local Filesystem, AWS S3 Bucket, GCS Bucket, Azure Blob Container, Local Filesystem — Sensitive Data, Local Filesystem — Crypto Code Analysis), runs the scan, renders results.
- `scanner/filesystem.py` — real encryption detection: per-file signature checks (OpenSSL, PGP/GPG, age, LUKS containers, encrypted ZIP), falling back to volume-level status (FileVault/LUKS/BitLocker, checked once per scan root and cached). Signature coverage is still narrow (no encrypted Office/PDF/VeraCrypt yet).
- `scanner/cloud.py` — AWS S3: checks each object's `ServerSideEncryption` header via boto3. No tests yet (see roadmap Pillar 4).
- `scanner/gcs.py` — GCS: CMEK vs. Google-managed per blob. Catches both `GoogleAPIError` and `google.auth.exceptions.DefaultCredentialsError` — the latter is raised eagerly by `storage.Client()` construction, not by the list call, and was missed in an early version (crashed the whole app; caught by manually running the app, not by code review — worth remembering when adding a new cloud scanner).
- `scanner/azure_blob.py` — Azure Blob: customer-managed encryption scope vs. Microsoft-managed default. Named to avoid shadowing the `azure` package it imports from. Uses `DefaultAzureCredential`.
- `classifier/` — PII/secrets detection (`patterns.py` regexes, `scanner.py` file walk). Reports category + count only, never the matched values, by design: a scan result must not itself leak the sensitive data it found.
- `code_analysis/` — weak/legacy crypto library usage in source, via Semgrep against a small vendored rule set (`rules/crypto.yaml`), not the hosted registry (registry configs need network access; local scans must not). `scanner.py` always passes `--metrics=off --disable-version-check` — both otherwise call home regardless of rule source, confirmed by watching the "new version available" network check disappear once set. Getting this working in the container took three real fixes, all found by running the built image, not by inspecting the Dockerfile: (1) `pip install --target=` bakes the *builder* stage's interpreter path into the console-script shebang, breaking in the distroless runtime — fixed by rewriting the shebang in the Dockerfile; (2) semgrep's compiled core separately `execvp()`s the literal command `pysemgrep` off PATH — fixed by adding `/deps/bin` to `PATH`; (3) semgrep tries to write `$HOME/.semgrep`, which fails under `--read-only` — fixed by setting `HOME=/tmp` (the one writable, tmpfs-mounted path). Verified end-to-end afterward with `--network none --read-only --tmpfs /tmp` together.
- `analyzer/risk.py` — heuristic scoring (base 50, +40 if unencrypted-equivalent, +20 if "Sensitive" in path, capped at 100). Buckets into High/Medium/Low HNDL exposure. `_UNENCRYPTED_VALUES` is the one place that maps scanner-output strings to "counts as unencrypted" — extend it there if a new scanner introduces another "unencrypted" sentinel string.
- `dashboard/visualizations.py` — `display_risk_dashboard` (pie + bar + table; used by the four encryption-status scan types), `display_sensitive_data_dashboard` (per-category bar chart + flagged-files table; classifier), and `display_code_analysis_dashboard` (per-rule bar chart + findings table; code_analysis). Three separate dashboards because the data shapes aren't unified yet — see the deferred `ScanResult` interface item below.
- `requirements.txt` — streamlit, boto3, google-cloud-storage, azure-storage-blob, azure-identity, semgrep, pandas, plotly, pydantic, prometheus-client, python-dotenv, weasyprint (weasyprint is for PDF export, declared but not yet wired up). semgrep adds ~160MB to the container image.

## Recommended next priorities

See `docs/ROADMAP.md` for the full pillar breakdown and rationale — why the
container story is a trust argument and not just packaging, why CBOM export
should target CycloneDX 1.6+, and a tooling-landscape survey for
network/code-level crypto detection. As of this writing:

1. Common `ScanResult` interface — deferred until a second cloud backend
   existed; that condition is now met (S3 + GCS + Azure all ship). Ready to
   pick up.
2. CBOM JSON export (target CycloneDX 1.6+) and PDF export — both referenced
   in the README, neither built yet.
3. Test coverage for `scanner/cloud.py` — the one scanner module with zero
   tests.
4. Network traffic/cipher detection (roadmap Pillar 1) — the other half of
   "Future scan surfaces," not started. Code analysis (this session) covers
   crypto usage in source; nothing yet covers crypto in transit.
5. k8s Job manifest/Helm chart (roadmap Pillar 2) — the one remaining open
   Pillar 2 item, low priority (nobody's running this in-cluster yet).
