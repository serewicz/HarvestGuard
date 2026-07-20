# HarvestGuard — Project Context

Context for Claude Code (or any fresh agent) picking up this repo.

## What this is

Open-source cryptographic inventory and quantum-risk (Harvest-Now-Decrypt-Later) scanner. Streamlit app, Apache-2.0, Python 3.10+. Target users: M&A/PE/legal due-diligence teams assessing a target company's encryption and sensitive-data posture. Built by Timothy Serewicz.

## Current state of the code

- `main.py` — Streamlit entry point. Sidebar selects one of five scan types (Local Filesystem, AWS S3 Bucket, GCS Bucket, Azure Blob Container, Local Filesystem — Sensitive Data), runs the scan, renders results.
- `scanner/filesystem.py` — real encryption detection: per-file signature checks (OpenSSL, PGP/GPG, age, LUKS containers, encrypted ZIP), falling back to volume-level status (FileVault/LUKS/BitLocker, checked once per scan root and cached). Signature coverage is still narrow (no encrypted Office/PDF/VeraCrypt yet).
- `scanner/cloud.py` — AWS S3: checks each object's `ServerSideEncryption` header via boto3. No tests yet (see roadmap Pillar 4).
- `scanner/gcs.py` — GCS: CMEK vs. Google-managed per blob. Catches both `GoogleAPIError` and `google.auth.exceptions.DefaultCredentialsError` — the latter is raised eagerly by `storage.Client()` construction, not by the list call, and was missed in an early version (crashed the whole app; caught by manually running the app, not by code review — worth remembering when adding a new cloud scanner).
- `scanner/azure_blob.py` — Azure Blob: customer-managed encryption scope vs. Microsoft-managed default. Named to avoid shadowing the `azure` package it imports from. Uses `DefaultAzureCredential`.
- `classifier/` — PII/secrets detection (`patterns.py` regexes, `scanner.py` file walk). Reports category + count only, never the matched values, by design: a scan result must not itself leak the sensitive data it found.
- `analyzer/risk.py` — heuristic scoring (base 50, +40 if unencrypted-equivalent, +20 if "Sensitive" in path, capped at 100). Buckets into High/Medium/Low HNDL exposure. `_UNENCRYPTED_VALUES` is the one place that maps scanner-output strings to "counts as unencrypted" — extend it there if a new scanner introduces another "unencrypted" sentinel string.
- `dashboard/visualizations.py` — `display_risk_dashboard` (pie + bar + table; used by the four encryption-status scan types) and `display_sensitive_data_dashboard` (per-category bar chart + flagged-files table; used only by the classifier scan type). Two separate dashboards because the two data shapes aren't unified yet — see the deferred `ScanResult` interface item below.
- `requirements.txt` — streamlit, boto3, google-cloud-storage, azure-storage-blob, azure-identity, pandas, plotly, pydantic, prometheus-client, python-dotenv, weasyprint (weasyprint is for PDF export, declared but not yet wired up).

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
3. Containerization (roadmap Pillar 2) — not started.
4. Test coverage for `scanner/cloud.py` — the one scanner module with zero
   tests.
