# HarvestGuard — Project Context

Handoff notes from a prior session, written for Claude Code (or any fresh agent) picking this up. Drop this file in the repo root as `CLAUDE.md`, or paste it as your first prompt.

## What this is

Open-source cryptographic inventory and quantum-risk (Harvest-Now-Decrypt-Later) scanner. Streamlit app + CLI, Apache-2.0, Python 3.10+. Target users: M&A/PE due diligence teams assessing a target company's encryption posture. Built by Timothy Serewicz.

## Current state of the code (100% Python, MVP stage)

- `main.py` — Streamlit entry point. Sidebar picks "Local Filesystem" or "AWS S3 Bucket", runs a scan, renders results.
- `scanner/filesystem.py` — walks a path, records size/mtime/owner. **Encryption detection is a hardcoded placeholder (`"Unknown"`) — not implemented.** This is the single biggest gap and the actual value proposition of the tool.
- `scanner/cloud.py` — real logic: checks each S3 object's `ServerSideEncryption` header via boto3, flags unencrypted objects High risk. This one works, not a stub.
- `analyzer/risk.py` — simple heuristic scoring (base 50, +40 if unencrypted, +20 if "Sensitive" in path string, capped at 100). Buckets into High/Medium/Low HNDL exposure.
- `dashboard/visualizations.py` — Plotly pie + bar chart, raw data table.
- `requirements.txt` — streamlit, boto3, pandas, plotly, pydantic, prometheus-client, python-dotenv, weasyprint (weasyprint is listed for PDF export but that export isn't built yet).
- `docs/` folder exists in the repo but its contents were never retrieved (GitHub's file browser is JS-rendered; no browser tool was available to read it in the prior session — worth checking manually).

## Scaffolding added in the prior session (ships as a zip, needs to be unzipped into repo root)

- `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md`
- `.github/workflows/ci.yml` (pytest + ruff on Python 3.10/3.11/3.12 matrix)
- `.github/ISSUE_TEMPLATE/bug_report.md`, `feature_request.md`, `.github/pull_request_template.md`
- `pyproject.toml` (pytest + ruff config; not yet a real installable package — see note inside the file)
- `requirements-dev.txt` (pytest, ruff)
- `.gitignore`
- `tests/conftest.py`, `tests/test_risk.py`, `tests/test_filesystem.py` — cover `analyzer/risk.py` and `scanner/filesystem.py`. Verified by manually running the same assertions against the real module code (pytest itself wasn't installable in the sandbox that produced this) — all passed.

None of this has been committed/pushed yet — the prior session had no way to reach github.com (proxy blocked both HTTPS clone and SSH to port 22), so the scaffolding was handed off as a zip for manual commit.

## Recommended next priorities, roughly in order

1. Real encryption/algorithm detection in `scanner/filesystem.py` — read file headers/magic bytes for known encrypted formats, check filesystem-level encryption (LUKS/FileVault/BitLocker), replace the `"Unknown"` placeholder.
2. Commit the scaffolding above and confirm CI goes green.
3. Additional cloud scan targets (Azure Blob, GCS) following the `scanner/cloud.py` pattern.
4. CBOM JSON export and the PDF export the README promises (weasyprint dependency is already declared, unused).
5. Read `docs/` in the actual repo to see if it changes any of the above priorities — it wasn't accessible in the prior session.
