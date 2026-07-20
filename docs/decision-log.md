# HarvestGuard Decision Log

- **2026-07-20**: Chose Streamlit for POC dashboard (fast iteration). Will add Prometheus/Grafana later.
- **Architecture**: Monolithic for MVP → microservices post-validation.
- **License**: Apache 2.0
- **Target**: M&A due diligence workflow
- **2026-07-20**: Broadened scope beyond crypto/HNDL posture to include general sensitive-data discovery (PII, secrets/credentials) — the target audience asks "where is the customer data and is it protected?", not just "is encryption strong?".
- **2026-07-20**: Classifier findings report category + count only, never the matched values — a scan result must not itself become a way to leak the sensitive data it found.
- **2026-07-20**: `scanner/azure_blob.py` (not `scanner/azure.py`) — avoids shadowing the top-level `azure` package the module imports from.
- **2026-07-20**: CBOM export will target the CycloneDX 1.6+ CBOM format rather than a bespoke JSON shape, for interoperability with other tools a due-diligence team might already run.
- **2026-07-20**: Common `ScanResult` interface deliberately deferred until a second cloud backend existed, to avoid speculative abstraction — condition now met (S3 + GCS + Azure).
