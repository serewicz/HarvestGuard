# HarvestGuard Decision Log

Architecture decisions are now captured as ADRs in
[docs/DECISIONS/](DECISIONS/README.md). This file is retained as a historical
index so older references do not break.

Historical notes preserved in ADRs and roadmap:

- 2026-07-20: Chose local-first operation as the trust boundary.
- 2026-07-20: Chose SQLite as the initial local evidence store direction.
- 2026-07-20: Prometheus and Grafana are optional operational layers, not first
  use requirements.
- 2026-07-20: Broadened scope to include sensitive-data discovery only where it
  supports crypto, diligence, remediation, or advisory value.
- 2026-07-20: Classifier findings report category and count only, never matched
  values.
- 2026-07-20: `scanner/azure_blob.py` avoids shadowing the top-level `azure`
  package.
- 2026-07-20: CBOM export should target CycloneDX rather than a bespoke JSON
  shape.
- 2026-07-20: Common scan-result normalization is now appropriate because S3,
  GCS, and Azure adapters exist.
