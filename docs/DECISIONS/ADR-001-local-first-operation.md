# ADR-001: Local-first Operation

- **Status:** Accepted
- **Date:** 2026-07-20

## Context

HarvestGuard is intended for diligence and advisory workflows where scan
targets may contain confidential deal data, customer data, intellectual
property, and cloud metadata. Users must be able to run the tool without
sharing scan details with a HarvestGuard-operated service.

The existing security documentation already positions the container and local
runtime as the trust boundary. Local filesystem and sensitive-data scans should
not require network access. Cloud scans need outbound access only to the
selected provider APIs.

## Decision

HarvestGuard is local-first and private by default.

First use must not require a hosted service, telemetry endpoint, external
database, Grafana, or Prometheus. Scan data, file paths, object names,
credentials, matched sensitive values, and detailed findings must remain on the
machine or environment where the user runs HarvestGuard unless the user
explicitly exports or shares them.

## Consequences

- CLI, local reports, local dashboard, and local evidence storage take priority
  over hosted workflows.
- Any future API must be local and explicitly enabled unless a later ADR
  changes this direction.
- Documentation and README claims must not imply that scan data leaves the
  user's environment.
- Cloud adapters may call cloud provider APIs required for the scan target, but
  must not transmit findings to HarvestGuard.
