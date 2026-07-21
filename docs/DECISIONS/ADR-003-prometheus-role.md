# ADR-003: Prometheus Role

- **Status:** Accepted
- **Date:** 2026-07-20

## Context

Prometheus and Grafana can help operational teams understand scan frequency,
runtime, failures, and trend-level exposure. They are poor places to store
detailed findings because labels and time series can leak paths, object names,
entities, or sensitive context.

## Decision

Prometheus stores operational and trend metrics only. It must not store detailed
findings.

Allowed examples include scan counts, durations, failure counts, finding totals
by broad class, and aggregate trend metrics. Disallowed examples include file
paths, bucket object names, matched sensitive values, raw finding JSON, and
per-asset evidence details.

Grafana is optional and uses only Prometheus-safe aggregate metrics.

## Consequences

- The detailed system of record remains SQLite initially.
- Metrics endpoint design must include a privacy review.
- Grafana dashboards are optional operational add-ons, not a product
  dependency.
- Contributors must avoid high-cardinality or sensitive Prometheus labels.
