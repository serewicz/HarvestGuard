# ADR-002: Local Evidence Store

- **Status:** Accepted
- **Date:** 2026-07-20

## Context

HarvestGuard needs scan history, report generation, baseline comparison,
remediation status, and future operational views. These features need a system
of record, but first use must stay local and simple.

The project should avoid requiring PostgreSQL, cloud databases, or managed
services for early users evaluating confidential targets.

## Decision

SQLite is the initial local system of record for HarvestGuard.

The local store should hold scan runs, normalized findings, immutable raw
evidence, and separate assessment records such as owner, remediation status,
priority, and notes.

## Consequences

- SQLite support is part of the default product path.
- PostgreSQL may be added later as an optional deployment mode, not as a first
  use requirement.
- Raw findings must remain immutable; assessment fields are stored separately.
- Schema design must support repeat scans, report generation, and drift
  detection without changing scanner behavior.
