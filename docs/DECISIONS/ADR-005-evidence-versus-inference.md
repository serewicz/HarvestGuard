# ADR-005: Evidence Versus Inference

- **Status:** Accepted
- **Date:** 2026-07-20

## Context

HarvestGuard users need defensible language. A scanner can observe evidence
such as a file signature, cloud encryption metadata, volume encryption status,
or a sensitive-data pattern count. It may then infer exposure, HNDL concern, or
remediation priority from that evidence.

Mixing evidence and inference makes findings harder to validate and can cause
reports to overstate certainty.

## Decision

Observed evidence is separated from inferred risk throughout HarvestGuard.

Raw findings must preserve observed evidence and scanner context. Risk scores,
exposure labels, executive priority, ownership horizon, remediation status, and
business interpretation live in a separate assessment layer.

## Consequences

- Normalized findings need fields for evidence, confidence, scanner metadata,
  and limitations.
- Reports and dashboards must show enough evidence for technical users to
  verify a claim.
- Executive summaries must link back to technical details.
- Risk language must identify assumptions and avoid presenting heuristic output
  as proof.
