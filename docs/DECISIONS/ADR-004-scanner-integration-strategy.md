# ADR-004: Scanner Integration Strategy

- **Status:** Accepted
- **Date:** 2026-07-20

## Context

HarvestGuard currently includes direct scanner adapters for local filesystems
and cloud object storage metadata. Future scan surfaces may include TLS and
network cipher detection, code and binary crypto usage, weak algorithm
detection, entropy analysis, and runtime crypto observation.

Mature open-source scanners already exist for several of these areas.
Rebuilding them inside HarvestGuard would increase maintenance burden and risk
weaker detection.

## Decision

HarvestGuard integrates mature third-party scanners where appropriate rather
than rebuilding specialized scanner logic.

Native adapters are appropriate where provider metadata or local evidence is
simple and directly available. For mature domains such as TLS enumeration,
static crypto API detection, or binary analysis, HarvestGuard should prefer
integration adapters that normalize external scanner output into HarvestGuard's
finding model.

## Consequences

- New scanner proposals should explain whether they are native detection or an
  integration adapter.
- Third-party tools must be optional unless they are required for the selected
  scan type.
- Integrated scanner output must still separate observed evidence from inferred
  risk.
- Additional dependencies require explicit review and should not be added as
  part of governance-only changes.
