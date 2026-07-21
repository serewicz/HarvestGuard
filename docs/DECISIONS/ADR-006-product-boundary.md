# ADR-006: Define HarvestGuard's Product Boundary

- **Status:** Accepted
- **Date:** 2026-07-20

## Context

HarvestGuard could easily expand into adjacent categories because
cryptographic inventory overlaps with:

- vulnerability management;
- cloud security posture management;
- SIEM and security operations;
- GRC and compliance;
- secrets scanning;
- data discovery;
- asset management;
- remediation orchestration;
- broader cybersecurity assessment.

Many of these capabilities may be technically feasible, but adding them would
dilute HarvestGuard's differentiated value and create unnecessary competition
with mature enterprise platforms.

HarvestGuard's differentiated role is to inventory cryptographic assets,
preserve defensible evidence, and package that evidence for technology due
diligence, executive assessment, integration planning, and future
cryptographic migration planning.

## Decision

HarvestGuard will remain a focused cryptographic asset inventory and
evidence-collection product.

Its intended executive-facing deliverable is the Technology Due Diligence
Evidence Package.

HarvestGuard will complement existing security, cloud, asset-management,
vulnerability-management, and governance tooling rather than attempt to replace
them.

Features belong in the core product only when they materially improve at least
one of:

- cryptographic asset discovery;
- cryptographic inventory completeness;
- evidence accuracy or defensibility;
- evidence provenance;
- normalized findings;
- report quality;
- the Technology Due Diligence Evidence Package;
- standalone local usability;
- integration of mature third-party cryptographic analysis tools.

Features do not belong in the core product merely because they:

- are security-related;
- are adjacent to cryptography;
- would make the dashboard more impressive;
- are requested by one potential user;
- are easy to implement;
- duplicate an established enterprise platform.

## Explicit Non-Goals

HarvestGuard is not intended to become:

- a general-purpose vulnerability scanner;
- a SIEM;
- a CSPM or CNAPP platform;
- a GRC platform;
- a broad secrets-management platform;
- an enterprise asset-management platform;
- a general data-classification platform;
- an autonomous remediation platform;
- a replacement for existing enterprise security platforms.

Limited capabilities from adjacent categories may still be appropriate when
they are narrowly required to collect or validate cryptographic evidence. For
example, sensitive-data detection may be relevant when it helps assess
long-lived encrypted data exposure, but broad data-loss-prevention
functionality is outside the product boundary.

## Consequences

Positive consequences:

- clearer roadmap decisions;
- reduced mission creep;
- stronger product differentiation;
- more consistent contributor and AI-agent decisions;
- easier integration with existing enterprise tooling;
- more defensible executive reporting.

Tradeoffs:

- some useful adjacent functionality will intentionally remain outside the core
  product;
- integrations may be preferred over native implementations;
- HarvestGuard may appear narrower than generic security platforms;
- some customer requests will need to be declined, integrated, or handled
  outside the core product.

## Feature-Fit Test

Canonical question:

"Does this change materially improve cryptographic inventory, evidence quality,
the Technology Due Diligence Evidence Package, or standalone usability?"

If the answer is no, the feature should normally remain outside the core
roadmap.

Secondary question:

"Could HarvestGuard integrate evidence from an existing mature tool instead of
rebuilding that capability?"
