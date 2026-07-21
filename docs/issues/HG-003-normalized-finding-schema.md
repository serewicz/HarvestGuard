# HG-003: Normalized Finding Schema

## Business Purpose

Create a stable contract between scanners, reports, storage, dashboard, and
future prioritization so contributors do not build incompatible result shapes.

## User Outcome

A user sees consistent finding fields regardless of whether the evidence came
from local files, cloud metadata, or sensitive-data classification.

## Scope

- Define a normalized finding schema.
- Include source, asset identity, evidence, inference, confidence, scanner
  metadata, timestamps, raw immutable details, and assessment linkage.
- Provide adapter mapping guidance for existing scanner outputs.
- Keep schema local-first and report-friendly.

## Out of Scope

- Full database implementation.
- New scanner features.
- Dashboard redesign.
- PostgreSQL support.

## Dependencies

- HG-001.
- HG-002.
- ADR-002: Local Evidence Store.
- ADR-005: Evidence Versus Inference.

## Implementation Considerations

- Prefer a simple Python model or documented schema that can be adopted
  incrementally.
- Existing dataframe columns may remain during transition.
- Raw findings and mutable assessment data should not be conflated.
- Include room for scanner limitations and confidence.

## Acceptance Criteria

- Schema fields and meanings are documented.
- Existing scanner outputs have documented mappings.
- Evidence and inference fields are distinct.
- Raw details are marked immutable.
- Future CLI and report work can depend on the schema.

## Testing Requirements

- Add unit tests for converting existing scanner output into the normalized
  schema in the implementation PR.
- Include examples for filesystem, S3, GCS, Azure Blob, code analysis, and
  classifier output.

## Documentation Requirements

- Update architecture documentation with the schema boundary.
- Link schema from roadmap item HG-003.

## Privacy and Security Considerations

- Schema must not require raw sensitive matched values.
- Avoid using high-cardinality or sensitive fields as metric labels later.
- Store only data needed for evidence, auditability, and remediation.
