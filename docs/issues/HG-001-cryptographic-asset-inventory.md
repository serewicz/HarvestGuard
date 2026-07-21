# HG-001: Cryptographic Asset Inventory

## Business Purpose

Give diligence and remediation teams a trustworthy inventory of where
cryptographic protection is observed, missing, or uncertain across supported
storage targets.

## User Outcome

A user can scan a supported target and receive asset-level records that explain
what was observed, where it was observed, which scanner produced it, and how
confident the scanner is.

## Scope

- Preserve existing local filesystem, AWS S3, GCS, Azure Blob, code crypto
  analysis, and sensitive-data scanner behavior.
- Identify the minimum inventory fields needed by the normalized finding model.
- Capture observed encryption evidence and scanner source for each supported
  adapter.
- Represent uncertain or inaccessible observations explicitly.

## Out of Scope

- New scanner surfaces such as TLS, code, binary, or runtime crypto analysis.
- Dashboard redesign.
- Executive scoring or prioritization.
- New dependencies.

## Dependencies

- Existing scanner modules.
- Product principles.
- ADR-005: Evidence Versus Inference.

## Implementation Considerations

- Treat current dataframe outputs as existing behavior that may be adapted, not
  broken.
- Preserve current category-count-only sensitive-data behavior.
- Capture cloud provider metadata as observed evidence.
- Avoid storing raw sensitive matched values.

## Acceptance Criteria

- Local filesystem, AWS S3, GCS, Azure Blob, and code crypto analysis scan
  outputs can be mapped to a documented inventory concept.
- Each inventory record includes source, location, observed encryption evidence,
  scanner identity, scan time, and confidence.
- Inaccessible or unknown results are visible rather than silently reclassified.
- README and roadmap claims remain accurate.

## Testing Requirements

- Existing tests continue to pass.
- Add or update tests only if implementation changes are made in a later PR.
- Future implementation PRs must include scanner-specific inventory mapping
  tests.

## Documentation Requirements

- Document inventory fields in the normalized schema work.
- Update README only if user-facing claims change.

## Privacy and Security Considerations

- Do not persist file contents or raw sensitive matched values.
- Do not send findings to external services.
- Redact or avoid unnecessary sensitive path detail in examples.
