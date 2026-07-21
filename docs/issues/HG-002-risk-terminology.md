# HG-002: Defensible Risk Terminology

## Business Purpose

Make HarvestGuard's findings suitable for diligence, advisory, legal, and
technical remediation conversations by using precise language.

## User Outcome

A user can tell the difference between observed evidence, inferred exposure,
confidence, and recommended remediation priority.

## Scope

- Define core terms: observed evidence, inference, confidence, exposure, HNDL
  exposure, risk score, remediation priority, false positive, and false
  negative.
- Align roadmap, architecture, dashboard labels, and reports with those terms.
- Identify current terminology that needs validation before release claims.

## Out of Scope

- Rewriting the risk engine.
- Adding new scoring models.
- Changing scanner output.
- Legal advice.

## Dependencies

- HG-001.
- ADR-005: Evidence Versus Inference.

## Implementation Considerations

- Keep terms concise and plain enough for executive users.
- Make technical evidence precise enough for remediation users.
- Avoid implying that heuristic scores are measured facts.

## Acceptance Criteria

- A terminology section exists in product or architecture documentation.
- Dashboard and report language has a clear path to separate evidence from
  inference.
- Terms are referenced by future schema and report work.
- Uncertain current behavior is marked `Needs Validation` where appropriate.

## Testing Requirements

- Documentation-only changes do not require code tests.
- Future UI or report changes must include tests or review fixtures that verify
  terminology appears correctly.

## Documentation Requirements

- Link terminology from the roadmap and contribution guidance.
- Update README only if existing product claims become inaccurate.

## Privacy and Security Considerations

- Terminology must not encourage users to export sensitive raw data.
- Reports must avoid sensitive matched values while still showing defensible
  evidence.
