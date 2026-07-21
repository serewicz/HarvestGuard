# HG-006: Demo Target

## Business Purpose

Give contributors, evaluators, and diligence users a safe way to see
HarvestGuard behavior without scanning real confidential data.

## User Outcome

A user can run a demo scan locally and compare output to documented expected
findings.

## Scope

- Create a small local demo fixture.
- Include examples that exercise encryption evidence, sensitive-data category
  counts, confidence, and reports.
- Use fake, clearly marked sample data only.
- Keep demo scans local and credential-free.

## Out of Scope

- Real secrets, credentials, PII, or customer data.
- Cloud demo infrastructure.
- Large benchmark corpus.
- New scanner logic.

## Dependencies

- HG-002.
- HG-003.

## Implementation Considerations

- Use deterministic fixture files.
- Include intentionally fake values for sensitive-data patterns.
- Document expected findings.
- Make the fixture small enough for CI.

## Acceptance Criteria

- Demo target can be scanned without credentials or network access.
- Expected findings are documented.
- Tests verify demo output remains stable.
- Demo data is clearly fake.

## Testing Requirements

- Add tests that scan the demo fixture and compare expected categories and
  evidence.
- Ensure tests do not depend on platform-specific volume encryption status.

## Documentation Requirements

- Add a demo walkthrough.
- Explain that demo values are fake and must not be used as real credentials.

## Privacy and Security Considerations

- Do not include real sensitive data.
- Avoid examples that train users to paste real secrets into issues.
