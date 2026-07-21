# HG-007: JSON and Markdown Reports

## Business Purpose

Produce portable artifacts that technical teams, diligence teams, and advisors
can review without needing the dashboard.

## User Outcome

A user can export normalized findings as machine-readable JSON and a
human-readable Markdown report.

## Scope

- JSON export from normalized findings.
- Markdown report with executive summary and technical appendix sections.
- Clear separation of evidence and inference.
- Safe omission of raw sensitive matched values.

## Out of Scope

- PDF or HTML report generation.
- Executive Priority Index.
- Hosted report sharing.
- Grafana dashboards.

## Dependencies

- HG-003.
- HG-004.

## Implementation Considerations

- JSON should preserve normalized schema fields.
- Markdown should summarize evidence, confidence, exposure, and remediation
  themes.
- Reports should be deterministic enough for tests.
- Avoid adding dependencies for Markdown generation.

## Acceptance Criteria

- CLI can write JSON report.
- CLI can write Markdown report.
- Reports separate observed evidence from inferred risk.
- Reports do not include raw sensitive matched values.
- Reports include generation metadata and scanner limitations.

## Testing Requirements

- Snapshot or content tests for JSON and Markdown output.
- Tests verify sensitive matched values are not emitted.
- Tests verify evidence and inference sections remain distinct.

## Documentation Requirements

- Document report commands and report field meanings.
- Update README when report export ships.

## Privacy and Security Considerations

- Reports can contain sensitive paths or object names; document handling
  expectations.
- Never emit matched secret or PII values.
- Keep report generation local by default.
