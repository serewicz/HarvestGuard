# HG-004: CLI

## Business Purpose

Make HarvestGuard usable in repeatable diligence, CI, and remediation workflows
without requiring users to operate the Streamlit dashboard.

## User Outcome

A user can run scans from the command line, receive structured output, and use
exit codes to automate follow-up.

## Scope

- Add a CLI entry path for existing scan types.
- Support JSON output suitable for report and storage work.
- Provide clear command help and error messages.
- Preserve current Streamlit behavior.

## Out of Scope

- Replacing the dashboard.
- Adding new scanners.
- Scheduling.
- External services.

## Dependencies

- HG-003.

## Implementation Considerations

- Use standard library CLI tooling unless a dependency is already present and
  appropriate.
- Commands should expose scan type, target, max depth or prefix where relevant,
  output path, and failure behavior.
- Exit codes should distinguish invalid input from scan execution errors.
- Cloud credentials should continue using provider SDK defaults.

## Acceptance Criteria

- CLI can run local filesystem, sensitive-data, S3, GCS, and Azure Blob scans
  where credentials and targets are available.
- CLI can write JSON output.
- Invalid arguments fail with a useful message and nonzero exit code.
- Streamlit app runtime behavior is unchanged.

## Testing Requirements

- Add CLI unit tests for argument parsing.
- Add smoke tests for local scan and sensitive-data scan using temporary files.
- Mock cloud scanner calls.

## Documentation Requirements

- Add CLI usage examples.
- Update README only when CLI behavior ships.

## Privacy and Security Considerations

- Output defaults should avoid raw sensitive matched values.
- CLI must not enable telemetry.
- Error messages should avoid dumping credentials or raw sensitive content.
