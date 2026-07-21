# HG-005: Scale, Pagination, and Safety

## Business Purpose

Prevent incomplete or unsafe findings when users scan large buckets,
directories, or environments with permission boundaries.

## User Outcome

A user can understand whether a scan completed fully, was limited, skipped
assets, or encountered permission/API failures.

## Scope

- Add or validate pagination for cloud scanners.
- Improve traversal safety and depth handling for filesystem scans.
- Represent skipped, inaccessible, or failed observations explicitly.
- Make scan limits visible.

## Out of Scope

- New scanner types.
- Distributed scanning.
- Scheduler implementation.
- External databases.

## Dependencies

- HG-001.
- HG-003.

## Implementation Considerations

- S3 `list_objects_v2` requires pagination for large buckets.
- GCS and Azure iterators should be reviewed for page behavior and error
  surfacing.
- Filesystem traversal should prune directories beyond max depth.
- Avoid treating permission failures as absence of findings.

## Acceptance Criteria

- S3 scans handle all pages for a prefix.
- Scanner errors and skipped counts are visible in output.
- Filesystem scan depth behavior is tested.
- Scan limits and partial results are represented in normalized output.

## Testing Requirements

- Add S3 pagination tests using mocks.
- Add filesystem traversal tests for pruning and inaccessible paths where
  feasible.
- Add tests for visible scanner errors or skipped counts.

## Documentation Requirements

- Document scan limits, partial results, and permissions behavior.
- Update troubleshooting guidance for cloud credentials and API errors.

## Privacy and Security Considerations

- Error reporting must avoid credentials and raw sensitive content.
- Large-scan output should not force export of unnecessary raw details.
