# Scan Coverage, Pagination, and Partial Results

This document defines HarvestGuard's scale, pagination, and safety semantics
(roadmap item HG-005): what "complete" means for a scan, how a configured
limit differs from a scanner failure, how large buckets and deep directory
trees are traversed without silently truncating, and how a scan that fails
partway through still returns what it found. It complements
[ASSET_INVENTORY.md](ASSET_INVENTORY.md) and
[NORMALIZED_FINDINGS.md](NORMALIZED_FINDINGS.md), which define the evidence
model these semantics are expressed through (`unknowns`, `limitations`,
`errors`, `technical_metadata`) — this document does not introduce new
schema fields.

## Completeness semantics

- **Complete scan** — the scanner processed the configured scope without
  scanner execution errors. Configured scope may already be limited by
  prefix, `--exclude`, or `max_depth`.
- **Limited scan** — the user intentionally bounded scope (an S3/GCS/Azure
  prefix, a CLI `--exclude` pattern, or filesystem `max_depth`). A configured
  limit is not a scanner failure — it exits `0` — but the resulting boundary
  is still recorded as an explicit finding wherever the scanner knows about
  it, so it stays visible.
- **Partial scan** — the scanner collected some valid findings but could not
  complete the configured scope because of a permission, provider,
  authentication, API, page, object/blob, or traversal failure.
- **Skipped asset** — a known asset or scope boundary intentionally not
  inspected: a directory beyond `max_depth`, or a symlink/FIFO/socket/device
  file skipped for safety. Represented as an explicit finding, never as
  silent absence.
- **Inaccessible asset** — an asset HarvestGuard attempted to inspect but
  could not access. Represented as a finding-level `limitations` entry where
  a normalized finding exists, or as a scan-level scanner error where no safe
  per-asset finding can be produced.
- **Provider/auth/API failure** — a cloud scanner failure from credentials,
  the provider service, the SDK, or a page/object/blob operation. Surfaced
  through the existing `CloudScanError` / `scanner_errors` path, with partial
  findings preserved.
- **Unsupported observation** — a condition HarvestGuard cannot currently
  inspect. Represented with `unknowns`, `limitations`, or per-finding
  `errors`; never turned into an absence of findings.
- **Max-depth boundary** — a configured filesystem recursion boundary. The
  scan root is depth 0. Child directories below a directory at `max_depth`
  are not descended into and are represented by explicit boundary findings.
- **Pagination boundary** — a normal provider page boundary is not a
  limitation by itself. A *failed* later page is a partial scan.

The rule threading through all of these: **absence of a finding is never
proof that an asset was inspected and found clean.** Where coverage was
bounded, skipped, or interrupted, that fact is a finding (or a
`scanner_errors` entry), not silence.

## Filesystem: `max_depth` and traversal safety

- Depth is measured from the scan root, which is **depth 0**. A direct child
  directory of the root is depth 1. `max_depth=N` inspects files in
  directories up to and including depth N.
- Child directories below depth N are **pruned before descent** — nothing
  beneath the boundary is listed, `stat`'d, or opened. Each pruned directory
  produces one `asset_type="directory"`, `rule_id="max_depth_boundary"`
  finding with `unknowns` and `limitations`, so the boundary stays visible
  even though its contents were never touched.
- A trailing separator on the target path (`/data/` vs `/data`) does not
  change the depth boundary — both describe the same scan root.
- A directory `os.walk` cannot list at all (permission denied, and similar)
  produces an `asset_type="directory"`, `rule_id="directory_traversal_error"`
  finding instead of silently omitting whatever might be inside it. No
  file-level findings are ever fabricated for scope that was not traversed.
- Symlinks (including symlinked directories), FIFOs, sockets, and device
  files are **not followed or opened** by the normalized filesystem evidence
  path — opening a FIFO with no writer can block indefinitely, and following
  a symlink can read data outside the intended scan root. Each such entry
  still produces an explicit `asset_type="special_file"`,
  `rule_id="skipped_special_file"` finding recording that it was identified
  and deliberately not inspected, so "not inspected" is never presented as
  "inspected and nothing found."
- A permission failure or a file that disappears mid-scan produces a
  finding with a `limitations` entry rather than silently vanishing from
  results.
- The legacy `scan_filesystem()` DataFrame function (used by the Streamlit
  dashboard) is unchanged by any of the above; it remains a separate,
  best-effort path.

## AWS S3: pagination

- `list_objects_v2` returns at most 1,000 keys per call. HarvestGuard follows
  every page using the provider's own `NextContinuationToken`, so a bucket
  with more than 1,000 objects under a prefix is scanned completely, not just
  its first page.
- The requested `prefix` is sent on every page request, including
  continuation requests.
- Findings are appended per object as pages are processed; no object is
  normalized twice across pages.
- A truncated response that carries no continuation token means the provider
  cannot say where to resume. That is treated as a coverage failure (a
  `scanner_errors` entry, preserved partial findings), not as the end of the
  listing — otherwise a scan that silently lost its place would report
  itself as complete.
- A failure reading an individual object's encryption status, or listing a
  later page, does not discard objects already found: `scan_s3_bucket_findings`
  raises `CloudScanError` with `partial_findings` populated from everything
  collected up to that point.

## GCS and Azure Blob: SDK iterator behavior

Both `google-cloud-storage`'s `list_blobs` and `azure-storage-blob`'s
`list_blobs` return the provider SDK's own paging iterator: later pages are
fetched transparently as iteration advances. HarvestGuard does not track
page/continuation tokens itself for these two providers — it processes every
blob the iterator yields, in order, exactly once, and relies on the SDK to
handle paging correctly (there is no evidence the SDK iterators need an
explicit HarvestGuard-side pagination rewrite; see the Testing Requirements
in GitHub issue #17 for the coverage that would surface such a gap).

- The requested `prefix` (S3-style path prefix for GCS, `name_starts_with`
  for Azure) is passed straight through to the SDK call.
- If iteration raises after already yielding one or more blobs (a later
  page, an expired credential, a transient provider error), the blobs
  already observed are preserved: `scan_gcs_bucket_findings` and
  `scan_azure_container_findings` raise `CloudScanError` with
  `partial_findings` populated from what was collected before the failure.

## Provider/auth/API failure handling

Every cloud scanner (S3, GCS, Azure Blob) follows the same shape:

1. The DataFrame-producing function (`scan_s3_bucket`, `scan_gcs_bucket`,
   `scan_azure_container`) never raises on a provider/auth/API failure — it
   records the failure into an `errors` list the caller supplies (or prints
   it, for the Streamlit dashboard's best-effort path) and returns whatever
   rows it already collected.
2. The `*_findings` wrapper (`scan_s3_bucket_findings`, and so on) checks
   that `errors` list. If it is non-empty, it raises `CloudScanError` whose
   message is the joined error text and whose `partial_findings` attribute
   holds the already-collected, already-normalized findings.
3. The CLI catches `CloudScanError` like any other scanner exception: the
   partial findings are added to the run's output, the failure is recorded
   in `scanner_errors`, and the process exits with the scanner-error code
   (`1`) by default.

Provider exception text is service-controlled and can be long or carry
response fragments, so it is never dumped wholesale into evidence output.
`scanner.errors.sanitize_provider_error` renders it as a single line, capped
at 300 characters, keeping the exception type and the leading part of the
message (where providers put the error code and failing operation) and
truncating the rest.

## Partial findings and the CLI

Given findings A and B were collected before a later failure:

- A and B remain in the CLI's output.
- The failure is recorded in `scanner_errors` (or, for a single-scan-type
  invocation, surfaces through the same reporting path).
- `--json` stdout remains valid, parseable JSON containing A and B; the
  failure message goes to stderr and/or the report context, never mixed
  into stdout.
- The process exits with the scanner-error code (`1`) by default. Pass
  `--no-fail-on-error` to force exit `0` despite a recorded scanner error.
- `--markdown` output includes A and B in Detailed Findings, lists the
  failure under Errors and Warnings, and states plainly that coverage was
  not complete (see below) — it never reads as proof of a clean scan.

## Markdown and console reporting

- The Markdown report's **Scan Information** table includes a `Coverage`
  row: `Not complete` whenever any finding carries a `limitations` entry or
  the scan recorded a `scanner_errors` entry, `No limits recorded`
  otherwise.
- A **Coverage was not complete** statement appears (in both the Markdown
  report and the console summary) whenever that condition holds, naming how
  many scanner errors and how many limitation-carrying findings were
  recorded. It draws no conclusion beyond that — it is evidence-only,
  consistent with [PRODUCT_PRINCIPLES.md](PRODUCT_PRINCIPLES.md).
- Every finding's `limitations` text is rendered in full in Detailed
  Findings (not just counted), so a technical reviewer can see exactly what
  scope was skipped or only partially observed, per finding.
- The Errors and Warnings section also breaks down limitation findings by
  `rule_id` (`max_depth_boundary`, `directory_traversal_error`,
  `skipped_special_file`, …) with a count for each.
- Coverage-limitation findings (a pruned directory, an unreadable directory,
  a skipped special file) are never counted toward "Files Scanned" — they
  record scope that was *not* inspected, so counting them would overstate
  coverage.

## Credentials

HarvestGuard never manages, stores, prompts for, or emits cloud
credentials. Every cloud scanner resolves credentials exclusively through
that provider SDK's own default credential chain (`boto3`'s default chain
for S3, Application Default Credentials for GCS, `DefaultAzureCredential`
for Azure). This is unchanged by HG-005 and is not something HG-005 adds
configuration for.

## What HG-005 deliberately does not change

- `NormalizedFinding`'s schema (see `unknowns`, `limitations`, `errors`,
  `technical_metadata` above — no new fields were added).
- Risk scoring, HNDL scoring, remediation priority, or any other assessment
  layer field.
- The Streamlit dashboard's layout or legacy DataFrame-returning scanner
  functions, beyond the narrow safety fix to skipped-asset visibility
  described above.
- Report structure beyond the truthful coverage/limitation additions
  described above (full report redesign is roadmap item HG-007).
