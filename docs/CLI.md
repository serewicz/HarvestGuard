# HarvestGuard CLI

HarvestGuard's unified CLI runs the same scanners as the dashboard through the
normalized finding model. It does not add storage, dashboard functionality,
risk scoring, or executive reporting.

## Installation

From the repository root:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

For an editable install that exposes the `harvestguard` command:

```bash
pip install -e .
```

Without installing the console script, run the same CLI as a module:

```bash
python -m harvestguard scan ./target
```

## Usage

```bash
harvestguard scan <target> [--type <type>] [--max-depth N] [--prefix <prefix>] \
    [--summary] [--json [PATH]] [--markdown [PATH]] [--quiet] \
    [--exclude <pattern>] [--fail-on-error | --no-fail-on-error]
```

`<target>` is a local file or directory path for local scan types, a bucket
name for `s3`/`gcs`, or `account-name/container-name` for `azure`.

### Scan types

`--type` selects which scanner runs (default `all`):

| `--type`         | Target                          | Scanner                                     |
| ---------------- | ------------------------------- | ------------------------------------------- |
| `all` (default)  | local path                      | every local scanner below                   |
| `filesystem`     | local path                      | local filesystem encryption evidence        |
| `crypto`         | local path                      | cryptographic asset inventory               |
| `sensitive-data` | local path                      | sensitive-data category detection           |
| `code`           | local path                      | local Semgrep crypto code analysis          |
| `s3`             | bucket name                     | AWS S3 object encryption status             |
| `gcs`            | bucket name                     | GCS object encryption status                |
| `azure`          | `account-name/container-name`   | Azure Blob encryption status                |

`--max-depth` bounds directory recursion for `filesystem` and `sensitive-data`
scans (and the `all` bundle). `--prefix` restricts cloud scans to a key or blob
prefix. Each option is ignored by scan types it does not apply to.

Cloud scans use the provider SDK's default credential resolution (for example
`AWS_PROFILE`/instance role for S3, application-default credentials for GCS,
`DefaultAzureCredential` for Azure). The CLI does not read, prompt for, or
store credentials itself.

## Examples

Default summary (all local scanners):

```bash
harvestguard scan ./target
```

Example output:

```text
HarvestGuard Scan Complete

Files scanned: 412

Findings

Certificates: 18
Private Keys: 5
Encrypted Keys: 1
SSH Keys: 2
PKCS#12: 1
Expired Certificates: 2
Sensitive Files: 7
Semgrep Findings: 4
Malformed Assets: 1
Errors: 0

Total Findings: 39
```

JSON normalized findings:

```bash
harvestguard scan ./target --json --quiet
```

Write JSON normalized findings to a file:

```bash
harvestguard scan ./target --json findings.json --quiet
```

Markdown report:

```bash
harvestguard scan ./target --markdown --exclude "vendor/*"
```

Write a professional Markdown evidence report:

```bash
harvestguard scan ./target --markdown report.md --exclude "vendor/*"
```

Scan a single local scan type with a bounded depth:

```bash
harvestguard scan ./target --type sensitive-data --max-depth 4 --json findings.json
```

Scan an AWS S3 bucket (uses AWS SDK default credentials):

```bash
harvestguard scan my-bucket --type s3 --prefix data/ --json --quiet
```

Scan a GCS bucket:

```bash
harvestguard scan my-bucket --type gcs --json --quiet
```

Scan an Azure Blob container:

```bash
harvestguard scan my-account/my-container --type azure --json --quiet
```

The Markdown report's sections are listed under
[Markdown output](#markdown-output).

## Demo Walkthrough

`demo/sample_target/` (GitHub issue [#18](https://github.com/serewicz/HarvestGuard/issues/18),
roadmap [HG-006](ROADMAP.md)) is a small, deterministic fixture so anyone can
see real HarvestGuard output without scanning real confidential data.

**All values in the fixture are synthetic and intentionally fake.** Do not
copy anything from it into a real `.env` file or substitute real credentials
or sensitive data into it. It exists only so the scanners have something
evidence-shaped to find, and its contents are documented in full in
[`demo/sample_target/sensitive/leaked_config.env`](../demo/sample_target/sensitive/leaked_config.env)'s
own header comment. It requires no credentials and no network access.

Run every local scanner against it:

```bash
harvestguard scan demo/sample_target --type all --summary
```

Expected output (files scanned and finding counts are deterministic; see
"What varies by host" below for the one platform-dependent field):

```text
HarvestGuard Scan Complete

Files scanned: 1

Findings

Certificates: 0
Private Keys: 1
Encrypted Keys: 0
SSH Keys: 0
PKCS#12: 0
Expired Certificates: 0
Sensitive Files: 1
Semgrep Findings: 0
Malformed Assets: 1
Errors: 1

Total Findings: 3
```

Three findings, one from each of three scanners:

- **Filesystem encryption evidence** (`--type filesystem`) — one finding for
  `leaked_config.env` with `Evidence: "Encryption status observed: <value>"`
  and a populated `Confidence` (`High`, `Medium`, or `Low`) plus
  `Confidence Rationale`. The exact `<value>` and confidence level depend on
  how encryption status was determined on your host (see "What varies by
  host" below) — this is expected, not a bug.
- **Cryptographic inventory evidence** (`--type crypto`) — one finding, asset
  type `Malformed PEM Private Key`, confidence `Low`. The fixture's PEM
  header (`-----BEGIN RSA PRIVATE KEY-----`) is real enough to be detected as
  a PEM block, but its body is plain fake text, not valid base64/DER, so
  parsing correctly fails. The `errors` field is non-empty and names the
  parse failure; `technical_metadata` (algorithm, key size, fingerprint,
  etc.) stays unset because parsing never succeeded. This is the intended,
  deterministic outcome for this fixture, not a scanner defect.
- **Sensitive-data categories** (`--type sensitive-data`) — one finding for
  `leaked_config.env` with `Categories: Email, Generic Secret, Private Key`.
  `Slack Token`, `GitHub Token`, and `AWS Access Key` do **not** appear: the
  fixture's Slack/GitHub/AWS-shaped lines are deliberately inert (they do not
  match those services' real credential formats), specifically so nothing
  committed to this repository can be mistaken for a live credential by
  GitHub push protection or any other scanner. Category names and counts are
  reported; the matched sensitive text itself is never included in output.

JSON (machine-readable, same normalized finding schema as
[NORMALIZED_FINDINGS.md](NORMALIZED_FINDINGS.md)):

```bash
harvestguard scan demo/sample_target --type all --json --quiet
```

Markdown (professional evidence report):

```bash
harvestguard scan demo/sample_target --type all --markdown --quiet
```

Both report exactly the same three findings as structured evidence records
(`Detailed Findings` in the Markdown report) — never the raw matched
sensitive value, the fixture's fake password, or its fake PEM body text, only
category names, counts, and evidence-layer fields such as confidence and
rule ID.

### What varies by host

Encryption status for a plain-text file with no matching file-level
signature falls back to volume-level encryption status, which is detected
differently per platform (FileVault on macOS, `lsblk`/similar on Linux) and
is not deterministic across environments — CI and your local machine may
report a different value or a different confidence level for that one field.
This is expected: `docs/TERMINOLOGY.md` documents this as evidence quality
that depends on what could be observed, not a claim that HarvestGuard can
always determine full-disk or volume encryption status the same way on every
supported platform. Every other field described above is fixed, since it
depends only on the fixture's unchanging content.

### Reading the results

Per [docs/TERMINOLOGY.md](TERMINOLOGY.md): everything the demo scan reports
above is **observed evidence** (encryption status, confidence, sensitive-data
categories, PEM parse errors) — direct scanner output about what the fixture
contains, not a business conclusion. The demo does not exercise the
dashboard's **Risk Score** or **HNDL Exposure** fields, which the same
terminology document marks as inferred heuristics (`Needs Validation`) and
which must never be read as measured facts. Nothing in this walkthrough is a
complete quantum-readiness assessment; it is a small, fixed evidence sample
for seeing real output.

## Exit Codes

- `0`: scan completed without scanner-level failures.
- `1`: at least one scanner failed, but other recoverable scanner results were
  returned. Suppress with `--no-fail-on-error` to exit `0` in this case.
- `2`: invalid CLI usage, such as an unknown `--type`, a negative `--max-depth`,
  a malformed Azure target, or a local path that does not exist.

Exit code `2` always means invalid input, and `1` always means a scan
execution failure, so automation can branch on the difference.

A scope you asked for is not a failure: a cloud `--prefix`, an `--exclude`
pattern, or a `--max-depth` boundary still exits `0`. Boundaries the filesystem
scanner knows about are reported as explicit findings instead; see
[Partial and limited scans](#partial-and-limited-scans) for which constraints
produce findings and which are reported only as scope.

## Scan Coverage and Partial Results

[SCAN_COVERAGE.md](SCAN_COVERAGE.md) documents what "complete" means for a
scan, `--max-depth` depth semantics and boundary findings, S3 pagination and
prefix behavior, GCS/Azure SDK iterator behavior, cloud provider/auth/API
failure handling, and how partial findings are preserved alongside a nonzero
exit code.

In short: when a scanner fails partway through, the findings it already
collected are still emitted, the failure is still reported, and the exit code is
still `1`. Reports and JSON that record scanner errors or limitation findings
must not be read as proof of complete coverage.

## Output Notes

### JSON output shape

`--json` emits a **JSON array of normalized findings** — one serialized
[NORMALIZED_FINDINGS.md](NORMALIZED_FINDINGS.md) record per array element, with
the schema unchanged. It is not a report envelope: there is no wrapper object,
and scan-level run metadata is not part of the array. Each element preserves
`schema_version`, `finding_id`, provenance fields (`scanner_name`,
`scanner_version`, `collection_method`, `collection_source`, `rule_id`,
`observed_at`, `repeatable`, `verification_rationale`), `evidence`,
`confidence`, `confidence_rationale`, `ownership_signals`, `unknowns`,
`limitations`, `errors`, and `technical_metadata`, serialized as plain JSON
objects, arrays, and scalars.

Scan-level scanner errors are deliberately outside that array. They are
reported through stderr, the exit code (see [Exit Codes](#exit-codes)), and the
Markdown report's *Errors and Warnings* section. Even when a scanner fails
partway through, `--json` stdout stays valid, machine-readable JSON containing
the findings collected before the failure; progress and failure messages never
mix into stdout.

With `--json PATH` the same JSON is written to `PATH`; with `--quiet` stdout
stays empty.

### Markdown output

`--markdown` emits a human-readable **evidence report** generated locally,
suitable for attaching to an issue, email, or advisory note. Its major sections
are stable:

- Executive Summary — evidence counts and scan context only
- Scan Information — scan time, report generator/version, target, duration,
  files scanned, excluded paths, coverage status
- Scanner Versions — scanner name, version, and finding count, listing every
  scanner the run invoked; a scanner that produced no findings, or that failed
  before producing any, still appears with its version and a count of `0`
- Scope — target, scan type, the scanners that actually ran for that scan
  type, and the scope constraints that bounded the run
- Findings Summary
- Finding Breakdown by Type
- Detailed Findings — per finding: location, asset type, the scanner name and
  version that produced it, when it was collected (`observed_at`), observed
  technical metadata, confidence, observed evidence, unknowns, limitations, and
  finding-level errors
- Errors and Warnings — scanner errors and coverage-limitation counts by type
- Known Limitations
- Appendix — normalized schema version and schema-preservation note

The report is evidence-only. It does not provide a risk score, HNDL exposure,
remediation advice or priority, business impact, ownership conclusions,
recommendations, compliance conclusions, quantum-readiness conclusions, or an
executive priority score. "Executive Summary" here means a concise summary of
what was observed, not an executive assessment. See
[TERMINOLOGY.md](TERMINOLOGY.md) for the evidence-versus-inference vocabulary.

The Scope section reports only the scanners the selected `--type` actually
ran — a `--type filesystem` or `--type s3` report never claims the other
scanners ran — together with the constraints those scanners honored
(`--max-depth` for `filesystem`/`sensitive-data`, `--prefix` for cloud scans,
and any `--exclude` patterns).

With `--markdown PATH` the report is written to `PATH`; with `--quiet` stdout
stays empty. Both `--json` and `--markdown` produce deterministic output apart
from genuinely volatile values (scan time, duration, and the host-dependent
fields noted above): findings are ordered by asset type, then location, then
finding ID, in both outputs.

PDF and HTML reports, hosted report sharing, and a JSON report envelope with
run metadata are not implemented; see [ROADMAP.md](ROADMAP.md).

### Partial and limited scans

A scope you configured (`--max-depth`, `--prefix`, `--exclude`) is not a
failure, but it does bound coverage. How each constraint is represented differs,
and the report distinguishes them:

- `--max-depth` produces explicit limitation findings **in the filesystem
  scanner only** (`--type filesystem`, and the filesystem pass of `--type
  all`). A directory past the configured depth is reported as a
  `max_depth_boundary` finding with a populated `limitations` field, alongside
  the `directory_traversal_error` and `skipped_special_file` findings the
  filesystem scanner records for entries it could not read or could not safely
  inspect.
- `--type sensitive-data` honors the same depth boundary — it inspects files in
  directories up to and including the configured depth — but does **not** emit
  boundary findings of its own: content below the boundary is skipped without a
  `max_depth_boundary` record. In a `--type all` run the filesystem pass still
  records the boundary directories. In a `--type sensitive-data` run the depth
  constraint is visible only in the report's *Scope* section, so read that
  section, not the absence of limitation findings, as the statement of how far
  a sensitive-data scan reached.
- `--prefix` and `--exclude` do **not** produce limitation findings.
  A cloud prefix narrows what the provider is asked to list, and an exclude
  pattern drops matching findings from output; in neither case does the scanner
  enumerate what it skipped. These constraints are visible in the report's
  *Scope* section (and `--exclude` in *Scan Information*), not as per-finding
  `limitations`.

Uninspected scope is never counted as a scanned file. When any scanner error or
limitation finding exists, the Markdown report states that coverage was not
complete and repeats that absence of a finding is not evidence that an asset was
inspected and found clean. When no error or limitation finding exists but a
scope constraint was configured, *Scan Information* reports coverage as
`Bounded by configured scan scope` rather than as unlimited; only a run with no
recorded constraint, error, or limitation reports `No limits recorded`. See
[SCAN_COVERAGE.md](SCAN_COVERAGE.md) for the full coverage semantics.

### Handling report output

Report generation is entirely local. HarvestGuard does not send findings or
reports to any external service, and it does not persist raw file contents.
Sensitive-data findings report category names and counts only — never the
matched values.

Even so, **treat generated reports as potentially sensitive artifacts**. File
paths, object and blob keys, bucket and container names, certificate subjects
and issuers, usernames, and other ownership signals can each be sensitive on
their own, and a report aggregates them. Store, transmit, and share
`findings.json` and `report.md` with the same care as the environment they
describe.

Provider credentials always come from each cloud SDK's own default credential
resolution. HarvestGuard does not manage, store, or emit credentials, and
provider error text is sanitized before it appears in output.
