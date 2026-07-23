# HarvestGuard CLI

HarvestGuard's unified CLI runs the same scanners as the Streamlit dashboard
through the normalized finding model, from the command line, for repeatable
diligence and CI workflows. It does not add storage, dashboard functionality,
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
harvestguard scan <target> [--type <type>] [--summary] [--json [PATH]] [--markdown [PATH]]
                           [--max-depth N] [--prefix <prefix>] [--fail-on <policy>]
                           [--quiet] [--exclude <pattern>]
```

The `--type` option selects which scanner to run (default `all`):

| `--type`           | Target             | Scanner                              |
| ------------------ | ------------------ | ------------------------------------ |
| `all` *(default)*  | local path         | all local scanners below             |
| `filesystem`       | local path         | local filesystem encryption evidence |
| `crypto-inventory` | local path         | cryptographic asset inventory        |
| `sensitive-data`   | local path         | sensitive-data category detection    |
| `code-analysis`    | local path         | local Semgrep crypto code analysis   |
| `s3`               | bucket name        | AWS S3 object encryption status      |
| `gcs`              | bucket name        | GCS object encryption status         |
| `azure-blob`       | `account/container`| Azure Blob encryption status         |

Cloud scans (`s3`, `gcs`, `azure-blob`) use each provider SDK's default
credential resolution — the same credentials the dashboard uses. No credentials
are read from CLI arguments.

`--max-depth` bounds directory recursion for the depth-aware local scans
(`all`, `filesystem`, `sensitive-data`). `--prefix` restricts a cloud scan to
objects/blobs under a key prefix. The two options are mutually exclusive with
each other's scan types and are rejected with a clear message when combined
with an incompatible `--type`.

## Examples

Default summary (all local scanners):

```bash
harvestguard scan ./target
```

Run a single local scan type:

```bash
harvestguard scan ./target --type sensitive-data --json --quiet
```

Scan a cloud bucket/container (uses provider default credentials):

```bash
harvestguard scan my-bucket --type s3 --prefix reports/ --json findings.json
harvestguard scan my-bucket --type gcs --json --quiet
harvestguard scan mystorageacct/mycontainer --type azure-blob --json --quiet
```

Bound local recursion depth:

```bash
harvestguard scan ./target --type filesystem --max-depth 1 --summary
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

The Markdown report includes:

- Executive Summary
- Scan Information
- Scanner Versions
- Scope
- Findings Summary
- Finding Breakdown by Type
- Detailed Findings
- Errors and Warnings
- Known Limitations
- Appendix

## Exit Codes

Exit codes distinguish invalid input from scan-execution problems so callers can
automate follow-up:

- `0`: scan completed without triggering the failure policy.
- `1`: the `--fail-on` policy was triggered (see below).
- `2`: invalid CLI usage — unknown arguments, a local path that does not exist,
  a malformed `azure-blob` target, an incompatible option/`--type` combination,
  or an output file that could not be written.

The `--fail-on` policy controls when a completed scan exits `1`:

- `error` *(default)*: exit `1` if any scanner failed, otherwise `0`.
- `findings`: exit `1` if any findings were emitted or any scanner failed.
- `never`: always exit `0` once the input is valid (invalid input still `2`).

A single scanner failing does not abort the run: remaining scanners still
execute and their findings are reported, with the failure recorded as a scanner
warning in the summary and Markdown report.

## Output Notes

JSON output serializes normalized findings from
[NORMALIZED_FINDINGS.md](NORMALIZED_FINDINGS.md) without changing the schema.
Markdown output is a professional evidence report suitable for attaching to an
issue, email, or advisory note. It reports observed evidence only. It does not
add executive priority, risk scoring, remediation recommendations, ownership,
persistence, or telemetry.
