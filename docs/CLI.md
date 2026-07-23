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

- `0`: scan completed without scanner-level failures.
- `1`: at least one scanner failed, but other recoverable scanner results were
  returned. Suppress with `--no-fail-on-error` to exit `0` in this case.
- `2`: invalid CLI usage, such as an unknown `--type`, a negative `--max-depth`,
  a malformed Azure target, or a local path that does not exist.

Exit code `2` always means invalid input, and `1` always means a scan
execution failure, so automation can branch on the difference.

## Output Notes

JSON output serializes normalized findings from
[NORMALIZED_FINDINGS.md](NORMALIZED_FINDINGS.md) without changing the schema.
Markdown output is a professional evidence report suitable for attaching to an
issue, email, or advisory note. It reports observed evidence only. It does not
add executive priority, risk scoring, remediation recommendations, ownership,
persistence, or telemetry.
