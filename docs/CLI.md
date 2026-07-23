# HarvestGuard CLI

HarvestGuard's unified CLI runs the same scanners as the Streamlit dashboard
through the normalized finding model, so scans can be repeated in diligence,
CI, and reporting workflows without operating the dashboard. It does not add
storage, dashboard functionality, risk scoring, or executive reporting.

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
harvestguard scan <target> [--type <type>] [--prefix <prefix>] [--max-depth <n>] \
    [--summary] [--json [PATH]] [--markdown [PATH]] [--quiet] [--exclude <pattern>]
```

`<target>` is a local file or directory for local scan types, or a
bucket/container identifier for cloud scan types (Azure uses the form
`account/container`).

### Scan types (`--type`)

The default is `all`, which runs every local scanner together (the original CLI
behavior). A single scan type can be selected instead:

| `--type`     | Scanner                                | Target             |
| ------------ | -------------------------------------- | ------------------ |
| `all`        | all local scanners (default)           | local path         |
| `filesystem` | local filesystem encryption evidence   | local path         |
| `crypto`     | cryptographic asset inventory          | local path         |
| `sensitive`  | sensitive-data category detection      | local path         |
| `code`       | local Semgrep crypto code analysis     | local path         |
| `s3`         | AWS S3 object encryption status        | bucket name        |
| `gcs`        | Google Cloud Storage encryption status | bucket name        |
| `azure`      | Azure Blob container encryption status | `account/container`|

### Options that apply to some scan types

- `--prefix` limits a cloud scan to objects/blobs under a key prefix; it applies
  to `s3`, `gcs`, and `azure` only.
- `--max-depth` limits directory recursion for local filesystem and
  sensitive-data scans; it applies to local scan types only.

Supplying `--prefix` with a local scan type, or `--max-depth` with a cloud scan
type, fails with a usage error and exit code `2`.

### Cloud credentials

Cloud scans use each provider SDK's default credential resolution (AWS, Google
Cloud, and Azure). The CLI does not accept or store credentials. See
[deploy/iam/](../deploy/iam/) for least-privilege, read-only policy templates.

## Examples

Default summary:

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

Single local scan type (sensitive data only):

```bash
harvestguard scan ./target --type sensitive --json findings.json --quiet
```

Cloud scans (credentials come from the provider SDK's default resolution):

```bash
# AWS S3 bucket, limited to a key prefix
harvestguard scan my-bucket --type s3 --prefix data/ --json --quiet

# Google Cloud Storage bucket
harvestguard scan my-bucket --type gcs --json --quiet

# Azure Blob container (target is 'account/container')
harvestguard scan mystorageaccount/mycontainer --type azure --json --quiet
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
  returned.
- `2`: invalid CLI usage, such as an unknown scan type, a local path that does
  not exist, a malformed Azure target, an option applied to a scan type it does
  not support, or an output file that could not be written.

## Output Notes

JSON output serializes normalized findings from
[NORMALIZED_FINDINGS.md](NORMALIZED_FINDINGS.md) without changing the schema.
Markdown output is a professional evidence report suitable for attaching to an
issue, email, or advisory note. It reports observed evidence only. It does not
add executive priority, risk scoring, remediation recommendations, ownership,
persistence, or telemetry.
