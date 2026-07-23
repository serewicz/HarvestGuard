# HarvestGuard CLI

HarvestGuard's unified CLI runs the existing local and cloud scanners through
the normalized finding model. It does not add new scanners, storage, dashboard
functionality, risk scoring, or executive reporting.

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
harvestguard scan <target> [--type <scan-type>] [--max-depth N] [--prefix PREFIX] \
  [--summary] [--json [PATH]] [--markdown [PATH]] [--quiet] [--exclude <pattern>]
```

`--type` selects which scanner runs (default: `all`):

| Scan type | Target | Scanner |
| --- | --- | --- |
| `all` (default) | local path | every local scanner below |
| `filesystem` | local path | local filesystem encryption evidence |
| `crypto-inventory` | local path | cryptographic asset inventory |
| `sensitive-data` | local path | sensitive-data category detection |
| `code-analysis` | local path | local Semgrep crypto code analysis |
| `s3` | bucket name | AWS S3 object encryption status |
| `gcs` | bucket name | GCS object encryption status |
| `azure-blob` | `account/container` | Azure Blob encryption status |

For local scan types `TARGET` is a file or directory path; for cloud scan
types it is a bucket or container reference. Azure Blob targets use the form
`account/container`; the CLI assembles the
`https://<account>.blob.core.windows.net` endpoint for you.

`--max-depth` limits directory recursion for the `filesystem` and
`sensitive-data` scans (default `3`); it is ignored by scan types that do not
walk directories. `--prefix` filters objects/blobs for the cloud scan types
and is ignored for local scans.

Cloud scans use the provider SDK credential defaults (for example the AWS,
Google Cloud, or Azure credential chains). No credentials are read from CLI
arguments, and the CLI never enables telemetry.

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

Run only the sensitive-data scanner, limiting recursion depth:

```bash
harvestguard scan ./target --type sensitive-data --max-depth 2 --json
```

Scan an S3 bucket (using the AWS SDK credential chain), filtered by prefix:

```bash
harvestguard scan my-bucket --type s3 --prefix data/ --json findings.json
```

Scan a GCS bucket:

```bash
harvestguard scan my-bucket --type gcs --json
```

Scan an Azure Blob container:

```bash
harvestguard scan mystorageaccount/mycontainer --type azure-blob --json
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
- `1`: a scanner failed during execution (for example a cloud scanner raised an
  error). Any recoverable results are still emitted.
- `2`: invalid CLI usage, such as an unknown `--type`, a negative
  `--max-depth`, a local path that does not exist, a malformed Azure Blob
  target, or an output file that could not be written.

## Output Notes

JSON output serializes normalized findings from
[NORMALIZED_FINDINGS.md](NORMALIZED_FINDINGS.md) without changing the schema.
Markdown output is a professional evidence report suitable for attaching to an
issue, email, or advisory note. It reports observed evidence only. It does not
add executive priority, risk scoring, remediation recommendations, ownership,
persistence, or telemetry.
