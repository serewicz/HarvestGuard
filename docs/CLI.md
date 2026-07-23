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

## Output Notes

JSON output serializes normalized findings from
[NORMALIZED_FINDINGS.md](NORMALIZED_FINDINGS.md) without changing the schema.
Markdown output is a professional evidence report suitable for attaching to an
issue, email, or advisory note. It reports observed evidence only. It does not
add executive priority, risk scoring, remediation recommendations, ownership,
persistence, or telemetry.
