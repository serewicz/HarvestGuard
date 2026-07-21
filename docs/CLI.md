# HarvestGuard CLI

HarvestGuard's unified CLI runs local scanners through the normalized finding
model. It does not add storage, dashboard functionality, risk scoring, or
executive reporting.

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
harvestguard scan <path> [--summary] [--json] [--markdown] [--quiet] [--exclude <pattern>]
```

The `scan` command runs current local scanners:

- local filesystem encryption evidence
- cryptographic asset inventory
- sensitive-data category detection
- local Semgrep crypto code analysis

Cloud scanners remain available through their scanner modules. The first CLI
command intentionally accepts a local path only.

## Examples

Default summary:

```bash
harvestguard scan ./target
```

Example output:

```text
Files scanned: 412

Certificates: 18
Private Keys: 5
Expired Certificates: 2
Sensitive Files: 7
Semgrep Findings: 4

Total Findings: 36
```

JSON normalized findings:

```bash
harvestguard scan ./target --json --quiet
```

Markdown report:

```bash
harvestguard scan ./target --markdown --exclude "vendor/*"
```

## Exit Codes

- `0`: scan completed without scanner-level failures.
- `1`: at least one scanner failed, but other recoverable scanner results were
  returned.
- `2`: invalid CLI usage, such as a path that does not exist.

## Output Notes

JSON output serializes normalized findings from
[NORMALIZED_FINDINGS.md](NORMALIZED_FINDINGS.md). Markdown output is a simple
evidence report suitable for copying into an issue or email. Neither output
adds executive priority, risk scoring, remediation cost, ownership, persistence,
or telemetry.
