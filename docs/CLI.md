# HarvestGuard CLI

HarvestGuard's unified CLI runs the same scanners as the dashboard through the
normalized finding model. It does not add storage, dashboard functionality,
risk scoring, or executive reporting.

## Installation

### Requirements

**Python 3.10 or newer.** Check before anything else:

```bash
python3 --version
```

On macOS the system interpreter (`/usr/bin/python3`) is **Python 3.9.6, which is
too old** — HarvestGuard will not install or run on it, and upgrading the system
Python is neither necessary nor recommended. Install a current Python (for
example `brew install python@3.12`, or a python.org installer) and build the
virtual environment from that interpreter instead:

```bash
python3.12 -m venv venv          # macOS: not /usr/bin/python3
source venv/bin/activate
python -m pip install .
```

### Install the CLI

From a clean virtual environment, in a checkout of this repository, one command
is enough:

```bash
git clone https://github.com/serewicz/HarvestGuard.git
cd HarvestGuard

python3 -m venv venv
source venv/bin/activate         # venv\Scripts\activate on Windows

python -m pip install .
```

That installs the `harvestguard` command **and everything it needs**.
`pyproject.toml` declares the CLI's runtime dependencies, so there is no second
`pip install -r requirements.txt` step: `requirements.txt` is repository-root
convenience for running the Streamlit dashboard from a checkout, and
`requirements-dev.txt` is for contributors running the tests and linter. A
normal user needs neither.

Confirm the install:

```bash
harvestguard --version           # e.g. "harvestguard 0.1.0"
```

Contributors who want their edits to take effect without reinstalling use an
editable install instead — same dependencies, same command:

```bash
python -m pip install -e .
```

### What to expect during installation

`pip` may print long runs of repeated "Downloading …" / "INFO: pip is looking at
multiple versions of …" messages while it resolves the Semgrep and
OpenTelemetry dependency graph. That backtracking is **normal**, can take
several minutes on a cold cache, and is not a hang. What is *not* normal is pip
finishing with an error, a `ResolutionImpossible`, or a nonzero exit code —
those are real failures, and the install did not succeed no matter how much
output scrolled past first.

### Running the CLI

Once installed, `harvestguard` works from **any** directory, not just the
repository root:

```bash
cd ~
harvestguard scan /path/to/target --type filesystem --summary
```

The install covers the CLI and the scanners only. The Streamlit dashboard is
run from the repository root with `streamlit run main.py` (after
`pip install -r requirements.txt`) and is deliberately not part of the installed
package.

Without installing the console script at all, run the same CLI as a module from
the repository root:

```bash
python -m harvestguard scan ./target
```

Both paths run the same code. To confirm either one works before you trust its
output, see [Validating an install end to end](#validating-an-install-end-to-end).

## Usage

```bash
harvestguard [--version]
harvestguard scan <target> [--type <type>] [--max-depth N] [--prefix <prefix>] \
    [--summary] [--json [PATH]] [--markdown [PATH]] [--quiet] \
    [--exclude <pattern>] [--fail-on-error | --no-fail-on-error]
```

`<target>` is a local file or directory path for local scan types, a bucket
name for `s3`/`gcs`, or `account-name/container-name` for `azure`.

`--version` (or `-V`) prints the HarvestGuard version and exits — the same
version a Markdown report records in its *Scan Information* table, so an
artifact can be traced back to the release that produced it. `--json` output
carries no version field: it stays a bare finding array. See
[docs/RELEASE.md](RELEASE.md#identifying-the-version-that-produced-an-artifact).

### Scan types

`--type` selects which scanner runs (default `all`):

| `--type`         | Target                          | Scanner                                     |
| ---------------- | ------------------------------- | ------------------------------------------- |
| `all` (default)  | local path                      | every local scanner below                   |
| `filesystem`     | local path                      | local filesystem encryption evidence        |
| `crypto`         | local path                      | cryptographic asset inventory               |
| `sensitive-data` | local path                      | sensitive-data category detection           |
| `code`           | local path                      | local Semgrep crypto code analysis (Python source only) |
| `s3`             | bucket name                     | AWS S3 object encryption status             |
| `gcs`            | bucket name                     | GCS object encryption status                |
| `azure`          | `account-name/container-name`   | Azure Blob encryption status                |

`--max-depth` bounds directory recursion for `filesystem` and `sensitive-data`
scans (and the `all` bundle), and **defaults to `3`** — a scan run without an
explicit `--max-depth` is bounded configured scope from the start, not unlimited
recursion, and the report's *Scope* section records the bound that applied.
`--prefix` restricts cloud scans to a key or blob prefix. Each option is ignored
by scan types it does not apply to.

`--type code` matches source **text** only, and the vendored rule set
(`code_analysis/rules/crypto.yaml`) currently declares `languages: [python]`,
so equivalent weak-crypto usage in another language produces no finding. There
is no binary, bytecode, runtime, or network/TLS discovery. See
[DETECTION_CHARACTERIZATION.md](DETECTION_CHARACTERIZATION.md).

#### OpenSSL encrypted-file evidence (HG-030)

A file whose leading bytes are `Salted__` — the header `openssl enc -salt`
writes — is cryptographic evidence, and the crypto-inventory scanner owns it:
a `--type crypto` (or `--type all`) scan reports it as asset type
`Encrypted File`, `rule_id: encrypted_file:openssl`, confidence `High`, with
evidence text limited to the observed signature (never a claim about
decryptability, password/key/algorithm, or encryption strength). Detection is
based on the file's actual content, evaluated before any extension-based
parsing, so a `Salted__` file saved with a misleading extension (e.g.
`secret.p12` or `secret.der`) is still reported as `Encrypted File`, not
routed into PKCS#12/DER parsing and reported as malformed.

The filesystem scanner also recognizes this same signature independently, as
it always has (`--type filesystem`, `rule_id: file_signature:file_level_openssl`,
asset type `file`, `Encryption: File-level (OpenSSL)`) — that behavior is
unchanged. When both scanners run together (`--type all`), the same file is
never reported twice: the crypto-inventory finding is the one that survives
in the combined output, and the filesystem scanner's record for that same
file is excluded. This dedup is deterministic and does not depend on which
scanner happened to run first.

`Files scanned` keeps its existing meaning (inspected regular files, from the
filesystem scanner's own activity — see below) and correctly reads `0` for a
pure `--type crypto` run, since the crypto-inventory scanner is not the
filesystem scanner. That is expected, not a bug. A separate, additive
`Crypto files inspected` line (console: `Crypto files inspected: N`;
Markdown: a `Crypto Files Inspected` row in *Scan Information*) reports how
many files the crypto-inventory scanner actually visited and opened —
including files that matched no recognized shape and produced no finding —
whenever that scanner ran. It is never arithmetically merged, reconciled, or
deduplicated against `Files scanned`, even when both scanners inspect the
same files under `--type all`.

As with every crypto-inventory finding, the absence of an `Encrypted File`
finding is not proof no encrypted files exist: the scanner's other
candidate-gate limitations (see
[DETECTION_CHARACTERIZATION.md](DETECTION_CHARACTERIZATION.md#local-cryptographic-asset-inventory))
still apply to every signature this issue did not add — only the exact
`Salted__` OpenSSL header is recognized here, not GPG/PGP, age, LUKS,
encrypted ZIP, or any other encrypted-container format.

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

Record Categories

Aggregate filesystem context records: 3
Per-file filesystem evidence records: 6
Coverage limitation records: 0
Skipped or inaccessible entry records: 2
Cryptographic inventory records: 18
Sensitive-data records: 7
Code-analysis records: 4
Cloud storage records: 0

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

Material evidence records: 35
Total normalized records: 40
Findings with finding-level errors: 0
Scanner execution errors: 0
```

`Files scanned` counts inspected regular files, not records: an ordinary
readable file with no file-level evidence and no file-specific failure
produces no record of its own, and is represented by its mount's aggregate
`filesystem_context` record instead (one per mount actually scanned) rather
than one record per file. `Total normalized records` is named for exactly
what it counts — it is not a count of distinct material findings, which is
what `Material evidence records` states instead. See [What Each Scanner Can
Miss](#what-each-scanner-can-miss) and
[DETECTION_CHARACTERIZATION.md](DETECTION_CHARACTERIZATION.md) for what each
record category means.

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

Record Categories

Aggregate filesystem context records: 1
Per-file filesystem evidence records: 0
Coverage limitation records: 0
Skipped or inaccessible entry records: 0
Cryptographic inventory records: 1
Sensitive-data records: 1
Code-analysis records: 0
Cloud storage records: 0

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

Material evidence records: 2
Total normalized records: 3
Findings with finding-level errors: 1
Scanner execution errors: 0
```

Three normalized records, one from each of three scanners:

- **Filesystem context** (`--type filesystem`) — `leaked_config.env` is an
  ordinary file with no file-level encrypted-format signature and no
  file-specific failure, so it produces no record of its own. It is
  represented instead by one aggregate `filesystem_context` finding for the
  demo fixture's mount, with `Evidence` starting `"Volume-level encryption
  status observed for mount <path>: <value>"` (or, if the status could not be
  determined on your host, `"...could not be determined for mount
  <path>..."`), a populated `Confidence` (`Medium` or `Low`) plus
  `Confidence Rationale`, and `technical_metadata["Files Represented By This
  Context"] == 1`. The exact `<value>` and confidence level depend on how
  encryption status was determined on your host (see "What varies by host"
  below) — this is expected, not a bug. See [Design: Aggregate Filesystem
  Context](DETECTION_CHARACTERIZATION.md#local-filesystem-encryption-evidence)
  for why ordinary files are represented this way.
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

Encryption status for an ordinary file with no matching file-level signature
falls back to volume-level encryption status, recorded on the mount's
aggregate `filesystem_context` finding rather than a per-file one. That
status is detected differently per platform (FileVault on macOS,
`lsblk`/similar on Linux) and is not deterministic across environments — CI
and your local machine may report a different value or a different
confidence level for that one field.
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

## Validating an Install End to End

Everything below is exercised automatically by
`tests/test_end_to_end_validation.py` (roadmap HG-008), which runs the same
documented commands: a real `pip install .` and `pip install -e .` of this
repository into a throwaway virtual environment whose installed `harvestguard`
console script is then invoked from outside the checkout, the demo fixture, a
representative non-demo target built at runtime, and S3/GCS/Azure scans faked at
the provider SDK boundary only. Run
`pytest -v tests/test_end_to_end_validation.py` to check an environment, or walk
the steps yourself:

1. **Install and invoke.** `pip install -e .` then `harvestguard scan
   demo/sample_target --type all --summary` (or `python -m harvestguard scan
   demo/sample_target --type all --summary` without installing). Expect exit
   code `0` and the summary shown in [Demo Walkthrough](#demo-walkthrough).
   Progress lines (`Running filesystem scanner...`) go to stderr, so stdout is
   safe to pipe.
2. **Demo artifacts.** Add `--json findings.json` and `--markdown report.md`.
   Expect three findings in the JSON array and every section listed under
   [Markdown output](#markdown-output) in the report.
3. **A representative target.** Point the same commands at a real repository or
   directory (`harvestguard scan /path/to/repo --type all --json findings.json`).
   Nothing about the output shape depends on the demo fixture. Individual scan
   types are worth running on their own too: `--type crypto` for certificate and
   key inventory, `--type code` for Semgrep crypto findings, `--type
   sensitive-data` for category counts.
4. **Cloud targets.** `--type s3`, `--type gcs`, and `--type azure` need working
   provider credentials from that SDK's own default chain (HarvestGuard never
   prompts for or stores them). A successful cloud scan with no `--prefix`
   reports `Coverage: No limits recorded`.
5. **Read the coverage status.** Use the table below to tell a complete scan
   from a limited, partial, or failed one. This is the only thing you need in
   order to interpret an artifact — no source-code reading required.

Two further test modules cover the installation itself rather than the scan
behavior. `tests/test_clean_install.py` performs both documented installs into a
virtual environment created **without** `--system-site-packages` and installed
**without** `--no-deps`, then runs `--version`, a filesystem summary scan, JSON,
and Markdown from outside the checkout — so a dependency that is only present
because the host happened to have it cannot make those checks pass. They
download real packages; set `HARVESTGUARD_SKIP_CLEAN_INSTALL_TESTS=1` to skip
them when working offline. `tests/test_packaging_dependencies.py` is the offline
counterpart: it fails if a packaged module imports something `pyproject.toml`
does not declare, or if `pyproject.toml` and `requirements.txt` drift apart.

### Reading coverage from an artifact

| What happened | Exit code | Markdown `Coverage` row | Other evidence in the artifact |
| --- | --- | --- | --- |
| **Complete** — the configured scope was processed, nothing was skipped | `0` | `No limits recorded` | *Errors and Warnings* says no scanner errors, finding-level errors, or limitations were reported |
| **Limited** — you configured `--prefix`, `--exclude`, or a depth bound the scanner does not enumerate | `0` | `Bounded by configured scan scope` | *Scope* lists each configured constraint; `--exclude` also appears in *Scan Information* |
| **Limited with enumerated boundaries** — a filesystem `--max-depth` boundary, unreadable directory, or skipped special file | `0` | `Not complete` | "Coverage was not complete: … N finding(s) with recorded limitations", a `max_depth_boundary`/`directory_traversal_error`/`skipped_special_file` count, and **no** `Scanner error:` line |
| **Partial** — findings were collected, then a provider, credential, or traversal failure stopped the scan | `1` | `Not complete` | The collected findings are still listed in *Detailed Findings*, and a `- Scanner error:` line names the failure |
| **Failed** — a scanner errored before producing anything | `1` | `Not complete` | A `- Scanner error:` line, plus a *Scanner Versions* row for that scanner with a finding count of `0`, so it is never silently dropped |

A `--type code` execution failure is the one case this table does not cover: it
exits `0`, reports `Coverage` as if nothing constrained the scan, and shows a
code-analysis *Scanner Versions* row with `0` findings that is indistinguishable
from a genuinely clean result. Its diagnostic appears on stderr only. See
[Exit Codes](#exit-codes).

A per-finding `errors` entry is a different thing from a scanner failure: it
records an observation that partly failed (an unparsable PEM, a JKS entry the
current scanner cannot read, an encrypted key whose metadata needs a
passphrase). The scan still exits `0`, and the `Coverage` row does not change;
the fact is reported as "Finding-level errors are listed in Detailed Findings"
in *Errors and Warnings*, with the reason in that finding's `Errors` column (and
its `errors` array in JSON). Read those two places, not just the `Coverage` row,
before treating a scan as clean.

With `--json`, the same distinctions come from the exit code, the stderr
messages, and each finding's `limitations` and `errors` arrays; scan-level
scanner errors are deliberately not part of the JSON array (see
[JSON output shape](#json-output-shape)).

## Exit Codes

- `0`: scan completed without scanner-level failures.
- `1`: at least one scanner failed, but other recoverable scanner results were
  returned. Suppress with `--no-fail-on-error` to exit `0` in this case.
- `2`: invalid CLI usage, such as an unknown `--type`, a negative `--max-depth`,
  a malformed Azure target, or a local path that does not exist.

Exit code `2` always means invalid input, and `1` always means a scan
execution failure, so automation can branch on the difference.

**One documented exception to `1`:** a `--type code` *execution* failure —
`semgrep` not installed, timed out, exiting non-zero, or emitting output that
cannot be parsed — writes its diagnostic to stderr and returns an empty result
instead of raising. It is therefore not recorded as a scanner error, and the run
exits `0` with no findings, unlike an equivalent S3/GCS/Azure failure. Read
stderr, not just the exit code, before treating an empty code-analysis result as
"the source was analyzed and nothing matched". This asymmetry is characterized
in [DETECTION_CHARACTERIZATION.md](DETECTION_CHARACTERIZATION.md#source-code-crypto-analysis)
and tracked as a separate scanner-error-propagation concern in
[CLAIMS_AUDIT.md](CLAIMS_AUDIT.md#identified-for-a-separate-issue); HG-010 did
not change the behavior.

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

## What Each Scanner Can Miss

Coverage semantics answer "was the configured scope processed?"
[DETECTION_CHARACTERIZATION.md](DETECTION_CHARACTERIZATION.md) answers the
other half: for each scan type above, what evidence that scanner actually
supports, what formats and inputs it does not recognize, its likely
false-positive and false-negative conditions, what its `confidence` value
means, and when a clean result must not be read as proof that no cryptographic
asset, sensitive data, weak crypto usage, or encryption gap exists. Read it
before treating any `--type` result as complete.

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
- Scan Information — scan time, the HarvestGuard version that produced the
  report, report generator/version, target, duration, files scanned, excluded
  paths, coverage status
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
