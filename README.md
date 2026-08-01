# HarvestGuard

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue)](https://www.python.org/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.38%2B-FF4B4B)](https://streamlit.io/)

**Open-source cryptographic evidence scanner for technology diligence and post-quantum migration planning.**

Built by [Timothy Serewicz](https://www.linkedin.com/in/serewicz/). Executive Technology Advisor & Fractional CTO.

## Why HarvestGuard?

HarvestGuard inventories cryptographic assets today, providing evidence organizations can use to assess future migration planning as cryptographic standards evolve.

In M&A due diligence, PE/VC portfolio reviews, acquisition planning, and enterprise technology decisions, teams need defensible evidence about encryption posture, sensitive-data placement, and cryptographic assets before they can assess modernization or migration work.

HarvestGuard gives teams **local, evidence-focused visibility** into implemented cryptographic posture across supported storage, cloud, source-code, and filesystem targets. Its outputs can contribute to a **Technology Due Diligence Evidence Package** for technology due diligence, executive assessment, acquisition review, integration planning, and cryptographic modernization planning.

HarvestGuard is additive to tools organizations may already use for security operations, cloud security, asset management, vulnerability management, and governance. It is not a replacement for broad vulnerability-management, CSPM, GRC, SIEM, or security-operations platforms.

## What HarvestGuard Does

HarvestGuard collects verifiable cryptographic evidence, communicates
confidence and unknowns, surfaces ownership signals, and frames the questions
organizations must answer. It does not prescribe the answer.

In practice, HarvestGuard helps reviewers:

- collect observable cryptographic evidence from supported targets;
- keep evidence, inference, uncertainty, and coverage limits visible;
- surface source-attributed ownership signals without assigning business
  accountability;
- use the resulting evidence in diligence, executive assessment, and
  post-quantum migration planning.

## What HarvestGuard Does Not Do

HarvestGuard does not:

- determine whether an organization is quantum-ready;
- assign business ownership or accountability;
- recommend products, vendors, architectures, or remediation plans;
- estimate migration or remediation costs;
- certify compliance;
- replace security assessments, legal review, architecture review, diligence
  professionals, or executive judgment.

Each scanner's detection surface is also deliberately narrow, and none of them
is exhaustive. **Absence of a finding is not proof of absence.** What every
scanner supports, what it can miss, its likely false positives and false
negatives, and how to read its `confidence` value are documented per scanner in
[docs/DETECTION_CHARACTERIZATION.md](docs/DETECTION_CHARACTERIZATION.md).

See [docs/PRODUCT_PRINCIPLES.md](docs/PRODUCT_PRINCIPLES.md) for the canonical
evidence, confidence, ownership-signal, and recommendation boundaries, and
[docs/CLAIMS_AUDIT.md](docs/CLAIMS_AUDIT.md) for how each claim below is
classified — implemented and tested, implemented with known limitations,
experimental / Needs Validation, planned, or out of scope.

## Target Users & Use Cases

- **M&A, IP Lawyers, PE/VC Firms**  
  Quickly scan target company storage/cloud for encryption status and sensitive-data categories (IP, customer PII), plus an inferred HNDL exposure bucket the dashboard marks as a heuristic needing validation. Many targets have poor inventory—this tool surfaces evidence early.

- **Deal Speed & Planning Evidence**  
  Pre-LOI or during DD, collect cryptographic evidence that can inform integration planning, modernization discussions, and follow-up advisory review.

- **Executive Assessment**  
  Give leaders a clearer evidence base for questions about cryptographic posture, long-lived data exposure, and future migration planning without claiming a complete quantum-readiness assessment.

- **Ease of Use**  
  Free/open-source, self-hosted, or simple web-based assessment → low friction entry.

- **Evidence Package** *(planned — see [docs/ROADMAP.md](docs/ROADMAP.md))*  
  Current JSON and Markdown reports are evidence outputs; future work may package these into a broader Technology Due Diligence Evidence Package for legal, advisory, and executive review.

Executive-facing reporting vision is documented in
[docs/EXECUTIVE_DELIVERABLES.md](docs/EXECUTIVE_DELIVERABLES.md). HarvestGuard
produces technical evidence first; executive deliverables are derived from that
evidence and must remain traceable back to it.

## Features (MVP)

- **Local filesystem** — real encryption detection: file-signature checks for
  common encrypted formats (OpenSSL, PGP/GPG, age, LUKS containers, encrypted
  ZIP), falling back to volume-level status (FileVault / LUKS / BitLocker)
  when a file isn't itself a recognized encrypted format. Local scans are
  bounded by `--max-depth`, which defaults to `3` — an ordinary scan is not
  unlimited recursion.
- **AWS S3, Google Cloud Storage, Azure Blob Storage** — per-object/blob
  encryption status as *reported by* each provider's API (S3
  `ServerSideEncryption`, GCS CMEK vs. Google-managed, Azure customer-managed
  encryption scope vs. Microsoft-managed). This is provider metadata, not
  independent proof of the underlying cryptographic implementation.
  Credentials come from each provider SDK's own default resolution;
  HarvestGuard never manages, prompts for, or stores them.
- **Sensitive-data classifier** — flags files containing email addresses,
  SSNs, phone numbers, Luhn-validated payment card numbers, and
  credentials/secrets (AWS keys, private keys, GitHub/Slack tokens). Reports
  category and count only, never the matched values, so a scan result can't
  itself leak the sensitive data it found.
- **Crypto code analysis** — flags weak/legacy crypto library usage in
  source (MD5/SHA1, DES/3DES/RC4, ECB mode, sub-2048-bit RSA keys) via a
  small vendored Semgrep rule set, not Semgrep's hosted registry — local
  scans stay network-free. **Source text only, and the current rules target
  Python source only**: no binary, bytecode, runtime, or network/TLS
  discovery, and equivalent weak-crypto usage in another language produces no
  finding today.
- **Cryptographic asset inventory** — discovers local certificate and key
  material (PEM/DER X.509 certificates, PEM and OpenSSH keys, PKCS#12
  containers, and JKS *header* evidence only) with algorithm, key size,
  issuer, subject, expiration, fingerprint, confidence, and parsing errors.
  Only files matching a candidate gate (recognized extension or crypto
  header) are parsed, and broader keystore/crypto-container coverage is not
  implemented. See [docs/CRYPTO_INVENTORY.md](docs/CRYPTO_INVENTORY.md).
- **Unified CLI** — runs local scanners through the normalized finding model
  with summary, JSON, and Markdown report output. `--json` emits an array of
  normalized findings; `--markdown` emits a local, evidence-only report
  covering scan context, scanner versions, detailed findings with confidence,
  unknowns, limitations, errors, and coverage caveats — no risk score, HNDL
  exposure, remediation advice, business impact, or quantum-readiness
  conclusion. Reports can contain sensitive identifiers (paths, object and
  bucket names, ownership signals), so handle the generated files
  accordingly. See [docs/CLI.md](docs/CLI.md).
- **HNDL exposure scoring** *(experimental — Needs Validation)* — a heuristic
  Harvest-Now-Decrypt-Later exposure bucket (High/Medium/Low) and 0–100 risk
  score inferred from encryption status and path signals. An inference and an
  ordering aid, not a measured fact, a probability, or a quantum-readiness
  verdict. It appears in the Streamlit dashboard only — never in CLI JSON or
  Markdown reports — and is labeled there as inferred and unvalidated. See
  [docs/TERMINOLOGY.md](docs/TERMINOLOGY.md).
- **Streamlit dashboard** — pie/bar charts and a results table per scan. Run
  with `streamlit run main.py` from the repository root: the dashboard is a
  separate operating path and is deliberately **not** part of the installed
  `harvestguard` CLI package.

Not yet built: CBOM/PDF export and network-level crypto scanning
(TLS/cipher-suite detection). See
[docs/ROADMAP.md](docs/ROADMAP.md) for what's next and why, in rough
priority order.

## Quick Start (macOS / Linux / Windows)

### Prerequisites
- **Python 3.10 or newer** (`python3 --version`). macOS ships Python 3.9.6 as
  `/usr/bin/python3`, which is **too old** — install a current Python (for
  example `brew install python@3.12`) and use that interpreter to create the
  virtual environment. Do not replace the system Python.
- Elevated rights (`sudo`) for deep local scans (or IAM for cloud)

### Install the CLI

One command from a clean virtual environment installs `harvestguard` and every
dependency it needs — `pyproject.toml` is authoritative, so there is no second
requirements step:

```bash
# Clone the repo
git clone https://github.com/serewicz/HarvestGuard.git
cd HarvestGuard

# Create and activate a clean virtual environment
python3 -m venv venv            # macOS: python3.12 -m venv venv
source venv/bin/activate        # On macOS/Linux
# venv\Scripts\activate         # On Windows

# Install the CLI and its dependencies
python -m pip install .

# Confirm it works -- from anywhere, not just this directory
harvestguard --version
cd ~ && harvestguard scan /path/to/target --type filesystem --summary
```

`pip` may print long runs of repeated download and "looking at multiple
versions of…" messages while resolving the Semgrep/OpenTelemetry dependency
graph. That backtracking is normal and can take several minutes on a cold
cache; a nonzero exit or a resolution error is a genuine failure.

Contributors who want their edits picked up without reinstalling use
`python -m pip install -e .` instead. See
[CONTRIBUTING.md](CONTRIBUTING.md) for the full dev setup.

### More CLI examples

```bash
harvestguard scan ./tests/fixtures/crypto_inventory

# Write a Markdown evidence report
harvestguard scan ./tests/fixtures/crypto_inventory --markdown report.md

# Run a single scan type, or a cloud scan (uses provider SDK default creds)
harvestguard scan ./tests/fixtures/crypto_inventory --type crypto --json findings.json
harvestguard scan my-bucket --type s3 --json --quiet
```

See [docs/CLI.md](docs/CLI.md) for all scan types, options, and exit codes.

### Running the dashboard

The Streamlit dashboard is a separate operating path: it runs from the
repository root and is not part of the installed CLI package, so it uses
`requirements.txt` rather than the packaging metadata.

```bash
pip install -r requirements.txt     # or pip3 if needed
streamlit run main.py
```

### Running in a container

For deal data you'd rather not run through a bare Python environment: a
non-root, distroless, read-only-filesystem-compatible image is provided.

```bash
docker build -t harvestguard .
docker run --rm -p 8501:8501 --read-only --tmpfs /tmp harvestguard
```

Local filesystem and PII/secrets scans need no network access at all —
verified in [SECURITY.md](SECURITY.md#container-network-posture). Cloud
scans need outbound access only to that provider's API; see
[deploy/iam/](deploy/iam/) for least-privilege, read-only IAM policy
templates scoped to exactly what each scanner calls.

## Version and Releases

HarvestGuard is pre-1.0. `harvestguard --version` prints the installed version,
and every Markdown report records it in its *Scan Information* table, so an
evidence artifact identifies the release that produced it. Release notes are in
[CHANGELOG.md](CHANGELOG.md); version identity, reproducibility expectations,
SBOM/signing/provenance status, and the release procedure are in
[docs/RELEASE.md](docs/RELEASE.md).

## Contributing

Contributions welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) for dev setup,
test/lint commands, good first-contribution areas, and the contribution
workflow. Non-trivial changes should start from a GitHub Issue; roadmap IDs are
planning references, not substitutes for issue scope. Product direction lives
in [docs/ROADMAP.md](docs/ROADMAP.md),
[docs/PRODUCT_PRINCIPLES.md](docs/PRODUCT_PRINCIPLES.md), and
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Security

Found a vulnerability? Please don't open a public issue — see
[SECURITY.md](SECURITY.md) for how to report it privately.
