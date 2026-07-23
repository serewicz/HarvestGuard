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

See [docs/PRODUCT_PRINCIPLES.md](docs/PRODUCT_PRINCIPLES.md) for the canonical
evidence, confidence, ownership-signal, and recommendation boundaries.

## Target Users & Use Cases

- **M&A, IP Lawyers, PE/VC Firms**  
  Quickly scan target company storage/cloud for encryption status, unencrypted sensitive data (IP, customer PII), and HNDL exposure. Many targets have poor inventory—this tool surfaces evidence early.

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
  when a file isn't itself a recognized encrypted format.
- **AWS S3, Google Cloud Storage, Azure Blob Storage** — per-object/blob
  encryption status via each provider's API (S3 `ServerSideEncryption`, GCS
  CMEK vs. Google-managed, Azure customer-managed encryption scope vs.
  Microsoft-managed).
- **Sensitive-data classifier** — flags files containing email addresses,
  SSNs, phone numbers, Luhn-validated payment card numbers, and
  credentials/secrets (AWS keys, private keys, GitHub/Slack tokens). Reports
  category and count only, never the matched values, so a scan result can't
  itself leak the sensitive data it found.
- **Crypto code analysis** — flags weak/legacy crypto library usage in
  source (MD5/SHA1, DES/3DES/RC4, ECB mode, sub-2048-bit RSA keys) via a
  small vendored Semgrep rule set, not Semgrep's hosted registry — local
  scans stay network-free.
- **Cryptographic asset inventory** — discovers local certificate and key
  material (PEM/DER X.509 certificates, PEM and OpenSSH keys, PKCS#12
  containers, and JKS header evidence) with algorithm, key size, issuer,
  subject, expiration, fingerprint, confidence, and parsing errors. See
  [docs/CRYPTO_INVENTORY.md](docs/CRYPTO_INVENTORY.md).
- **Unified CLI** — runs local and cloud scanners through the normalized
  finding model. Select a scan type (local filesystem, sensitive data, crypto
  inventory, code analysis, S3, GCS, or Azure Blob) and emit summary, JSON, or
  a professional Markdown report, with exit codes for automation. See
  [docs/CLI.md](docs/CLI.md).
- **Quantum risk scoring** — heuristic HNDL (Harvest-Now-Decrypt-Later)
  exposure scoring (High/Medium/Low) layered on top of encryption status.
- **Streamlit dashboard** — pie/bar charts and a results table per scan.

Not yet built: CBOM/PDF export and network-level crypto scanning
(TLS/cipher-suite detection). See
[docs/ROADMAP.md](docs/ROADMAP.md) for what's next and why, in rough
priority order.

## Quick Start (macOS / Linux / Windows)

### Prerequisites
- Python 3.10+ (`python3 --version`)
- Elevated rights (`sudo`) for deep local scans (or IAM for cloud)

### Installation

```bash
# Clone the repo
git clone https://github.com/serewicz/HarvestGuard.git
cd HarvestGuard

# Create and activate virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate    # On macOS/Linux
# venv\Scripts\activate    # On Windows

# Install dependencies
pip install -r requirements.txt     # or pip3 if needed

# Optional: install the unified CLI command
pip install -e .

# Run the dashboard
streamlit run main.py

# Or run a local CLI scan
harvestguard scan ./tests/fixtures/crypto_inventory

# Write a Markdown evidence report
harvestguard scan ./tests/fixtures/crypto_inventory --markdown report.md

# Run a single scan type and emit JSON (cloud scans use provider SDK credentials)
harvestguard scan ./tests/fixtures/crypto_inventory --type sensitive --json findings.json
harvestguard scan my-bucket --type s3 --prefix data/ --json --quiet
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
