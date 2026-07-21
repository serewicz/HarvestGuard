# HarvestGuard

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue)](https://www.python.org/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.38%2B-FF4B4B)](https://streamlit.io/)

**Open-source cryptographic inventory and quantum risk scanner for enterprise resilience.**

Built by [Timothy Serewicz](https://www.linkedin.com/in/serewicz/). Executive Technology Advisor & Fractional CTO.

## Why HarvestGuard?

In M&A due diligence, PE/VC portfolio reviews, and enterprise technology decisions, undetected cryptographic weaknesses and **Harvest Now, Decrypt Later (HNDL)** risks can create massive liabilities, delay integrations, and destroy deal value.

HarvestGuard gives teams **fast, actionable visibility** into encryption posture across storage, clusters, and cloud environments—without weeks of manual effort or expensive enterprise tools.

## Target Users & Use Cases

- **M&A, IP Lawyers, PE/VC Firms**  
  Quickly scan target company storage/cloud for encryption status, unencrypted sensitive data (IP, customer PII), and HNDL exposure. Many targets have poor inventory—this tool surfaces risks early.

- **Deal Speed & Risk Mitigation**  
  Pre-LOI or during DD, identify crypto debt that could delay integration or create liabilities (breaches, compliance failures post-quantum).

- **Valuation Impact**  
  Quantify remediation costs/risks (e.g., “This $X dataset requires $Y migration effort”). Ties directly into board-level technology governance expectations.

- **Ease of Use**  
  Free/open-source, self-hosted, or simple web-based assessment → low friction entry.

- **Audit Trail** *(planned — see [docs/ROADMAP.md](docs/ROADMAP.md))*  
  CBOM and professional-report export for legal/IP teams.

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
- **Quantum risk scoring** — heuristic HNDL (Harvest-Now-Decrypt-Later)
  exposure scoring (High/Medium/Low) layered on top of encryption status.
- **Streamlit dashboard** — pie/bar charts and a results table per scan.

Not yet built: CBOM/PDF export, a CLI (today it's `streamlit run main.py`
only), and network-level crypto scanning (TLS/cipher-suite detection). See
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

# Run the dashboard
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

## Contributing

Contributions welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) for dev setup,
test/lint commands, good first-contribution areas, and the contribution
workflow. Product direction lives in [docs/ROADMAP.md](docs/ROADMAP.md),
[docs/PRODUCT_PRINCIPLES.md](docs/PRODUCT_PRINCIPLES.md), and
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Security

Found a vulnerability? Please don't open a public issue — see
[SECURITY.md](SECURITY.md) for how to report it privately.
