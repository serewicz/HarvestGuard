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
  Quickly scan target company storage/clusters/cloud for encryption status, weak algorithms, unencrypted sensitive data (IP, customer PII), and HNDL exposure. Many targets have poor inventory—this tool surfaces risks early.

- **Deal Speed & Risk Mitigation**  
  Pre-LOI or during DD, identify crypto debt that could delay integration or create liabilities (breaches, compliance failures post-quantum).

- **Valuation Impact**  
  Quantify remediation costs/risks (e.g., “This $X dataset requires $Y migration effort”). Ties directly into board-level technology governance expectations.

- **Ease of Use**  
  Free/open-source, self-hosted, or simple web-based assessment → low friction entry.

- **Audit Trail**  
  Generates CBOMs and professional reports for legal/IP teams.

## Features (MVP)

- Multi-environment scanning (local filesystems, storage clusters, AWS S3 — expandable)
- Encryption detection & strength assessment
- Ownership, access patterns, and usage insights
- Quantum risk analysis (HNDL exposure, risk scoring)
- Visualizations (risk heatmaps, tables, basic flame graphs)
- Exports: CBOM JSON, PDF reports
- Streamlit web dashboard + CLI support

**Future Roadmap**: Microservices architecture, Prometheus + Grafana monitoring, advanced AI recommendations, hardware partnerships for crypto-agility.

## Quick Start

### Prerequisites
- Python 3.10+
- Elevated rights (`sudo`) for deep local filesystem scans (or appropriate IAM roles for cloud)
- (Optional but recommended) Docker for easy deployment

### Installation

```bash
git clone https://github.com/yourusername/harvestguard.git
cd harvestguard
pip install -r requirements.txt
streamlit run main.py
