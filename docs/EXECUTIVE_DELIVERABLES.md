# Executive Deliverables

## Purpose

HarvestGuard collects cryptographic evidence that supports executive
technology decisions.

Technical evidence should be reusable across multiple reporting formats. The
software produces observed evidence first; executive reports are derived from
that evidence and must remain traceable back to it.

This document describes HarvestGuard's executive-facing reporting vision. It
does not claim that every deliverable described here is fully implemented
today.

## Primary Deliverable

### Technology Due Diligence Evidence Package

The Technology Due Diligence Evidence Package is HarvestGuard's flagship
executive deliverable. It packages observed cryptographic evidence into a form
that can support technology due diligence, executive assessment, acquisition
review, integration planning, and future cryptographic migration planning.

The package summarizes observed evidence. It does not replace executive
judgment.

Potential sections include:

- Executive Summary
- Cryptographic Inventory Summary
- Algorithm Inventory
- Certificate Inventory
- Key Management Observations
- Long-lived Data Exposure
- Third-party Dependencies
- Migration Considerations
- Evidence Appendix
- Confidence / Evidence Quality

## Additional Deliverables

The following report families may be derived from the same underlying evidence
as HarvestGuard's reporting capabilities mature.

### Technology Due Diligence

- **Audience:** technology diligence teams, CTOs, CIOs, advisors, and
  investment stakeholders.
- **Purpose:** support a structured review of cryptographic posture during a
  diligence process.
- **Evidence used:** cryptographic inventory, certificate and key evidence,
  sensitive-data categories, code-analysis findings, scanner metadata,
  confidence, and finding-level errors.
- **Typical decisions supported:** diligence follow-up, integration planning,
  technical workstream scoping, and questions for the target organization.

### M&A Technical Assessment

- **Audience:** acquisition teams, deal partners, integration leaders, legal
  teams, and technical advisors.
- **Purpose:** summarize cryptographic evidence relevant to acquisition review
  without replacing broader technical due diligence.
- **Evidence used:** inventory summaries, long-lived data exposure indicators,
  key and certificate observations, report metadata, and evidence limitations.
- **Typical decisions supported:** diligence scope, post-close integration
  planning, advisory follow-up, and executive briefing preparation.

### Portfolio Risk Review

- **Audience:** private equity operating partners, portfolio CTOs, CISOs, and
  advisory teams.
- **Purpose:** compare evidence themes across repeat scans or portfolio
  entities once history and comparison capabilities exist.
- **Evidence used:** normalized finding totals, scanner confidence, repeat-scan
  trends, cryptographic asset categories, and observed gaps.
- **Typical decisions supported:** portfolio prioritization, operating cadence,
  modernization planning, and executive discussion topics.

### Cryptographic Modernization Assessment

- **Audience:** enterprise technology leaders, security architecture teams,
  platform owners, and modernization programs.
- **Purpose:** identify evidence that informs future cryptographic migration
  planning as standards evolve.
- **Evidence used:** algorithm inventory, key sizes, certificate expiration,
  code-analysis observations, dependency evidence, and confidence notes.
- **Typical decisions supported:** modernization roadmap input, migration
  sequencing, system owner discussions, and follow-up technical analysis.

### Executive Briefing

- **Audience:** CEOs, CTOs, CIOs, CISOs, general counsel, and operating
  partners.
- **Purpose:** present a concise evidence-backed narrative for leadership
  discussion.
- **Evidence used:** summarized findings, confidence indicators, scanner
  limitations, and links to supporting technical detail.
- **Typical decisions supported:** leadership alignment, diligence questions,
  resourcing discussions, and planning assumptions.

### Board Brief

- **Audience:** boards, board committees, investment committees, and executive
  sponsors.
- **Purpose:** provide a high-level evidence summary for governance discussion.
- **Evidence used:** aggregate evidence, confidence summaries, material
  observations, and documented limitations.
- **Typical decisions supported:** governance oversight, investment committee
  discussion, and direction for management follow-up.

### Regulatory Evidence Package

- **Audience:** compliance teams, auditors, legal teams, and regulated
  enterprises.
- **Purpose:** collect evidence that may support internal or external review
  processes without turning HarvestGuard into a GRC platform.
- **Evidence used:** scan metadata, normalized findings, evidence provenance,
  confidence, limitations, and retained technical appendices.
- **Typical decisions supported:** audit preparation, control evidence
  discussion, policy review, and evidence handoff to established compliance
  systems.

### Asset Inventory Export

- **Audience:** security architecture teams, platform owners, CMDB owners, and
  downstream tooling maintainers.
- **Purpose:** export cryptographic asset evidence for review or integration
  with existing systems.
- **Evidence used:** normalized findings, asset location, asset type,
  algorithm, key size, certificate metadata, scanner identity, and errors.
- **Typical decisions supported:** inventory reconciliation, owner follow-up,
  exception review, and system-of-record updates outside HarvestGuard.

### Architecture Appendix

- **Audience:** enterprise architects, security architects, engineering leads,
  and technical due diligence teams.
- **Purpose:** preserve enough technical detail for reviewers to validate
  executive statements.
- **Evidence used:** detailed findings, scanner metadata, technical metadata,
  known limitations, confidence, and errors.
- **Typical decisions supported:** architecture review, design follow-up,
  implementation planning, and validation of report conclusions.

## Evidence Principles

Evidence is primary.

Assessment is secondary.

Recommendations are optional.

Inference must remain distinguishable from observation.

Executive-facing statements should be traceable to technical evidence.

## Report Philosophy

Reports should:

- show supporting evidence;
- identify confidence;
- link conclusions to observations;
- avoid unsupported scoring;
- avoid "magic AI."

Reports should not make unsupported claims about complete quantum readiness,
business impact, remediation cost, ownership, or priority. Those concepts may
appear only when they are clearly labeled as assessment or advisory judgment
and remain separate from observed evidence.

## Audience

HarvestGuard deliverables are intended for:

- Private Equity
- Portfolio CTOs
- Enterprise CIOs
- Boards
- M&A teams
- Government
- Critical infrastructure
- Large enterprises
