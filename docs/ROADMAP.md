# HarvestGuard Roadmap

This is the canonical product roadmap for HarvestGuard. It preserves the
current product direction while organizing implementation work into stable,
issue-ready milestones.

HarvestGuard exists for M&A, PE/VC, legal, and enterprise technology diligence
teams that need fast, trustworthy visibility into cryptographic posture,
long-lived data exposure, and remediation priorities. It is not a general
security scanner. The product stays focused on crypto-first evidence, local
operation, defensible terminology, and reports that serve both executives and
technical remediation owners.

## Status Values

- `Complete`: repository evidence shows the capability exists and is tested or
  documented enough to rely on.
- `Partial`: repository evidence shows useful implementation exists, but the
  roadmap item is not fully satisfied.
- `Needs Validation`: repository evidence is insufficient or the current
  implementation may not meet the item without review.
- `Planned`: not implemented yet.

## Current State

Current state (as of this writing): local filesystem, AWS S3, GCS, and Azure
Blob scanning all do real encryption-status detection; the PII/secrets
classifier and a Semgrep-based crypto code analysis scanner each ship as
their own scan type. Pillar 2 (containers) is done except the k8s manifest —
signed, keylessly-attested images with an SBOM ship from CI. No CBOM/PDF
export yet, no network-level crypto detection (TLS/cipher-suite scanning).

## Direction

Architecture direction:

Scan adapters -> Normalized finding model -> Local evidence store -> CLI and
service layer -> Built-in dashboard and reports -> Optional Prometheus and
Grafana -> Future Executive Priority Index.

## Quantum Risk Taxonomy

1. **Harvest Now, Decrypt Later (HNDL)** — done. Pillar 1's encryption
   detection + HNDL exposure scoring.
2. **Cryptographic inventory blind spots** — partially done. Pillar 1's
   "Future scan surfaces" section covers this; code & binary crypto usage
   analysis now ships (`code_analysis/`), network/cipher detection doesn't
   yet — most companies have no map of what algorithms/key
   lengths/libraries they're running, which is exactly what this section
   targets.
3. **PQC migration debt / crypto-agility** — the code/binary analysis
   prerequisite now exists, but assessing crypto-agility itself (can a
   system swap algorithms without a rewrite) remains unsolved — no clear
   detection approach yet beyond "does the code use a crypto-agility
   abstraction," itself a further code-analysis question. See the Quantum
   Risk Engine section below.
4. **Data ownership & classification gaps** — primarily an advisory/services
   deliverable, not a tool feature. See "Advisory backlog" below.
5. **Supply chain & third-party exposure (incl. shadow AI)** — explicitly out
   of scope for now; see bottom of this doc.
6. **Valuation & integration impact** — Pillar 3's dollarized-risk and
   partner-ready-summary items. Related existing work:
   [technology-leadership-portfolio](https://github.com/serewicz/technology-leadership-portfolio).
7. **Talent & governance gaps** — not scannable; advisory-only, with one
   small tool-buildable nicety (see "Advisory backlog" below).

Key product constraints:

- Local-first operation is the trust boundary.
- Observed evidence and inferred risk must remain separate.
- Raw findings are immutable; prioritization is a separate assessment layer.
- SQLite is the initial local system of record.
- Prometheus stores operational and trend metrics, not detailed findings.
- Grafana is optional and must not be required for first use.

## Milestone 1: MVP - Trustworthy Scanner

### HG-001

- **Title:** Cryptographic asset inventory
- **Purpose:** Identify cryptographic exposure across local filesystems and
  supported object storage using observable evidence.
- **Status:** Partial
- **Milestone:** 1 - MVP: Trustworthy Scanner
- **Dependencies:** None
- **Acceptance criteria:** Local filesystem, AWS S3, GCS, Azure Blob, and code
  crypto analysis scan adapters produce inventory records; each record includes
  source, location, observed evidence, scanner identity, scan time, and
  confidence; existing scanner capabilities are preserved.
- **GitHub issue:** https://github.com/serewicz/HarvestGuard/issues/13

### HG-002

- **Title:** Defensible risk terminology
- **Purpose:** Use risk language that is accurate enough for diligence,
  remediation, and executive reporting without overstating certainty.
- **Status:** Partial
- **Milestone:** 1 - MVP: Trustworthy Scanner
- **Dependencies:** HG-001
- **Acceptance criteria:** Documentation defines observed evidence, inference,
  confidence, exposure, HNDL exposure, risk score, and remediation priority;
  UI and reports avoid claiming certainty where only inference exists.
- **GitHub issue:** https://github.com/serewicz/HarvestGuard/issues/14

### HG-003

- **Title:** Normalized finding schema
- **Purpose:** Give all scanners a common result contract before reports,
  history, filters, and prioritization grow around incompatible dataframes.
- **Status:** Planned
- **Milestone:** 1 - MVP: Trustworthy Scanner
- **Dependencies:** HG-001, HG-002
- **Acceptance criteria:** A documented schema represents source, asset,
  evidence, inference, confidence, timestamps, scanner metadata, and raw
  immutable details; existing scanner outputs can be converted without changing
  runtime behavior.
- **GitHub issue:** https://github.com/serewicz/HarvestGuard/issues/15

### HG-004

- **Title:** CLI
- **Purpose:** Make scanner behavior scriptable, testable, and suitable for
  diligence workflows before adding more visual polish.
- **Status:** Planned
- **Milestone:** 1 - MVP: Trustworthy Scanner
- **Dependencies:** HG-003
- **Acceptance criteria:** Users can run supported scan types from the command
  line; output can be written as JSON; nonzero exit codes distinguish user
  errors from scanner failures; dashboard behavior remains unchanged.
- **GitHub issue:** https://github.com/serewicz/HarvestGuard/issues/16

### HG-005

- **Title:** Scale, pagination, and safety
- **Purpose:** Avoid incomplete or unsafe scans when targets contain many
  files, large cloud buckets, inaccessible paths, or permission failures.
- **Status:** Partial
- **Milestone:** 1 - MVP: Trustworthy Scanner
- **Dependencies:** HG-001, HG-003
- **Acceptance criteria:** Cloud scanners handle pagination; filesystem scans
  prune traversal safely; scan limits are visible; permission and API errors
  are represented without crashing or silently changing findings.
- **GitHub issue:** https://github.com/serewicz/HarvestGuard/issues/17

### HG-006

- **Title:** Demo target
- **Purpose:** Provide a safe, repeatable sample target that demonstrates
  crypto evidence, sensitive-data findings, confidence, and reports.
- **Status:** Planned
- **Milestone:** 1 - MVP: Trustworthy Scanner
- **Dependencies:** HG-002, HG-003
- **Acceptance criteria:** A small local demo fixture can be scanned without
  real credentials or sensitive data; expected findings are documented; tests
  verify the demo remains stable.
- **GitHub issue:** https://github.com/serewicz/HarvestGuard/issues/18

### HG-007

- **Title:** JSON and Markdown reports
- **Purpose:** Produce reviewable artifacts that can be shared with technical
  teams and imported into downstream diligence workflows.
- **Status:** Planned
- **Milestone:** 1 - MVP: Trustworthy Scanner
- **Dependencies:** HG-003, HG-004
- **Acceptance criteria:** CLI can export normalized findings as JSON and a
  human-readable Markdown report; reports separate evidence from inference;
  sensitive matched values are never written to reports.
- **GitHub issue:** https://github.com/serewicz/HarvestGuard/issues/19

### HG-008

- **Title:** End-to-end validation
- **Purpose:** Prove the scanner can run from setup through output generation
  on representative local and mocked cloud targets.
- **Status:** Partial
- **Milestone:** 1 - MVP: Trustworthy Scanner
- **Dependencies:** HG-004, HG-006, HG-007
- **Acceptance criteria:** CI covers local scan, classifier scan, cloud scanner
  unit tests, CLI invocation, and report generation; validation instructions
  are documented.
- **GitHub issue:** TBD

### HG-009

- **Title:** Confidence and false-positive handling
- **Purpose:** Make uncertainty explicit so users can triage findings without
  mistaking heuristics for proof.
- **Status:** Needs Validation
- **Milestone:** 1 - MVP: Trustworthy Scanner
- **Dependencies:** HG-002, HG-003
- **Acceptance criteria:** Findings include confidence; scanner docs explain
  known false positives and false negatives; dashboard and reports expose
  confidence alongside risk language.
- **GitHub issue:** TBD

### HG-010

- **Title:** Accurate product claims
- **Purpose:** Keep README, dashboard text, and reports aligned with actual
  repository evidence.
- **Status:** Needs Validation
- **Milestone:** 1 - MVP: Trustworthy Scanner
- **Dependencies:** HG-001 through HG-009
- **Acceptance criteria:** README claims match implemented and tested behavior;
  planned features are labelled as planned; no marketing copy implies
  unsupported scanner coverage or certainty.
- **GitHub issue:** TBD

## Milestone 2: MVP+ - Visual and Operational Experience

### HG-011

- **Title:** Built-in dashboard
- **Purpose:** Let users inspect scan output locally without requiring Grafana
  or external services.
- **Status:** Partial
- **Milestone:** 2 - MVP+: Visual and Operational Experience
- **Dependencies:** HG-003
- **Acceptance criteria:** Dashboard reads normalized findings, shows evidence
  and inference separately, and remains usable without network access for
  local scans.
- **GitHub issue:** TBD

### HG-012

- **Title:** Finding filters and drill-down
- **Purpose:** Help users move from summary charts to the underlying evidence
  for a specific asset or class of findings.
- **Status:** Planned
- **Milestone:** 2 - MVP+: Visual and Operational Experience
- **Dependencies:** HG-011
- **Acceptance criteria:** Users can filter by source, exposure state,
  confidence, scanner, owner state, and finding type; drill-down links back to
  technical evidence.
- **GitHub issue:** TBD

### HG-013

- **Title:** Color-coded exposure and ownership states
- **Purpose:** Make remediation and ownership triage scannable without hiding
  the underlying evidence.
- **Status:** Planned
- **Milestone:** 2 - MVP+: Visual and Operational Experience
- **Dependencies:** HG-002, HG-012
- **Acceptance criteria:** Colors map to documented exposure and ownership
  states; visual states never replace textual evidence or confidence.
- **GitHub issue:** TBD

### HG-014

- **Title:** Scan history
- **Purpose:** Track repeat scans over time for diligence follow-up and
  ownership-period risk management.
- **Status:** Planned
- **Milestone:** 2 - MVP+: Visual and Operational Experience
- **Dependencies:** HG-003, ADR-002
- **Acceptance criteria:** SQLite stores scan runs, immutable raw findings, and
  derived assessments; users can compare current and previous scans locally.
- **GitHub issue:** TBD

### HG-015

- **Title:** Technical remediation queue
- **Purpose:** Turn findings into actionable remediation work without mutating
  the underlying raw evidence.
- **Status:** Planned
- **Milestone:** 2 - MVP+: Visual and Operational Experience
- **Dependencies:** HG-014
- **Acceptance criteria:** Users can assign remediation status, owner, notes,
  and priority in a separate assessment layer; raw findings remain unchanged.
- **GitHub issue:** TBD

### HG-016

- **Title:** HTML executive report
- **Purpose:** Provide a polished local report for partners, GCs, boards, and
  deal teams.
- **Status:** Planned
- **Milestone:** 2 - MVP+: Visual and Operational Experience
- **Dependencies:** HG-007, HG-015
- **Acceptance criteria:** HTML report summarizes exposure, confidence,
  remediation themes, and technical appendix links; it avoids raw sensitive
  matched values.
- **GitHub issue:** TBD

## Milestone 3: Operational Edition

### HG-017

- **Title:** Prometheus metrics endpoint
- **Purpose:** Expose operational metrics and high-level trends without storing
  detailed findings in Prometheus.
- **Status:** Planned
- **Milestone:** 3 - Operational Edition
- **Dependencies:** HG-014, ADR-003
- **Acceptance criteria:** Endpoint exports scan counts, durations, failure
  counts, finding totals by class, and trend-safe aggregates only; no file
  paths, secrets, object names, or detailed findings are exported.
- **GitHub issue:** TBD

### HG-018

- **Title:** Grafana dashboard pack
- **Purpose:** Offer optional operational visualization for teams already using
  Grafana.
- **Status:** Planned
- **Milestone:** 3 - Operational Edition
- **Dependencies:** HG-017
- **Acceptance criteria:** Grafana dashboards import cleanly; first use of
  HarvestGuard does not require Grafana; dashboards use only Prometheus-safe
  aggregate metrics.
- **GitHub issue:** TBD

### HG-019

- **Title:** Scheduled scans
- **Purpose:** Support ownership-period monitoring after diligence or
  acquisition.
- **Status:** Planned
- **Milestone:** 3 - Operational Edition
- **Dependencies:** HG-014, HG-017
- **Acceptance criteria:** Users can schedule repeat local or cloud scans;
  schedule config is local; failures are visible in history and metrics.
- **GitHub issue:** TBD

### HG-020

- **Title:** Baseline drift detection
- **Purpose:** Identify changes in crypto exposure, sensitive-data placement,
  and scanner confidence over time.
- **Status:** Planned
- **Milestone:** 3 - Operational Edition
- **Dependencies:** HG-014, HG-019
- **Acceptance criteria:** Users can compare scans against a chosen baseline;
  added, removed, and changed findings are reported separately from raw
  findings.
- **GitHub issue:** TBD

### HG-021

- **Title:** Portfolio and multi-entity comparison
- **Purpose:** Help PE/VC and advisory users compare exposure across companies,
  business units, or diligence targets.
- **Status:** Planned
- **Milestone:** 3 - Operational Edition
- **Dependencies:** HG-020
- **Acceptance criteria:** Users can tag scans by entity; comparisons use
  aggregate and normalized fields; entity-level reports avoid leaking raw
  detail across boundaries.
- **GitHub issue:** TBD

### HG-022

- **Title:** Optional PostgreSQL deployment
- **Purpose:** Support larger operational deployments while keeping SQLite as
  the first-use local system of record.
- **Status:** Planned
- **Milestone:** 3 - Operational Edition
- **Dependencies:** HG-014
- **Acceptance criteria:** PostgreSQL is optional; SQLite remains supported;
  migration strategy is documented; first use does not require external
  infrastructure.
- **GitHub issue:** TBD

## Milestone 4: Decision-Support Edition

### HG-023

- **Title:** Ownership-horizon model
- **Purpose:** Connect findings to diligence, holding period, and remediation
  horizon decisions.
- **Status:** Planned
- **Milestone:** 4 - Decision-Support Edition
- **Dependencies:** HG-020, HG-021
- **Acceptance criteria:** Users can model short, medium, and long ownership
  horizons; outputs are labelled as decision support, not observed evidence.
- **GitHub issue:** TBD

### HG-024

- **Title:** Crypto-agility and migration-difficulty models
- **Purpose:** Estimate how hard it may be to migrate crypto usage after
  inventory and code-analysis signals exist.
- **Status:** Planned
- **Milestone:** 4 - Decision-Support Edition
- **Dependencies:** HG-003, future code and binary crypto analysis
- **Acceptance criteria:** Model inputs are documented; assumptions are visible;
  migration difficulty is stored as assessment data separate from raw findings.
- **GitHub issue:** TBD

### HG-025

- **Title:** Long-lived data exposure model
- **Purpose:** Prioritize data whose useful lifetime exceeds plausible
  cryptographic protection windows.
- **Status:** Planned
- **Milestone:** 4 - Decision-Support Edition
- **Dependencies:** HG-002, HG-023, HG-024
- **Acceptance criteria:** Reports distinguish long-lived data exposure from
  generic sensitive data; assumptions are configurable and documented.
- **GitHub issue:** TBD

### HG-026

- **Title:** Executive Priority Index and board/M&A report
- **Purpose:** Translate evidence and assessment into a concise executive
  priority view for board, buyer, GC, and integration planning conversations.
- **Status:** Planned
- **Milestone:** 4 - Decision-Support Edition
- **Dependencies:** HG-016, HG-021, HG-023, HG-024, HG-025
- **Acceptance criteria:** Index combines normalized findings, confidence,
  ownership horizon, migration difficulty, and long-lived exposure; report
  explains assumptions and links to technical evidence.
- **GitHub issue:** TBD

## Preserved Product Notes

These existing decisions remain part of the roadmap context:

- Coverage must span crypto posture and sensitive-data discovery because users
  ask where customer data is and whether it is protected.
- The container story is the trust story: local operation, no telemetry, no
  default outbound service, non-root image, and read-only-root compatibility.
- Cloud metadata is the reliable baseline for object storage encryption
  evidence.
- CycloneDX is the preferred CBOM target for interoperability.
- Code crypto analysis now exists through `code_analysis/` and a vendored
  Semgrep rule set; network, deeper binary, entropy, and runtime crypto
  analysis remain future scan surfaces and should integrate mature third-party
  scanners where appropriate.
