# HarvestGuard Roadmap

This is the canonical product roadmap for HarvestGuard. It preserves the
current product direction while organizing implementation work into stable,
issue-ready milestones. GitHub Issues are the source of truth for non-trivial
implementation scope; `HG-###` IDs are roadmap references, not substitutes for
Issues.

HarvestGuard exists for M&A, PE/VC, legal, and enterprise technology diligence
teams that need a focused cryptographic asset inventory and defensible evidence
about cryptographic posture, long-lived data exposure, and future migration
planning. It is not a general security scanner or a replacement for established
enterprise security platforms. The product stays focused on crypto-first
evidence, local operation, defensible terminology, and reports that support
technical review, executive assessment, acquisition review, integration
planning, and cryptographic modernization.

## Status Values

- `Complete`: repository evidence shows the capability exists and is tested or
  documented enough to rely on.
- `Partial`: repository evidence shows useful implementation exists, but the
  roadmap item is not fully satisfied.
- `Needs Validation`: repository evidence is insufficient or the current
  implementation may not meet the item without review.
- `Planned`: not implemented yet.

## Roadmap IDs and Issues

Use `HG-###` IDs to connect work to product direction, dependencies, and
milestones. Use GitHub Issues to define the accepted implementation scope,
out-of-scope boundaries, acceptance criteria, tests, documentation impact, and
review discussion for each non-trivial change. When an Issue and roadmap text
disagree, update or clarify the Issue before implementation and reconcile the
roadmap as part of the docs impact.

## Current State

Current state (as of this writing): local filesystem, AWS S3, GCS, and Azure
Blob scanning all do real encryption-status detection; the PII/secrets
classifier, local cryptographic asset inventory scanner, and a Semgrep-based
crypto code analysis scanner each ship as their own scan type. The unified CLI
can produce console summaries, normalized JSON, and evidence-only Markdown
reports that can contribute to a future Technology Due Diligence Evidence
Package and other executive deliverables described in
[EXECUTIVE_DELIVERABLES.md](EXECUTIVE_DELIVERABLES.md). The container work is
done except the k8s manifest: `.github/workflows/container-build.yml` builds a
non-root distroless image and is configured to sign it keylessly and attach a
CycloneDX SBOM attestation (see
[SECURITY.md](../SECURITY.md#verifying-the-container-image) for what has and has
not been exercised against a real published image; release identity and
provenance are HG-011's scope). No CBOM/PDF export yet, no network-level crypto
detection (TLS/cipher-suite scanning).

## Direction

Architecture direction:

Scan adapters -> Normalized finding model -> Local evidence store -> CLI and
service layer -> Built-in dashboard and reports -> Optional Prometheus and
Grafana -> Future Executive Priority Index.

## Quantum Risk Taxonomy

1. **Harvest Now, Decrypt Later (HNDL)** — encryption detection is
   implemented and evidence-backed; HNDL exposure scoring is a heuristic
   inference layered on top of that evidence and is **Needs Validation**
   (see [TERMINOLOGY.md](TERMINOLOGY.md)). HNDL exposure must not be
   presented as a validated, measured result.
2. **Cryptographic inventory blind spots** — partially done. The future scan
   surfaces listed under "Preserved Product Notes" below cover this;
   source-code crypto usage analysis now ships (`code_analysis/`, a vendored
   Semgrep rule set) but inspects source text only, and its current rules
   target Python source only — binary and network/cipher detection don't
   exist yet — most companies have no map of what algorithms/key
   lengths/libraries they're running, which is exactly what this section
   targets.
3. **PQC migration debt / crypto-agility** — the source-code analysis
   prerequisite now exists, but assessing crypto-agility itself (can a
   system swap algorithms without a rewrite) remains unsolved, and would
   also benefit from binary-level analysis that does not exist yet — no
   clear detection approach yet beyond "does the code use a crypto-agility
   abstraction," itself a further code-analysis question. See the Quantum
   Risk Engine section below.
4. **Data ownership & classification gaps** — primarily an advisory/services
   deliverable, not a tool feature. See "Advisory backlog" below.
5. **Supply chain & third-party exposure (incl. shadow AI)** — explicitly out
   of scope for now; see bottom of this doc.
6. **Valuation & integration impact** — the dollarized-risk and
   partner-ready-summary direction, none of which is implemented; the closest
   roadmap items are HG-024 through HG-027 in Milestone 5. Related existing
   work:
   [technology-leadership-portfolio](https://github.com/serewicz/technology-leadership-portfolio).
7. **Talent & governance gaps** — not scannable; advisory-only, with one
   small tool-buildable nicety (see "Advisory backlog" below).

Key product constraints:

- Local-first operation is the trust boundary.
- Observed evidence and inferred risk must remain separate. The shared
  vocabulary for both is defined in [TERMINOLOGY.md](TERMINOLOGY.md).
- Raw findings are immutable; prioritization is a separate assessment layer.
- SQLite is the initial local system of record.
- Prometheus stores operational and trend metrics, not detailed findings.
- Grafana is optional and must not be required for first use.

## Milestone 1: MVP - Trustworthy Scanner

### HG-001

- **Title:** Cryptographic asset inventory
- **Purpose:** Identify cryptographic exposure across local filesystems and
  supported object storage using observable evidence.
- **Status:** Complete
- **Milestone:** 1 - MVP: Trustworthy Scanner
- **Dependencies:** None
- **Acceptance criteria:** Local filesystem, AWS S3, GCS, Azure Blob, and code
  crypto analysis scan adapters produce inventory records; each record includes
  source, location, observed evidence, scanner identity, scan time, and
  confidence; existing scanner capabilities are preserved. The inventory
  concept, its minimum record fields, and the per-adapter mapping are documented
  in [ASSET_INVENTORY.md](ASSET_INVENTORY.md); the adapters that produce the
  records are implemented in `finding_adapters.py` over the normalized model in
  `findings.py`. Uncertain and inaccessible observations remain visible rather
  than being silently reclassified.
- **GitHub issue:** https://github.com/serewicz/HarvestGuard/issues/13

### HG-002

- **Title:** Defensible risk terminology
- **Purpose:** Use evidence and risk language that is accurate enough for
  diligence and executive reporting without overstating certainty or drifting
  into recommendations.
- **Status:** Complete
- **Milestone:** 1 - MVP: Trustworthy Scanner
- **Dependencies:** HG-001
- **Acceptance criteria:** Documentation defines observed evidence, inference,
  ownership signal, unknown, evidence confidence, coverage, partial scan,
  evidence-based risk topology, executive question, exposure, HNDL exposure,
  risk score, and remediation priority; recommendation is defined as outside
  the core HarvestGuard evidence layer; UI and reports avoid claiming
  certainty where only inference exists. Terminology is defined in
  [TERMINOLOGY.md](TERMINOLOGY.md), which also maps current dashboard and
  report language to these terms and marks the heuristic risk score and HNDL
  exposure as `Needs Validation` until validated. The dashboard now labels
  Risk Score and HNDL Exposure as inferred heuristics (`Needs Validation`)
  with help text distinguishing them from observed evidence; rendering
  evidence and inference in fully separate labeled areas remains future UI
  work under HG-012 and HG-014.
- **GitHub issue:** https://github.com/serewicz/HarvestGuard/issues/14

### HG-003

- **Title:** Normalized finding schema
- **Purpose:** Give all scanners a common result contract before reports,
  history, filters, and prioritization grow around incompatible dataframes.
- **Status:** Complete
- **Milestone:** 1 - MVP: Trustworthy Scanner
- **Dependencies:** HG-001, HG-002
- **Acceptance criteria:** A documented schema contract represents asset
  identity, source, observed evidence, evidence source, scanner identity and
  version, collection timestamp, ownership signals, unknowns, confidence,
  limitations, and coverage or partial-scan status as fields of the raw,
  immutable `NormalizedFinding`; existing scanner outputs can be converted
  without changing runtime behavior. Derived exposure or topology linkage,
  executive questions, and mutable assessment records are explicitly out of
  scope for this schema — they belong to a separate, downstream assessment
  layer that would consume normalized findings by `finding_id` rather than
  carrying that data inside the raw finding itself (see
  [ARCHITECTURE.md](ARCHITECTURE.md#normalized-finding-model)). Implemented in
  `findings.py`, `finding_adapters.py`, and documented in
  `docs/NORMALIZED_FINDINGS.md`.
- **GitHub issue:** https://github.com/serewicz/HarvestGuard/issues/15

### HG-004

- **Title:** CLI
- **Purpose:** Make scanner behavior scriptable, testable, and suitable for
  diligence workflows before adding more visual polish.
- **Status:** Complete
- **Milestone:** 1 - MVP: Trustworthy Scanner
- **Dependencies:** HG-003
- **Acceptance criteria:** Users can run supported scan types from the command
  line; output can be written as JSON; nonzero exit codes distinguish user
  errors from scanner failures; dashboard behavior remains unchanged.
  Implemented in `harvestguard.py` and documented in `docs/CLI.md`.
- **GitHub issue:** https://github.com/serewicz/HarvestGuard/issues/16

### HG-005

- **Title:** Scale, pagination, and safety
- **Purpose:** Avoid incomplete or unsafe scans when targets contain many
  files, large cloud buckets, inaccessible paths, or permission failures.
- **Status:** Complete
- **Milestone:** 1 - MVP: Trustworthy Scanner
- **Dependencies:** HG-001, HG-003
- **Acceptance criteria:** S3 pagination, prefix, and later-page-failure
  behavior are correct and tested; GCS and Azure Blob SDK iterators are
  processed fully with partial findings preserved on later failure;
  filesystem `max_depth` treats root as depth 0 and prunes before descent;
  symlinks, FIFOs, sockets, and device files are never followed or opened,
  and are reported as explicit `skipped_special_file` findings rather than
  silently omitted; provider/auth/API failures surface as `scanner_errors`
  with a nonzero CLI exit while preserving `CloudScanError.partial_findings`;
  CLI JSON stays valid and Markdown/console reports state plainly when
  coverage was not complete. See
  [SCAN_COVERAGE.md](SCAN_COVERAGE.md) for the full semantics, which also
  covers provider-error sanitization
  (`scanner.errors.sanitize_provider_error`). No new `NormalizedFinding`
  schema fields were needed; no scanner algorithm or credential-management
  change was made.
- **GitHub issue:** https://github.com/serewicz/HarvestGuard/issues/17

### HG-006

- **Title:** Demo target
- **Purpose:** Provide a safe, repeatable sample target that demonstrates
  crypto evidence, sensitive-data findings, confidence, and reports.
- **Status:** Complete
- **Milestone:** 1 - MVP: Trustworthy Scanner
- **Dependencies:** HG-002, HG-003
- **Acceptance criteria:** A small local demo fixture
  (`demo/sample_target/`) can be scanned without real credentials or network
  access; expected findings are documented in
  [docs/CLI.md](CLI.md#demo-walkthrough), including filesystem encryption
  evidence, cryptographic inventory evidence, sensitive-data categories, and
  confidence fields; tests verify the demo's evidence, confidence, and
  JSON/Markdown report behavior remain stable, without pinning the one field
  (volume-level encryption fallback) that is legitimately platform-dependent;
  every fixture value is clearly marked fake, and none matches a real
  service's credential format.
- **GitHub issue:** https://github.com/serewicz/HarvestGuard/issues/18

### HG-007

- **Title:** JSON and Markdown reports
- **Purpose:** Produce reviewable artifacts that can be shared with technical
  teams and imported into downstream diligence workflows as evidence packages.
- **Status:** Complete
- **Milestone:** 1 - MVP: Trustworthy Scanner
- **Dependencies:** HG-003, HG-004
- **Acceptance criteria:** CLI can export normalized findings as JSON and a
  human-readable Markdown report; reports separate evidence from inference;
  sensitive matched values are never written to reports; the Markdown report
  includes scope and coverage, observed evidence, scanner versions, findings
  summary and breakdown, errors and warnings, and known limitations sections.
  Current JSON and Markdown report export is implemented in `reports.py`,
  exposed through `harvestguard.py`, and documented in `docs/CLI.md`. An
  expanded evidence package with ownership-signal summaries, evidence-based
  risk topology, and framed executive questions is a future reporting
  contract (see HG-017's HTML executive report and the "Future Executive
  Priority Index" direction), not part of the current JSON/Markdown output.
- **GitHub issue:** https://github.com/serewicz/HarvestGuard/issues/19

## Milestone 2: HarvestGuard v0.1 - Controlled Diligence Pilot

The evidence and scanner foundation (HG-001 through HG-007) is substantially
complete. This milestone is the next concrete product objective: a
controlled external pilot release.

**Product gate:** a technically sophisticated CTO can install HarvestGuard
without developer assistance, safely run the demo and representative scans,
understand what was and was not inspected, interpret confidence and
limitations correctly, generate a shareable evidence report, and identify
exactly which HarvestGuard version produced it.

HG-008 through HG-011 form this milestone, and all four are now `Complete` —
Milestone 2 is fully delivered.

### HG-008

- **Title:** End-to-end validation
- **Purpose:** Prove a fresh technically competent user can install
  HarvestGuard, run the documented demo and representative scanner paths,
  generate the supported evidence artifacts, and correctly understand
  successful, partial, limited, and failed scans.
- **Status:** Complete
- **Milestone:** 2 - HarvestGuard v0.1: Controlled Diligence Pilot
- **Dependencies:** HG-004, HG-006, HG-007
- **Acceptance criteria:** CI already covers local scan, classifier scan,
  cloud scanner unit tests, CLI invocation, and report generation for the
  demo target. This item extends that coverage to a fresh-install path: a
  technically competent user with no prior HarvestGuard exposure and no
  developer assistance can follow published installation and demo
  instructions, run representative local and cloud (mocked or sandboxed)
  scans, generate JSON/Markdown reports, and correctly distinguish
  successful, partial, limited, and failed scan outcomes from the output
  alone. Implemented as `tests/test_end_to_end_validation.py`, which drives
  the public CLI over the demo fixture, a representative non-demo target
  built at runtime, and S3/GCS/Azure scans faked at the provider SDK
  boundary only, across successful, limited, partial, and failed scans in
  summary, JSON, and Markdown output. The fresh-install path is validated by
  really installing the repository (both `pip install .` and `pip install -e .`)
  into a throwaway virtual environment and running the installed `harvestguard`
  console script from outside the checkout. Validation also fixed the documented
  `pip install -e .` path, which the flat repository layout broke, and
  documented how to read complete/limited/partial/failed coverage from an
  artifact (`docs/CLI.md`, "Reading coverage from an artifact"). Per-scanner
  detection characterization stays with HG-009 and final product-claims
  reconciliation with HG-010.
- **GitHub issue:** https://github.com/serewicz/HarvestGuard/issues/53

### HG-009

- **Title:** Confidence and detection characterization
- **Purpose:** Characterize what each scanner detects, what it can miss,
  important false-positive and false-negative conditions, what confidence
  means, and how operators should interpret unknown or limited evidence.
  This is evidence-characterization work, not risk scoring.
- **Status:** Complete
- **Milestone:** 2 - HarvestGuard v0.1: Controlled Diligence Pilot
- **Dependencies:** HG-002, HG-003, HG-005
- **Acceptance criteria:** Findings already carry `confidence` and
  `confidence_rationale`; this item requires per-scanner documentation of
  known detection scope, known false positives, known false negatives, and
  what an `unknown` or a `limitations` entry means for that scanner, so an
  operator reading a report can correctly interpret confidence and coverage
  rather than mistaking a heuristic for proof. Satisfied per scanner, including
  the two narrow behavioral corrections (PGP armor prefix narrowed;
  code-analysis failure diagnostics moved to stderr) documented there.
- **Delivered by:** [DETECTION_CHARACTERIZATION.md](DETECTION_CHARACTERIZATION.md),
  validated by `tests/test_detection_characterization.py`.
- **GitHub issue:** https://github.com/serewicz/HarvestGuard/issues/54

### HG-010

- **Title:** Product claims and trust audit
- **Purpose:** Reconcile public and product claims across README, CLI/help
  output, reports, dashboard, architecture, terminology, and documentation
  against behavior actually supported by implementation and tests. HG-008
  and HG-009 should complete first so this final claims and trust audit can
  draw on their validated end-to-end and detection-characterization results.
- **Status:** Complete
- **Milestone:** 2 - HarvestGuard v0.1: Controlled Diligence Pilot
- **Dependencies:** HG-001 through HG-009
- **Acceptance criteria:** Every reviewed product claim is classified as one
  of: implemented and tested; implemented with known limitations;
  experimental / needs validation; planned; or explicitly out of scope. The
  evidence-versus-inference boundary (observed evidence vs. heuristic
  inference such as risk score and HNDL exposure) is preserved and made
  explicit everywhere a claim is made. The audited claims, their
  classifications, the corrections made, and the areas deliberately left
  marked `Needs Validation` are recorded in
  [CLAIMS_AUDIT.md](CLAIMS_AUDIT.md). No scanner, risk, remediation,
  dashboard, storage, or release capability was added to satisfy a claim:
  unsupported claims were narrowed, marked planned, or declared out of scope.
- **Delivered by:** [CLAIMS_AUDIT.md](CLAIMS_AUDIT.md), validated by
  `tests/test_product_claims.py`.
- **GitHub issue:** https://github.com/serewicz/HarvestGuard/issues/55

### HG-011

- **Title:** Versioned release and reproducibility
- **Purpose:** Produce an identifiable, reproducible HarvestGuard release
  suitable for a controlled external pilot.
- **Status:** Complete
- **Milestone:** 2 - HarvestGuard v0.1: Controlled Diligence Pilot
- **Dependencies:** HG-008, HG-009, HG-010
- **Acceptance criteria:** An explicit HarvestGuard version identifier; a
  versioned release/tag; release notes; a reproducible or clearly identified
  container artifact; SBOM, signing, and provenance expectations where
  appropriate; documented dependency and reproducibility expectations; an
  explicit pre-1.0 support/status statement; and a way for a generated
  evidence report to identify exactly which HarvestGuard version produced it.
  Satisfied as release-identity work only: `0.1.0` is declared in
  `pyproject.toml` and `harvestguard_version.py`, `harvestguard --version`
  reports it, and every Markdown report records it in *Scan Information*. JSON
  output stays a bare finding array — no report envelope was added. SBOM,
  container signing, dependency pinning, and provenance are documented at
  their real status rather than claimed. Status is `Complete`: this
  implementation and its pull request have received independent closure
  review and merged. The `v0.1.0` tag itself has not been created — creating
  it is a separate, deliberate human release action performed after this
  post-closure documentation reconciliation is reviewed and merged, not a
  gate on any remaining roadmap or implementation work.
- **Delivered by:** [RELEASE.md](RELEASE.md) and
  [CHANGELOG.md](../CHANGELOG.md), validated by
  `tests/test_release_identity.py`.
- **GitHub issue:** https://github.com/serewicz/HarvestGuard/issues/56

## Milestone 3: MVP+ - Visual and Operational Experience

### HG-012

- **Title:** Built-in dashboard
- **Purpose:** Let users inspect scan output locally without requiring Grafana
  or external services.
- **Status:** Partial
- **Milestone:** 3 - MVP+: Visual and Operational Experience
- **Dependencies:** HG-003
- **Acceptance criteria:** Dashboard reads normalized findings, shows evidence
  and inference separately, and remains usable without network access for
  local scans.
- **GitHub issue:** TBD

### HG-013

- **Title:** Finding filters and drill-down
- **Purpose:** Help users move from summary charts to the underlying evidence
  for a specific asset or class of findings.
- **Status:** Planned
- **Milestone:** 3 - MVP+: Visual and Operational Experience
- **Dependencies:** HG-012
- **Acceptance criteria:** Users can filter by source, exposure state,
  confidence, scanner, owner state, and finding type; drill-down links back to
  technical evidence.
- **GitHub issue:** TBD

### HG-014

- **Title:** Color-coded exposure and ownership states
- **Purpose:** Make remediation and ownership triage scannable without hiding
  the underlying evidence.
- **Status:** Planned
- **Milestone:** 3 - MVP+: Visual and Operational Experience
- **Dependencies:** HG-002, HG-013
- **Acceptance criteria:** Colors map to documented exposure and ownership
  states; visual states never replace textual evidence or confidence.
- **GitHub issue:** TBD

### HG-015

- **Title:** Scan history
- **Purpose:** Track repeat scans over time for diligence follow-up and
  ownership-period risk management.
- **Status:** Planned
- **Milestone:** 3 - MVP+: Visual and Operational Experience
- **Dependencies:** HG-003, ADR-002
- **Acceptance criteria:** SQLite stores scan runs, immutable raw findings, and
  derived assessments; users can compare current and previous scans locally.
- **GitHub issue:** TBD

### HG-016

- **Title:** Technical remediation queue
- **Purpose:** Turn findings into actionable remediation work without mutating
  the underlying raw evidence.
- **Status:** Planned
- **Milestone:** 3 - MVP+: Visual and Operational Experience
- **Dependencies:** HG-015
- **Acceptance criteria:** Users can assign remediation status, owner, notes,
  and priority in a separate assessment layer; raw findings remain unchanged.
- **GitHub issue:** TBD

### HG-017

- **Title:** HTML executive report
- **Purpose:** Package report outputs into a polished local Technology Due
  Diligence Evidence Package or related executive deliverable for partners,
  GCs, boards, and deal teams.
- **Status:** Planned
- **Milestone:** 3 - MVP+: Visual and Operational Experience
- **Dependencies:** HG-007, HG-016
- **Acceptance criteria:** HTML report summarizes exposure, confidence,
  remediation themes, and technical appendix links; it avoids raw sensitive
  matched values.
- **GitHub issue:** TBD

## Milestone 4: Operational Edition

### HG-018

- **Title:** Prometheus metrics endpoint
- **Purpose:** Expose operational metrics and high-level trends without storing
  detailed findings in Prometheus.
- **Status:** Planned
- **Milestone:** 4 - Operational Edition
- **Dependencies:** HG-015, ADR-003
- **Acceptance criteria:** Endpoint exports scan counts, durations, failure
  counts, finding totals by class, and trend-safe aggregates only; no file
  paths, secrets, object names, or detailed findings are exported.
- **GitHub issue:** TBD

### HG-019

- **Title:** Grafana dashboard pack
- **Purpose:** Offer optional operational visualization for teams already using
  Grafana.
- **Status:** Planned
- **Milestone:** 4 - Operational Edition
- **Dependencies:** HG-018
- **Acceptance criteria:** Grafana dashboards import cleanly; first use of
  HarvestGuard does not require Grafana; dashboards use only Prometheus-safe
  aggregate metrics.
- **GitHub issue:** TBD

### HG-020

- **Title:** Scheduled scans
- **Purpose:** Support ownership-period monitoring after diligence or
  acquisition.
- **Status:** Planned
- **Milestone:** 4 - Operational Edition
- **Dependencies:** HG-015, HG-018
- **Acceptance criteria:** Users can schedule repeat local or cloud scans;
  schedule config is local; failures are visible in history and metrics.
- **GitHub issue:** TBD

### HG-021

- **Title:** Baseline drift detection
- **Purpose:** Identify changes in crypto exposure, sensitive-data placement,
  and scanner confidence over time.
- **Status:** Planned
- **Milestone:** 4 - Operational Edition
- **Dependencies:** HG-015, HG-020
- **Acceptance criteria:** Users can compare scans against a chosen baseline;
  added, removed, and changed findings are reported separately from raw
  findings.
- **GitHub issue:** TBD

### HG-022

- **Title:** Portfolio and multi-entity comparison
- **Purpose:** Help PE/VC and advisory users compare exposure across companies,
  business units, or diligence targets.
- **Status:** Planned
- **Milestone:** 4 - Operational Edition
- **Dependencies:** HG-021
- **Acceptance criteria:** Users can tag scans by entity; comparisons use
  aggregate and normalized fields; entity-level reports avoid leaking raw
  detail across boundaries.
- **GitHub issue:** TBD

### HG-023

- **Title:** Optional PostgreSQL deployment
- **Purpose:** Support larger operational deployments while keeping SQLite as
  the first-use local system of record.
- **Status:** Planned
- **Milestone:** 4 - Operational Edition
- **Dependencies:** HG-015
- **Acceptance criteria:** PostgreSQL is optional; SQLite remains supported;
  migration strategy is documented; first use does not require external
  infrastructure.
- **GitHub issue:** TBD

## Milestone 5: Decision-Support Edition

### HG-024

- **Title:** Ownership-horizon model
- **Purpose:** Connect findings to diligence, holding period, and remediation
  horizon decisions.
- **Status:** Planned
- **Milestone:** 5 - Decision-Support Edition
- **Dependencies:** HG-021, HG-022
- **Acceptance criteria:** Users can model short, medium, and long ownership
  horizons; outputs are labelled as decision support, not observed evidence.
- **GitHub issue:** TBD

### HG-025

- **Title:** Crypto-agility and migration-difficulty models
- **Purpose:** Estimate how hard it may be to migrate crypto usage after
  inventory and code-analysis signals exist.
- **Status:** Planned
- **Milestone:** 5 - Decision-Support Edition
- **Dependencies:** HG-003, future code and binary crypto analysis
- **Acceptance criteria:** Model inputs are documented; assumptions are visible;
  migration difficulty is stored as assessment data separate from raw findings.
- **GitHub issue:** TBD

### HG-026

- **Title:** Long-lived data exposure model
- **Purpose:** Prioritize data whose useful lifetime exceeds plausible
  cryptographic protection windows.
- **Status:** Planned
- **Milestone:** 5 - Decision-Support Edition
- **Dependencies:** HG-002, HG-024, HG-025
- **Acceptance criteria:** Reports distinguish long-lived data exposure from
  generic sensitive data; assumptions are configurable and documented.
- **GitHub issue:** TBD

### HG-027

- **Title:** Executive Priority Index and board/M&A report
- **Purpose:** Translate evidence and assessment into a concise executive
  priority view for board, buyer, GC, and integration planning conversations.
- **Status:** Planned
- **Milestone:** 5 - Decision-Support Edition
- **Dependencies:** HG-017, HG-022, HG-024, HG-025, HG-026
- **Acceptance criteria:** Index combines normalized findings, confidence,
  ownership horizon, migration difficulty, and long-lived exposure; report
  explains assumptions and links to technical evidence.
- **GitHub issue:** TBD

## v0.1.1 Stabilization

### HG-028

- **Title:** Self-contained CLI installation and dependency packaging
- **Purpose:** Ensure a fresh Python 3.10+ environment can install and run
  the documented HarvestGuard CLI without hidden dependency steps.
- **Status:** Complete
- **Milestone:** v0.1.1 Stabilization
- **Dependencies:** HG-008, HG-011
- **Acceptance criteria:** `pip install .` and `pip install -e .` create a
  usable installed CLI in isolated environments; runtime dependencies are
  declared in `pyproject.toml`; JSON and Markdown contracts remain
  unchanged; installation documentation covers Python requirements and
  resolver behavior.
- **Delivered by:** `pyproject.toml`, `requirements.txt`,
  `tests/test_clean_install.py`, and `tests/test_packaging_dependencies.py`.
- **GitHub issue:** https://github.com/serewicz/HarvestGuard/issues/62

### HG-029

- **Title:** Filesystem Finding Amplification and Summary Semantics
- **Purpose:** Prevent ordinary files from generating repeated per-file
  filesystem context findings. Represent shared filesystem context once per
  mount or volume. Clarify console and Markdown summaries by separating
  material evidence, aggregate filesystem context, coverage limitations,
  skipped or inaccessible entries, finding-level errors, scanner errors, and
  total normalized records.
- **Status:** Complete
- **Milestone:** v0.1.1 Stabilization
- **Dependencies:** HG-008, HG-009
- **Acceptance criteria:** Ordinary readable files without supported evidence
  or file-specific failures do not become individual normalized findings;
  shared filesystem context is aggregated per mount or volume; Unknown remains
  distinct from observed Unencrypted; JSON remains a bare normalized-finding
  array; console and Markdown summaries distinguish files inspected, material
  evidence, filesystem context, coverage limitations, skipped or inaccessible
  records, finding-level errors, scanner errors, and total normalized records.
- **Delivered by:** `scanner/filesystem.py`, `finding_adapters.py`,
  `reports.py`, `docs/CLI.md`, `docs/DETECTION_CHARACTERIZATION.md`, and
  `tests/test_filesystem_aggregate_context.py`.
- **GitHub issue:** https://github.com/serewicz/HarvestGuard/issues/65
- **Pull request:** https://github.com/serewicz/HarvestGuard/pull/67

### HG-030

- **Title:** OpenSSL Encrypted-File Detection and Crypto Scan Accounting
- **Purpose:** Add first-class OpenSSL `Salted__` encrypted-file detection to
  the crypto inventory scanner. Provide deterministic crypto-inventory
  ownership for OpenSSL encrypted-file findings, preserve filesystem-only
  behavior, deduplicate deterministically under `--type all`, add Crypto files
  inspected accounting, preserve HG-029 Files scanned semantics, retain
  bare-array JSON output, and cover OpenSSL detection with regression tests.
- **Status:** Complete
- **Milestone:** v0.1.1 Stabilization
- **Dependencies:** HG-028, HG-029
- **Acceptance criteria:** OpenSSL `Salted__` files are detected as crypto
  inventory evidence with deterministic `encrypted_file:openssl` rule
  ownership; filesystem-only scans continue to report filesystem signature
  evidence; combined scans emit exactly one OpenSSL finding per file with
  crypto inventory winning; Crypto files inspected is reported separately from
  HG-029 Files scanned; JSON remains a bare normalized-finding array; OpenSSL
  detection, deduplication, accounting, JSON, and Markdown behavior are covered
  by regression tests.
- **Delivered by:** `scanner/crypto_inventory.py`, `finding_adapters.py`,
  `harvestguard.py`, `reports.py`, and
  `tests/test_openssl_encrypted_file_detection.py`.
- **GitHub issue:** https://github.com/serewicz/HarvestGuard/issues/66
- **Pull request:** https://github.com/serewicz/HarvestGuard/pull/69

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
  Semgrep rule set whose rules currently declare `languages: [python]`;
  additional source languages, network, deeper binary, entropy, and runtime
  crypto analysis remain future scan surfaces and should integrate mature
  third-party scanners where appropriate.
- Broader crypto-container and keystore coverage (for example Java keystores,
  HSM/KMS integrations beyond current cloud provider metadata, and additional
  certificate/key container formats) is a future scan surface, not yet
  implemented.
- Filename- and path-based regulated-data classification signals, if added,
  are a heuristic classification/ownership signal only — a filename or path
  match is never proof that regulated data exists in a file, and must carry
  the same evidence/inference discipline as other ownership signals.
