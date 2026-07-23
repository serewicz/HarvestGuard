# Product Principles

This is the canonical product-boundary document for HarvestGuard. These
principles keep HarvestGuard's product claims, implementation scope, and
evidence model aligned. They apply to roadmap decisions, issue scoping,
implementation review, documentation, and release claims.

The durable product-boundary decision is recorded in
[ADR-006: Product boundary](DECISIONS/ADR-006-product-boundary.md).

HarvestGuard collects verifiable cryptographic evidence, communicates
confidence and unknowns, surfaces ownership signals, and frames the questions
organizations must answer. It does not prescribe the answer.

## Purpose

HarvestGuard is an open-source evidence collection tool for cryptographic
exposure, long-lived data risk, technology diligence, and future post-quantum
migration planning.

HarvestGuard should help users understand:

- what was directly observed;
- how reliable that evidence is;
- what ownership metadata or signals exist;
- what remains unknown;
- where cryptographic exposure appears concentrated;
- which questions management and executive leadership should answer.

HarvestGuard stops at evidence, confidence, uncertainty, ownership signals, and
decision questions. Business recommendations require organizational,
contractual, financial, and operating context that the scanner cannot
independently observe.

HarvestGuard should not prescribe remediation, recommend vendors, estimate
costs, assign business accountability, certify compliance, or determine whether
an organization is quantum-ready.

## Evidence Principles

1. **Evidence before opinion.** HarvestGuard's primary external value is
   defensible cryptographic evidence. It inventories cryptographic assets and
   related exposure so organizations have a factual basis for technology
   diligence and future migration planning.
2. **Observation before recommendation.** Scanner output records what was
   observed before any advisory layer interprets what an organization should
   do next.
3. **Confidence before certainty.** Confidence describes the quality of the
   evidence, not business severity. Findings must not imply certainty where a
   scanner only has a heuristic, partial, or indirect observation.
4. **Unknown is a valid result.** If evidence cannot establish an answer, the
   result should say so. Unknowns are not defects to hide; they are decision
   inputs for follow-up review.
5. **Ownership signals are evidence, not assigned accountability.** Filesystem
   ownership, cloud tags, IAM metadata, repository metadata, CODEOWNERS,
   project labels, namespaces, or similar source-attributed metadata may
   indicate where to ask follow-up questions. They must never be treated as
   confirmed business accountability without corroboration.
6. **Evidence must survive independent verification.** Findings should include
   enough source, scanner, timestamp, confidence, limitation, and raw-detail
   context for another reviewer to understand how the evidence was collected.
7. **Observed evidence must remain separate from inference, risk
   interpretation, and advisory judgment.** Risk, priority, business
   interpretation, remediation status, notes, and advisory conclusions belong
   in a separate assessment layer.
8. **Missing expected governance or ownership information is reportable, but
   absence must not be presented as proof of organizational failure.** A scan
   can report that expected metadata was unavailable, missing, or outside
   coverage without asserting why.
9. **HarvestGuard is intentionally bounded.** It collects and organizes
   evidence; it does not claim to know the full operating, contractual,
   financial, regulatory, or organizational context around that evidence.
10. **Executive judgment remains human.** HarvestGuard may frame executive
    questions from evidence, unknowns, and concentration patterns, but leaders
    and advisors decide what those answers mean.

## Engineering and Product Constraints

11. **Crypto-first, not general-purpose security scanning.** HarvestGuard
    exists to inventory cryptographic posture, cryptographic exposure, and
    long-lived data risk. Sensitive-data discovery is included only where it
    supports cryptographic and diligence questions.
12. **Local-first and private by default.** First use must work without sending
    scan details, file contents, paths, object names, or credentials to a
    HarvestGuard-operated service.
13. **HarvestGuard complements existing security and governance tools.** It is
    additive to security, cloud, asset-management, vulnerability-management,
    and governance platforms; it should not become a replacement for them.
14. **CLI functionality precedes visual polish.** Core scanner behavior must be
    scriptable, testable, and reportable before the dashboard becomes the main
    workflow.
15. **Dashboards must link visual summaries back to technical evidence.**
    Visual states and charts must make the supporting evidence reachable, not
    hide it behind colors or scores.
16. **Reports contribute to a Technology Due Diligence Evidence Package.**
    Reports should package cryptographic evidence for executive assessment,
    technical review, acquisition review, integration planning, and
    cryptographic modernization planning without overstating what the tool has
    observed.
17. **Mature third-party scanners should be integrated where appropriate
    rather than rebuilt.** Network, code, binary, and runtime crypto analysis
    should rely on proven tools when they are better than bespoke detection.
18. **SQLite remains the initial local system of record.** Local scan history
    and raw findings start in SQLite to keep first use simple and private.
19. **Prometheus stores aggregate operational metrics, not detailed findings.**
    Prometheus must not receive file paths, object names, secrets, matched
    values, or full finding details.
20. **Grafana remains optional.** The built-in CLI, local store, reports, and
    dashboard remain the default experience.
21. **Raw findings remain immutable.** New interpretation or workflow state
    must not rewrite the original evidence.
22. **Assessment, ownership notes, priority, and remediation status must remain
    separate from raw evidence.** These records may help users manage work, but
    they are not the same thing as source-collected evidence.
23. **New features must pass the product-boundary fit test.** A core feature
    should materially improve cryptographic inventory, evidence quality,
    confidence, unknowns, ownership signals, evidence-based topology,
    executive questions, the Technology Due Diligence Evidence Package, or
    standalone local usability.

## Vocabulary

The terms below are the product-boundary essentials.
[docs/TERMINOLOGY.md](TERMINOLOGY.md) is the canonical, complete glossary and
adds exposure, HNDL exposure, risk score, remediation priority, false positive,
and false negative, plus how current dashboard and report language maps to
these terms.

- **Observed evidence:** Source-attributed facts collected directly by a
  scanner, such as file signatures, object encryption metadata, certificate
  fields, key properties, scanner errors, or pattern counts.
- **Inference:** A conclusion derived from observed evidence, such as likely
  exposure state or possible HNDL relevance. Inference must remain traceable to
  the evidence that produced it.
- **Ownership signal:** Source-attributed metadata that may indicate who or
  what system is associated with an asset. Examples include filesystem
  ownership, cloud tags, IAM metadata, repository metadata, CODEOWNERS, project
  labels, namespaces, or similar metadata. Ownership signals must never be
  treated as confirmed business accountability without corroboration.
- **Unknown:** A valid result when available evidence cannot establish an
  answer. Unknown may mean the scanner lacked access, the source did not expose
  the needed metadata, the scan was partial, or the evidence was ambiguous.
- **Evidence confidence:** A statement about the quality, directness,
  completeness, and reliability of the evidence. Confidence describes evidence
  quality, not business severity.
- **Coverage:** The portion of the intended scan scope that was actually
  inspected, including limits, exclusions, permission failures, unsupported
  asset types, and scanner errors.
- **Partial scan:** A scan whose coverage is limited by scope, permissions,
  limits, errors, time, unsupported formats, or other constraints.
- **Evidence-based risk topology:** A traceable view of where cryptographic
  exposure appears concentrated across observed assets, systems, repositories,
  buckets, namespaces, or ownership signals. It is not a remediation plan.
- **Executive question:** A management or leadership question generated from
  observed evidence, unknowns, confidence, coverage limits, or concentration
  patterns.
- **Recommendation:** A proposed decision, product, vendor, architecture,
  remediation plan, cost estimate, accountability assignment, or compliance
  conclusion. Recommendations are outside the core HarvestGuard evidence
  layer.

## Feature-Boundary Test

Before accepting a new core feature, ask:

1. Does it improve verifiable cryptographic evidence, confidence, unknowns,
   coverage, ownership signals, evidence-based topology, executive questions,
   reporting, or local standalone use?
2. Can observed evidence remain separate from inference, risk interpretation,
   assessment records, and advisory judgment?
3. Can source attribution, scanner identity, timestamp, confidence, and
   limitations survive independent review?
4. Does the feature avoid prescribing remediation, recommending vendors,
   estimating costs, assigning business accountability, certifying compliance,
   or declaring quantum readiness?
5. Does it keep HarvestGuard crypto-first and complementary to existing
   security and governance tools?

If the answer to these questions is no, the work likely belongs in an external
advisory process, an integration, or a downstream assessment layer rather than
the core HarvestGuard evidence layer.
