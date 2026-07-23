# Terminology

This is HarvestGuard's canonical glossary of evidence and risk terminology. It
exists so that findings are precise enough for diligence, advisory, legal, and
technical remediation conversations without overstating certainty or drifting
into recommendations.

It builds on [ADR-005: Evidence versus inference](DECISIONS/ADR-005-evidence-versus-inference.md)
and the Vocabulary section of
[Product Principles](PRODUCT_PRINCIPLES.md#vocabulary). Where a term appears in
both, the definitions are intended to agree; this document is the fuller
reference and adds the exposure, scoring, priority, and false positive/negative
terms.

## The core distinction

HarvestGuard separates two layers of language, and every term below belongs to
one of them:

- **Observed evidence** — source-attributed facts a scanner collected directly.
- **Inference and assessment** — conclusions derived from that evidence.

A reader must always be able to tell which layer a statement belongs to.
Inference must remain traceable back to the observed evidence and confidence
that produced it, and heuristic output must never be presented as a measured
fact. This is the rule that HG-002 exists to make explicit.

## Evidence-layer terms

These describe what a scanner directly observed and how good that observation
is. They live in the immutable raw finding (see
[NORMALIZED_FINDINGS.md](NORMALIZED_FINDINGS.md)).

- **Observed evidence** — Source-attributed facts collected directly by a
  scanner, such as file signatures, object encryption metadata, certificate
  fields, key properties, scanner errors, or sensitive-data pattern counts.
  Observed evidence never includes matched sensitive values themselves.
- **Confidence (evidence confidence)** — A statement about the quality,
  directness, completeness, and reliability of the evidence. Confidence
  describes evidence quality, not business severity, exposure, or remediation
  urgency. A high-confidence observation of an unencrypted file says the
  observation is reliable; it says nothing about how much that matters to the
  business.
- **Ownership signal** — Source-attributed metadata that may indicate who or
  what system is associated with an asset (filesystem ownership, cloud tags,
  IAM metadata, repository metadata, CODEOWNERS, project labels, namespaces,
  and similar). Ownership signals are evidence, not confirmed business
  accountability, and must never be presented as accountability without
  corroboration.
- **Unknown** — A valid result when available evidence cannot establish an
  answer: the scanner lacked access, the source did not expose the needed
  metadata, the scan was partial, or the evidence was ambiguous. An unknown is
  a decision input, not a defect to hide.
- **Coverage** — The portion of the intended scan scope that was actually
  inspected, including limits, exclusions, permission failures, unsupported
  asset types, and scanner errors. Incomplete coverage must never be
  indistinguishable from "no findings."
- **Partial scan** — A scan whose coverage is limited by scope, permissions,
  limits, errors, time, unsupported formats, or other constraints. A partial
  scan is reported as such rather than presented as complete.
- **False positive** — A finding that reports evidence or an inferred state
  that is not actually true of the asset — for example, flagging a file as
  unencrypted when it is encrypted in a format the scanner does not recognize,
  or a code-analysis match on a string that is not really a weak-crypto call.
  Confidence and limitations exist partly to bound how often this happens.
- **False negative** — A real condition the scanner failed to report — for
  example, an encrypted format or weak-crypto usage that the current signatures
  or rules do not detect. Several HarvestGuard scanners have deliberately
  narrow coverage today, so false negatives are expected; this is exactly why
  coverage and limitations must travel with every result and why absence of a
  finding is not proof of absence.

## Inference and assessment-layer terms

These are conclusions derived from evidence. Per ADR-005 they live in a
separate assessment layer, must stay traceable to the evidence that produced
them, and must not be written into the immutable raw finding.

- **Inference** — A conclusion derived from observed evidence, such as a likely
  exposure state or possible HNDL relevance. Inference must remain traceable to
  the evidence that produced it and must be labeled so a reader does not mistake
  it for a direct observation.
- **Exposure** — An inferred assessment that observed evidence indicates a
  cryptographic asset or data set could be reached, read, or misused — for
  example, data that is unencrypted or protected only by algorithms considered
  weak. Exposure is derived, not directly observed; it must remain traceable to
  the evidence and confidence behind it.
- **HNDL exposure (Harvest Now, Decrypt Later)** — A specific inferred exposure
  describing long-lived sensitive data that, if captured today while protected
  by classical cryptography, could be decrypted later once cryptanalytic
  capability (including quantum) advances. HarvestGuard's current HNDL exposure
  label is a heuristic bucket (High/Medium/Low) derived from encryption status
  and path signals, not a measured probability. **Needs Validation** — see the
  mapping table below.
- **Evidence-based risk topology** — A traceable view of where cryptographic
  exposure appears concentrated across observed assets, systems, repositories,
  buckets, namespaces, or ownership signals. It is a concentration view, not a
  remediation plan, and every point in it must remain traceable to underlying
  findings, source evidence, confidence, and coverage limits.
- **Risk score** — A heuristic numeric inference (currently a 0–100 value in
  `analyzer/risk.py`) derived from observed evidence such as encryption status
  and path signals. It is an ordering aid, not a measured fact, a probability,
  or a business-impact figure. The current implementation is an early
  proof-of-concept heuristic. **Needs Validation** — see the mapping table
  below.
- **Remediation priority** — An assessment-layer ordering of which findings a
  team might address first. Priority depends on business, contractual, and
  operational context HarvestGuard cannot observe. Where it is ever expressed,
  it must be labeled as assessment or advisory judgment and kept separate from
  observed evidence; the core evidence layer does not produce it.
- **Executive question** — A management or leadership question generated from
  observed evidence, unknowns, confidence, coverage limits, or concentration
  patterns. HarvestGuard frames the questions; it does not answer them.
- **Recommendation** — A proposed decision, product, vendor, architecture,
  remediation plan, cost estimate, accountability assignment, or compliance
  conclusion. **Recommendations are outside the core HarvestGuard evidence
  layer.** They require organizational, contractual, financial, and operating
  context the scanner cannot independently observe, and belong to an external
  advisory process or a downstream assessment layer.

## How current dashboard and report language maps to these terms

This table is the path from today's language to a clean evidence/inference
separation. It records which current labels are observed evidence, which are
inference, and where current behavior still needs validation before it can be
relied on for release claims. Future UI or report work (see roadmap HG-009,
HG-011, HG-013) should carry these labels into the interface itself and, per
the issue's testing requirements, verify the terminology with tests or review
fixtures.

| Where it appears | Current label | Layer | Notes |
| --- | --- | --- | --- |
| Dashboard results table (`dashboard/visualizations.py`) | `Encryption` | Observed evidence | Encryption status as reported by the scanner or provider metadata. |
| Dashboard "Risk Scores" bar / results table | `Risk Score` | Inference (heuristic) | 0–100 heuristic from `analyzer/risk.py`. Not a measured fact. **Needs Validation.** The dashboard labels it as an inferred heuristic. |
| Dashboard "Risk Distribution" pie | `HNDL Exposure` | Inference (heuristic) | High/Medium/Low bucket derived from the risk score. **Needs Validation.** The dashboard labels it as inferred. |
| Markdown / JSON report (`reports.py`) | `Observed Evidence`, `Confidence` | Observed evidence | Reports are evidence-only by design and already state that they do not infer business risk. |
| Markdown / JSON report | (risk score, priority, ownership inference) | Inference / assessment | Deliberately **excluded** from reports today; if ever added, must be a clearly labeled assessment section separate from evidence. |

### The clear path to separation

- The evidence-only CLI reports (`reports.py`) already keep observed evidence
  and confidence separate from inference: they carry no risk score, exposure
  bucket, remediation priority, or ownership inference. They are the reference
  for how the rest of the product should read.
- The Streamlit dashboard labels `Risk Score` and `HNDL Exposure` as
  inferred heuristics (**Needs Validation**), with help text distinguishing
  them from observed evidence. Rendering evidence and inference in fully
  separate labeled areas remains future UI work (HG-011 "shows evidence and
  inference separately", HG-013 color-coded exposure states). The fields stay
  marked **Needs Validation** here and in `analyzer/risk.py` so no release
  claim treats them as measured.
- When the dashboard migrates to the normalized finding model, evidence fields
  and inferred fields should render in separate, labeled areas rather than in a
  single undifferentiated table.

## Referenced by schema and report work

These terms are the shared vocabulary for downstream work and should be used
verbatim there rather than re-invented:

- The normalized finding schema ([NORMALIZED_FINDINGS.md](NORMALIZED_FINDINGS.md))
  realizes the evidence-layer terms as fields (`evidence`, `confidence`,
  `ownership_signals`, `unknowns`, `limitations`, coverage/partial-scan
  findings) and deliberately excludes assessment-layer terms from the immutable
  raw finding.
- Reports ([reports.py](../reports.py), roadmap HG-007) use the evidence-layer
  terms and keep inference/assessment terms out of evidence output.
- Confidence and false-positive/false-negative handling (roadmap HG-009) builds
  directly on the confidence, false positive, and false negative definitions
  here.
