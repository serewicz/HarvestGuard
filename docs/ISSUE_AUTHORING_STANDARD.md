# Issue Authoring Standard

This is the canonical authoring standard for HarvestGuard implementation
issues. Every non-trivial implementation issue must be written to this
standard before implementation begins.

The issue body is the builder contract. It should settle product boundaries,
architecture decisions, compatibility, privacy, acceptance criteria, and
regression expectations before a branch exists.

## Purpose

State the problem being solved.

Include:

- the user or evaluator pain;
- the business reason this matters;
- why this issue should happen now;
- what product outcome the work supports.

Avoid implementation detail in this section unless the problem itself is an
implementation defect.

## Product Boundary

Define exactly what is in scope.

Define exactly what is out of scope.

Include explicit non-goals. Name nearby work that must not be pulled into the
issue, especially:

- new scanner surfaces;
- schema redesign;
- report redesign;
- dashboard redesign;
- storage or database work;
- packaging or release work;
- risk, remediation, compliance, HNDL, quantum-readiness, or business-impact
  scoring;
- product-claim expansion.

If an issue is a refactor, say so plainly and require observational
equivalence.

## Architecture Decisions

Record implementation decisions that should not be rediscovered during
implementation.

Include decisions about:

- ownership of behavior or evidence;
- abstractions;
- detector or adapter models;
- compatibility boundaries;
- traversal ownership;
- accounting semantics;
- error handling;
- partial findings;
- ordering and deduplication;
- metadata allowlisting;
- privacy boundaries.

When a decision is intentionally left to implementation, state the allowable
choices and why they are equivalent for product behavior.

## Compatibility Contract

List every externally observable behavior that must remain unchanged.

At minimum consider:

- CLI commands, options, stdout, stderr, and exit codes;
- JSON shape, field names, ordering, and error behavior;
- Markdown report sections, evidence wording, and coverage language;
- DataFrame columns and legacy scanner callers;
- Streamlit/dashboard behavior;
- `finding_id` stability;
- `rule_id` stability;
- confidence values and confidence rationale;
- evidence wording;
- scanner accounting;
- summary counts;
- scanner error and partial-finding behavior.

If ordering is externally visible, define whether historical order or only
deterministic order is required.

## Privacy Contract

State the evidence-only philosophy for the issue.

List allowed metadata.

List forbidden metadata.

Call out sensitive values that must not appear in findings, JSON, Markdown,
console output, stderr, logs, artifacts, or documentation examples.

Common forbidden values include:

- plaintext;
- raw file contents;
- raw matched sensitive-data values;
- credentials;
- passphrases;
- private key material;
- encrypted key blobs when not intentionally approved;
- ciphertext payloads;
- raw provider exception payloads;
- raw parser exception payloads;
- raw config files containing secrets.

If metadata is allowed, specify whether it is source-attributed observed
evidence, technical metadata, ownership signal, unknown, limitation, or error.

## Acceptance Criteria

Acceptance criteria must be observable and objectively testable.

Each criterion should describe externally visible behavior, stable internal
contract behavior, or required documentation. Avoid vague criteria such as
"clean up implementation" or "make it better."

Use precise language:

- "produces exactly one finding";
- "preserves JSON as a bare normalized-finding array";
- "returns nonzero scanner-error exit code";
- "does not emit raw matched values";
- "records a limitation finding";
- "does not add a new `NormalizedFinding` field."

## Required Regression Matrix

Define the regression categories the implementation must cover.

Common categories:

- positive cases;
- negative cases;
- malformed input;
- boundary cases;
- misleading names or extensions;
- empty, short, unreadable, skipped, or excluded inputs;
- partial results;
- scanner execution errors;
- accounting;
- deterministic ordering;
- deduplication;
- metadata allowlisting;
- raw sensitive value exclusion;
- JSON output;
- Markdown output;
- CLI exit codes;
- DataFrame compatibility;
- Streamlit compatibility;
- existing adjacent detectors or scanners.

Regression tests should prove behavior, not merely assert constants or mock
away the path under review.

## Documentation Requirements

List exactly which documentation must change.

Explain what each document must say.

Call out documentation that must not change, such as:

- `docs/ROADMAP.md` before implementation is merged and closure-reviewed;
- `CHANGELOG.md` unless release-facing behavior changed;
- release notes unless release work is in scope;
- product claims unless the issue explicitly changes supported capability.

Documentation must not overstate coverage, certainty, remediation, compliance,
business impact, or quantum readiness.

## Out of Scope

Include a large explicit exclusion list for any nearby work that a builder
might reasonably attempt.

Examples:

- new cryptographic formats;
- new scan surfaces;
- cloud credential redesign;
- dashboard redesign;
- storage or database implementation;
- report envelope changes;
- PDF, HTML, or hosted reports;
- packaging;
- release tagging;
- workflow or orchestrator changes;
- concurrency, async, multiprocessing, or streaming rewrites;
- plugin systems or dynamic discovery;
- risk, remediation, compliance, HNDL, quantum-readiness, or business-impact
  scoring;
- unrelated cleanup.

## Implementation Guidance

Prefer the smallest implementation that satisfies the acceptance criteria.

Builders should:

- reuse existing abstractions;
- prefer additive changes;
- preserve existing behavior by default;
- add focused characterization tests before refactoring;
- make intentional behavior changes explicit;
- avoid speculative improvements;
- avoid unrelated cleanup;
- avoid dependency additions without explicit approval;
- avoid redesigning working paths;
- keep privacy and product boundaries intact.

If the issue cannot be completed within its stated boundary, stop and request
human direction instead of expanding scope.

## Definition of Ready

An implementation issue is ready only after:

- architecture decisions are finalized;
- compatibility is defined;
- acceptance criteria are complete;
- regression requirements are complete;
- scope boundaries are explicit;
- privacy expectations are explicit;
- documentation requirements are identified;
- dependencies are known;
- no open design questions remain.

If any of these are missing, the issue should go through another specification
gate before implementation begins.
