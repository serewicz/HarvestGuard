# HarvestGuard Agent Contract (v1)

Canonical, human-readable governance for AI agents working on HarvestGuard.
The machine-readable counterpart is [`.agent-policy.yml`](../.agent-policy.yml)
at the repo root; the two must not contradict each other. Where they appear
to, this document is authoritative until reconciled.

## Purpose

HarvestGuard uses multiple AI agents as bounded engineering roles.

The system optimizes for:

> automatic execution when agents agree, human judgment when they do not.

Autonomy is bounded by authority, data sensitivity, and budget.

## Human authority

Tim is final authority.

Human approval is required for:

- merge to `main`;
- product-boundary changes;
- architecture changes;
- security tradeoffs;
- workflow/orchestration changes;
- repository permission changes;
- secrets/credential changes;
- destructive or irreversible operations;
- unresolved agent disagreements;
- meaningful scope expansion.

## Roles

### Builder

Provider/role: Claude.

May:

- read approved issue;
- work in isolated disposable workspace;
- modify its assigned branch/worktree;
- run approved development/test commands;
- commit and push ordinary source-code branches;
- open/update draft PRs;
- address agreed review findings.

May not:

- push to `main`;
- merge;
- force push;
- change secrets;
- change repository security controls;
- publish workflow changes without human approval;
- approve its own work;
- expand scope silently.

### Principal Reviewer

Provider/role: Codex.

May:

- review exact PR SHA;
- inspect code and architecture;
- run independent tests/probes;
- classify findings;
- request changes;
- re-review corrections.

Should remain independent and normally not edit the implementation.

### CISO / QA Reviewer

Provider/role: Grok.

Focus on:

- hostile input;
- credentials/secrets;
- dependency/security risk;
- privacy;
- filesystem/network behavior;
- operational failure modes;
- test gaps;
- reproducibility;
- claims beyond what the product proves.

Must not block solely for generic best practices, speculative enterprise
features, or out-of-scope architecture preferences.

## Shared source of truth

Cross-agent coordination must use:

`GitHub Issue -> PR -> exact commit SHA`

Never depend on another agent's local state.

## Workspace isolation

- canonical repo is human-controlled;
- agents use disposable worktrees/containers;
- agents may write only inside assigned workspace;
- canonical checkout is never an autonomous implementation workspace.

## Work definition

Every implementation starts from an approved issue containing:

- objective;
- scope;
- out of scope;
- acceptance criteria;
- validation requirements;
- product/security constraints.

Scope expansion requires human approval.

## Builder completion

Requires:

- implementation complete;
- Ruff clean;
- tests passing;
- relevant manual validation;
- diff reviewed;
- no unexplained scope expansion;
- draft PR created.

## Recovery checkpoints

Claude builder execution is split into two 40-turn segments. The
orchestrator must preserve complete worktree checkpoints after turn 40 and
turn 80, including tracked, staged, and untracked files and binary fixtures.
Segment 2 runs only when segment 1 exhausted its turn budget; it resumes the
same Claude session in the same workspace and branch. COMPLETE, NEEDS_HUMAN,
and non-budget failures never trigger an automatic continuation. There is no
third segment and the cumulative build budget remains 80 turns.

Each checkpoint artifact records workflow/run identity, issue, base SHA,
current HEAD and branch, NUL-safe status, separate staged and unstaged binary
patches, a hash-and-size manifest, an archive of eligible untracked files,
builder result, sanitized structured execution diagnostics and test output when
available, an executable hash verifier, and standalone recovery instructions.
Empty untracked sets are valid. Recovery must work on a fresh checkout after
the runner is gone.

Correction cycles follow the same recovery principle: if a correction Claude
run fails before publishing, the orchestrator preserves a complete worktree
checkpoint so human recovery does not depend on text-only diffs or logs.
Correction recovery also carries the correction context, including Codex
blocker input, the exact rendered correction prompt, and an explicit recovery
base equal to the reviewed PR implementation HEAD before correction.

Checkpoints exclude ignored files, virtual environments, dependencies, caches,
environment files, authentication stores, `.git`, and paths outside the
repository. Generated checkpoint text is secret-scanned before upload; binary
fixture contents are never printed to logs. Credential-like paths and
credential-shaped file contents are excluded with path-and-reason-only reports;
only files under repository `tests/**/fixtures/` receive the narrow disposable
fixture exception.

## Detector fixture discipline

When an issue requires real or official format fixtures, detector work is
fixture-first. The builder obtains them only from issue-approved official
tooling, official upstream test data, or existing provenance-documented
repository fixtures. It records source/tool, version, safe generation command
or upstream path, size, SHA-256, and artifact category, adds minimal fixture
loading tests, and confirms availability before substantive detector code.

If mandatory fixtures require unapproved installation, prohibited network
access, production credentials, or fabricated bytes where real fixtures are
required, the builder returns `NEEDS_HUMAN` before most product implementation.
The result lists exactly the missing fixtures, required provenance, and
acceptable human-supply options. Unrelated work is not forced to add fixtures.

## Review vocabulary

Use exactly:

- `BLOCKER`
- `IMPORTANT`
- `FOLLOW_UP`
- `APPROVED`

Define:

**BLOCKER**: must prevent merge.

**IMPORTANT**: normally fixed before merge.

**FOLLOW_UP**: valid issue that belongs in separate work.

**APPROVED**: no remaining blocker or important finding.

## Disagreement handling

When reviewer raises a blocker:

Builder responds:

- `AGREE`
- `DISAGREE`

If `AGREE`: builder fixes and reviewer re-reviews automatically.

If `DISAGREE`: builder provides evidence/reasoning. Reviewer reconsiders
once.

If disagreement remains: escalate to Tim.

Maximum automated correction/review cycles: 3.

## When human involvement is required

Escalate for:

- unresolved disagreement;
- product boundary;
- architecture;
- security tradeoff;
- meaningful compatibility decision;
- scope expansion;
- credential/permission change;
- budget/cycle limit exceeded;
- final merge.

## Security / credentials

- no secrets in source, prompts, issue bodies, PR comments, logs, artifacts,
  or fixtures;
- secrets only in approved secret stores;
- agents may use credentials but may not manage their own credentials;
- credentials scoped per role;
- reviewers normally read-only;
- no agent admin permissions;
- workflow/orchestration credentials human-controlled;
- credentials independently revocable;
- rotate on suspected exposure.

## External data

Default policy:

- no raw customer HarvestGuard scan data to external AI models;
- no customer-sensitive content unless explicitly approved;
- private GitHub content is not automatically approved for third-party AI
  processing.

## Cost governance

- max automated correction cycles: 3;
- max review cycles: 3;
- log provider/model, run count, duration, and estimated cost where
  available;
- no infinite review/fix loops;
- budget exhaustion escalates to human;
- use stronger/more expensive models only when risk justifies it.

Dollar budgets are intentionally not hard-coded here; that isn't agreed
elsewhere yet.

## Merge contract

No autonomous merge.

Merge readiness requires:

- builder complete;
- principal reviewer approved;
- security reviewer approved when required;
- required CI green;
- no unresolved review conversations;
- exact PR SHA reviewed;
- Tim approval.

## Required CISO review paths

Security review required when PR changes include:

- `scanner/**`
- `classifier/**`
- `code_analysis/**`
- `Dockerfile`
- `requirements*`
- `.github/**`
- `deploy/**`
- credential/auth/security code
- filesystem/network operations
- cryptography
- external parsers
