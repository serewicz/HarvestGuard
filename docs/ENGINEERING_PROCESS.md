# Engineering Process

This document describes HarvestGuard's development workflow from an idea to a
closed issue and reconciled documentation. It formalizes the process used for
implementation issues, autonomous builder runs, principal reviews, closure
reviews, and roadmap/documentation reconciliation.

The process keeps product boundaries, evidence semantics, privacy, and
compatibility decisions settled before implementation starts.

## Lifecycle

```text
Idea
  -> GitHub Issue
  -> Spec Gate
  -> Claude Implementation
  -> Codex Principal Review
  -> Claude Corrections
  -> Codex Approval
  -> Merge
  -> Closure Review
  -> Documentation PR
  -> Documentation Review
  -> Done
```

Implementation issues must follow
[ISSUE_AUTHORING_STANDARD.md](ISSUE_AUTHORING_STANDARD.md).

## Idea

### Purpose

Capture a product need, field-validation defect, technical gap, or
implementation risk before it becomes code.

### Inputs

- field evidence;
- user or evaluator feedback;
- roadmap context;
- prior review findings;
- current product principles and architecture.

### Outputs

- a decision to create or update a GitHub Issue;
- or a decision that the idea is out of scope, duplicate, or premature.

### Exit Criteria

- the intended product outcome is clear enough to author an issue;
- nearby out-of-scope work is identified;
- dependencies or sequencing concerns are known.

## GitHub Issue

### Purpose

Turn the idea into the authoritative implementation contract.

### Inputs

- issue authoring standard;
- current `origin/main`;
- relevant docs, tests, and implementation files;
- product principles;
- roadmap or milestone context;
- confirmed field evidence when available.

### Outputs

- a GitHub Issue with purpose, product boundary, architecture decisions,
  compatibility contract, privacy contract, acceptance criteria, regression
  matrix, documentation requirements, and out-of-scope list.

### Exit Criteria

- the issue can stand alone as the builder contract;
- no unresolved design question remains;
- acceptance criteria are objectively testable;
- implementation boundaries are explicit.

## Spec Gate

### Purpose

Review the live GitHub Issue before implementation begins. The spec gate asks
whether two independent builders would likely implement substantially the same
behavior without scope drift.

### Inputs

- current live GitHub Issue;
- current `origin/main`;
- relevant code, tests, and documentation;
- product principles and architecture boundaries.

### Outputs

- `READY TO IMPLEMENT`; or
- `NOT READY TO IMPLEMENT` with the smallest issue-body corrections needed.

### Exit Criteria

- no blocker-level ambiguity remains;
- architecture decisions are specific enough;
- compatibility and privacy contracts are explicit;
- scope boundaries prevent likely correction cycles.

## Claude Implementation

### Purpose

Implement the approved issue contract with the smallest acceptance-relevant
change.

### Inputs

- spec-gated GitHub Issue;
- current `origin/main`;
- repository tests and documentation;
- orchestrator policy and work-budget guidance.

### Outputs

- an implementation branch;
- code, tests, and documentation required by the issue;
- validation results;
- a draft pull request.

### Exit Criteria

- issue acceptance criteria are implemented;
- focused tests and full required validation pass or failures are explained;
- no unrelated scope is added;
- PR remains draft until review is complete.

## Codex Principal Review

### Purpose

Perform an independent engineering, security, product-boundary, and
compatibility review of the exact PR head.

### Inputs

- exact PR head SHA;
- complete cumulative PR diff against current base;
- live issue contract;
- current repository behavior;
- CI and focused local probes where useful.

### Outputs

- `APPROVED`; or
- blocker, important, and follow-up findings with exact file/behavior
  references.

### Exit Criteria

- no merge blocker remains;
- important findings are either resolved or deliberately accepted;
- product and privacy boundaries remain intact.

## Claude Corrections

### Purpose

Resolve bounded review findings without broadening the issue.

### Inputs

- Codex review findings;
- current PR branch and exact reviewed SHA;
- original issue contract;
- correction-cycle policy.

### Outputs

- one correction commit per automated correction cycle;
- updated tests or documentation only where required;
- refreshed CI results;
- rereview-ready PR head.

### Exit Criteria

- the correction addresses the cited blocker or important finding;
- no second PR, force push, merge, or ready-for-review transition is created by
  automation;
- stale-SHA and protected-path checks pass;
- correction-cycle limit is respected.

## Codex Approval

### Purpose

Confirm the final PR head satisfies the issue contract and prior review
findings.

### Inputs

- exact final PR head SHA;
- complete cumulative diff;
- current issue;
- relevant tests and CI.

### Outputs

- approval statement for the exact reviewed SHA; or
- a final blocker requiring another permitted correction or human work.

### Exit Criteria

- no blocker remains;
- CI required for the PR head is green;
- the PR is ready for human merge decision.

## Merge

### Purpose

Integrate the approved implementation into `main`.

### Inputs

- approved draft or ready PR;
- green required checks;
- maintainer judgment.

### Outputs

- merged PR;
- implementation commits reachable from `origin/main`;
- issue still open until closure review confirms completion.

### Exit Criteria

- merge is complete;
- `origin/main` contains the approved implementation;
- no release or roadmap status is assumed solely from merge.

## Closure Review

### Purpose

Determine whether the original issue can actually be closed based on merged
`origin/main`, not merely PR approval.

### Inputs

- original GitHub Issue acceptance contract;
- current `origin/main`;
- merged code, tests, documentation, and CI state;
- focused local validation where useful.

### Outputs

- `READY TO CLOSE`; or
- `NOT READY TO CLOSE` with the smallest remaining closure blocker.

### Exit Criteria

- every acceptance criterion is satisfied or correctly classified as out of
  scope;
- implementation is merged and reachable from `origin/main`;
- no regression or scope violation blocks closure.

## Documentation PR

### Purpose

Reconcile planning documentation after an issue is implemented, merged,
closure-reviewed, and closed.

### Inputs

- closed issue;
- merged implementation PR;
- closure review verdict;
- current `origin/main`;
- roadmap or planning documentation requiring reconciliation.

### Outputs

- documentation-only branch;
- documentation-only commit;
- draft PR.

### Exit Criteria

- only intended documentation changed;
- implementation, tests, workflows, release files, and unrelated roadmap
  entries are untouched;
- validation passes.

## Documentation Review

### Purpose

Confirm the documentation-only reconciliation accurately records completed
work without changing product behavior or overclaiming capability.

### Inputs

- documentation PR;
- merged implementation evidence;
- issue and PR links;
- current roadmap and related docs.

### Outputs

- approval; or
- documentation correction request.

### Exit Criteria

- status, dependencies, delivered files, issue links, and PR links are
  accurate;
- no unrelated roadmap or product-claim drift exists;
- documentation PR can be merged by a maintainer.

## Done

### Purpose

Mark the work as fully complete in both implementation and planning records.

### Inputs

- merged implementation;
- closed issue;
- merged documentation reconciliation when required.

### Outputs

- repository history and planning docs agree;
- future issues can depend on the completed work.

### Exit Criteria

- issue is closed;
- roadmap or planning docs are reconciled if applicable;
- no known closure blocker remains.

## Operating Rules

- The GitHub Issue is the implementation contract after it passes spec gate.
- `origin/main` is the source of truth for current repository behavior.
- Merge does not automatically mean closure.
- Roadmap status changes happen after closure review, through a separate
  documentation-only PR when practical.
- Automation may propose, implement, and correct within policy, but humans
  remain responsible for merge, release, and product judgment.
- Missing evidence is not proof of absence, and scanner output must not
  become remediation, compliance, HNDL, quantum-readiness, or business-impact
  advice.
