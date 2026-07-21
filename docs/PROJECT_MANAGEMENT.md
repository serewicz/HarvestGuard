# Project Management

GitHub issues are the canonical unit of implementation work. The roadmap is
the canonical source of product direction. Architecture decisions live in ADRs.

Do not create a GitHub Project automatically unless organization, ownership,
and project settings are known. The recommended structure below can be created
manually when the maintainer is ready.

## Recommended Columns

- Backlog
- Ready
- In Progress
- Review
- Blocked
- Done

## Recommended Fields

- **Milestone:** `M1 MVP`, `M2 MVP+`, `M3 Operational`, `M4 Decision Support`
- **Priority:** `P0`, `P1`, `P2`, `P3`
- **Owner:** GitHub assignee or named maintainer/contributor
- **Work Type:** `scanner`, `schema`, `cli`, `reporting`, `dashboard`,
  `documentation`, `security`, `tests`, `operations`
- **Risk:** `low`, `medium`, `high`
- **Target Release:** planned release or `TBD`

## Recommended Workflow

1. New ideas enter `Backlog` with a clear problem statement.
2. Maintainers move issues to `Ready` only after scope, acceptance criteria,
   and dependencies are clear.
3. Contributors move approved work to `In Progress` after creating a branch.
4. Pull requests move work to `Review`.
5. Blocked issues must document the blocker and the next needed decision.
6. Done means the issue acceptance criteria and Definition of Done are met.

## Initial Labels

Recommended labels for the first seven MVP issues:

- `mvp`
- `priority:p1`
- `work:scanner`
- `work:documentation`
- `work:schema`
- `work:cli`
- `work:reporting`
- `work:tests`

Use the most specific work-type labels needed for each issue.
