# Contributing to HarvestGuard

Thanks for considering a contribution. HarvestGuard is an early-stage,
crypto-first diligence tool, so contribution discipline matters: contributors
should not need to redefine product direction before doing useful work.

Before proposing work, read:

- [Product Principles](docs/PRODUCT_PRINCIPLES.md)
- [Roadmap](docs/ROADMAP.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Architecture Decision Records](docs/DECISIONS/README.md)
- [Security Policy](SECURITY.md)

## Ground Rules

- Be respectful. See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
- Found a security issue? Do not open a public issue. See [SECURITY.md](SECURITY.md).
- Keep HarvestGuard crypto-first. Do not broaden it into a generic security
  scanner without an accepted roadmap and ADR change.
- Preserve local-first behavior and no telemetry by default.
- Separate observed evidence from inferred risk.

## Contribution Workflow

Use this workflow for all non-trivial changes:

1. **Issue:** Open or select a GitHub issue that describes the business purpose,
   user outcome, scope, out-of-scope items, acceptance criteria, and testing
   requirements.
2. **Proposed implementation approach:** Comment on the issue with the planned
   approach, files likely to change, schema or documentation impact, and any
   privacy/security considerations.
3. **Approval:** Wait for maintainer approval or clear maintainer direction
   before investing in implementation work.
4. **Branch:** Create a focused branch for the approved issue.
5. **Pull request:** Open a PR linked to the issue. Keep the PR focused on one
   logical change.
6. **Tests and documentation:** Add or update tests and documentation required
   by the issue and Definition of Done.
7. **Review:** Address review comments without expanding scope unless the
   maintainer asks for it.
8. **Merge:** Maintainers merge when the PR satisfies the issue and Definition
   of Done.

Small typo or formatting fixes may skip the full proposal step, but they should
still stay focused.

## Definition of Done

A change is done when:

- The issue acceptance criteria are satisfied.
- Relevant tests pass, and new behavior has appropriate tests.
- Scanner-facing work uses or prepares for the normalized schema.
- Errors, partial results, confidence, and limitations are visible where
  relevant.
- Local-first behavior is preserved.
- No telemetry or HarvestGuard-operated outbound service is added by default.
- Documentation is updated for user-facing, architectural, or contributor-facing
  changes.
- README claims remain accurate and do not imply unbuilt capabilities.
- The PR links to the issue it resolves.

## Getting Set Up

```bash
git clone https://github.com/serewicz/HarvestGuard.git
cd HarvestGuard

python3 -m venv venv
source venv/bin/activate    # venv\Scripts\activate on Windows

pip install -r requirements.txt
pip install -r requirements-dev.txt
```

Run the app locally:

```bash
streamlit run main.py
```

## Before Opening a PR

Run the test suite:

```bash
pytest
```

Run the linter:

```bash
ruff check .
```

Both run automatically in CI on every PR, but running them locally first saves
round-trips.

If you are touching `Dockerfile`, build and actually run it before opening a
PR. A Dockerfile that builds is not the same as one that works.

```bash
docker build -t harvestguard .
docker run --rm -p 8501:8501 --read-only --tmpfs /tmp harvestguard
```

To test the SBOM/signing flow locally (`syft`, `cosign`), sign against a local
registry rather than pushing anywhere real:

```bash
docker run -d -p 5000:5000 registry:2
docker tag harvestguard localhost:5000/harvestguard
docker push localhost:5000/harvestguard
syft localhost:5000/harvestguard -o cyclonedx-json=sbom.json
cosign generate-key-pair   # local test key only; production signing is keyless
cosign sign --key cosign.key localhost:5000/harvestguard
```

## Where to Start

The roadmap is the single source of truth:

- [Milestone 1: MVP - Trustworthy Scanner](docs/ROADMAP.md#milestone-1-mvp---trustworthy-scanner)
- [Issue-ready specs for HG-001 through HG-007](docs/issues/)

Good early contribution areas include:

- S3 scanner test coverage and pagination safety.
- Normalized finding schema design.
- CLI and JSON/Markdown report export.
- Demo target and end-to-end validation.

## Reporting Bugs or Requesting Features

Use the issue templates under `.github/ISSUE_TEMPLATE/`. Include enough detail
that someone else can reproduce or evaluate the request without back-and-forth.
Redact sensitive paths, bucket names, object names, credentials, and sample
data.
