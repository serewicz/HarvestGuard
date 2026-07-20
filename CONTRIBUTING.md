# Contributing to HarvestGuard

Thanks for considering a contribution. HarvestGuard is an early-stage project (MVP), so there's a lot of room to shape it — from the core detection engine to the dashboard.

## Ground rules

- Be respectful. See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
- Found a security issue (not a regular bug)? Do not open a public issue — see [SECURITY.md](SECURITY.md).

## Getting set up

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

## Before opening a PR

Run the test suite:

```bash
pytest
```

Run the linter:

```bash
ruff check .
```

Both run automatically in CI on every PR, but running them locally first saves round-trips.

If you're touching `Dockerfile`, build and actually run it before opening a
PR — a Dockerfile that builds isn't the same as one that works (an unpinned
dependency version once broke the app's routing entirely inside the
container while building cleanly):

```bash
docker build -t harvestguard .
docker run --rm -p 8501:8501 --read-only --tmpfs /tmp harvestguard
```

To test the SBOM/signing flow locally (`syft`, `cosign` — install via
`brew install syft cosign` or see their docs), sign against a local
registry rather than pushing anywhere real:

```bash
docker run -d -p 5000:5000 registry:2
docker tag harvestguard localhost:5000/harvestguard
docker push localhost:5000/harvestguard
syft localhost:5000/harvestguard -o cyclonedx-json=sbom.json
cosign generate-key-pair   # local test key only -- production signing is keyless, see SECURITY.md
cosign sign --key cosign.key localhost:5000/harvestguard
```

## Making changes

- Keep PRs focused — one logical change per PR is easier to review than a bundle of unrelated fixes.
- Add or update tests for any behavior change, especially in `scanner/` and `analyzer/`, since those are the modules doing the actual risk assessment.
- Update `README.md` if you change setup steps, CLI flags, or user-facing behavior.
- Reference the issue your PR addresses (`Fixes #123`) where applicable.

## Where to start

See [docs/ROADMAP.md](docs/ROADMAP.md) for the current, maintained priority
list — it's the single source of truth, so this file doesn't try to keep a
duplicate one in sync. A few concrete, currently-open starting points:

- Test coverage for `scanner/cloud.py` (the AWS S3 scanner) — it's the one
  scanner module with zero tests today.
- Export formats (CBOM JSON targeting CycloneDX 1.6+, PDF via `weasyprint`)
  referenced in the README but not yet implemented.
- The common `ScanResult` interface described in the roadmap's Pillar 1 —
  now that three cloud scanners exist, the normalization is worth doing.

Check open issues labeled `good first issue` if present, or open a new issue to discuss an idea before investing significant time — that avoids duplicate or misaligned work.

## Reporting bugs / requesting features

Use the issue templates under `.github/ISSUE_TEMPLATE/`. Include enough detail (OS, Python version, scan target, steps to reproduce) that someone else can reproduce the problem without back-and-forth.
