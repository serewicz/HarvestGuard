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

## Making changes

- Keep PRs focused — one logical change per PR is easier to review than a bundle of unrelated fixes.
- Add or update tests for any behavior change, especially in `scanner/` and `analyzer/`, since those are the modules doing the actual risk assessment.
- Update `README.md` if you change setup steps, CLI flags, or user-facing behavior.
- Reference the issue your PR addresses (`Fixes #123`) where applicable.

## Where to start

Good areas for a first contribution:

- Real encryption/algorithm detection in `scanner/filesystem.py` (currently a placeholder that returns `"Unknown"` for every file).
- Additional cloud targets in `scanner/` (Azure Blob, GCS) following the pattern in `scanner/cloud.py`.
- Export formats (CBOM JSON, PDF via `weasyprint`) referenced in the README but not yet implemented.
- Test coverage for existing modules.

Check open issues labeled `good first issue` if present, or open a new issue to discuss an idea before investing significant time — that avoids duplicate or misaligned work.

## Reporting bugs / requesting features

Use the issue templates under `.github/ISSUE_TEMPLATE/`. Include enough detail (OS, Python version, scan target, steps to reproduce) that someone else can reproduce the problem without back-and-forth.
