"""Dependency metadata for the installed CLI stays complete and undrifted (HG-028).

`pyproject.toml`'s `[project].dependencies` is what a `pip install .` actually
resolves, so it -- not `requirements.txt` -- decides whether a fresh evaluator's
`harvestguard` command runs or dies with `ModuleNotFoundError`. These tests are
the cheap, offline half of that guarantee: they read the metadata and the
packaged source, and fail when the two disagree. The expensive half, a real
install into a clean virtual environment, lives in `tests/test_clean_install.py`.

Three drift directions are covered:

- a packaged module grows a third-party import that nothing declares;
- a shared requirement's version floor moves in one file but not the other;
- a new `requirements.txt` entry is added without classifying it as an installed
  CLI dependency or as dashboard/repository-root convenience.
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = REPO_ROOT / "pyproject.toml"
REQUIREMENTS = REPO_ROOT / "requirements.txt"

# The dependency set a `pip install .` must resolve for the documented CLI and
# every currently supported scan type. Kept as an explicit literal rather than
# derived from the source scan below, so that adding an import and adding a
# dependency stay two deliberate acts that have to agree with each other.
EXPECTED_CLI_DEPENDENCIES = {
    "pandas",
    "cryptography",
    "certifi",
    "semgrep",
    "boto3",
    "botocore",
    "google-cloud-storage",
    "google-api-core",
    "google-auth",
    "azure-storage-blob",
    "azure-identity",
    "azure-core",
}

# requirements.txt entries that are deliberately NOT installed-CLI dependencies.
# streamlit/plotly belong to the Streamlit dashboard, which is run from the
# repository root and is not packaged; the rest are declared for planned work
# (PDF export, metrics, config loading) and are imported by no packaged module
# today. Anything added to requirements.txt has to land in one list or the other.
NON_CLI_REQUIREMENTS = {
    "streamlit",
    "plotly",
    "pydantic",
    "prometheus-client",
    "python-dotenv",
    "weasyprint",
}

# Top-level modules and packages that ship in the install (pyproject's
# `py-modules` plus `packages.find`), and the repository-root-only modules that
# must never be imported by them.
PACKAGED_MODULES = (
    "harvestguard.py",
    "harvestguard_version.py",
    "findings.py",
    "finding_adapters.py",
    "reports.py",
    "evidence_store.py",
)
PACKAGED_PACKAGES = ("analyzer", "classifier", "code_analysis", "scanner")
FIRST_PARTY_NAMES = {
    "harvestguard",
    "harvestguard_version",
    "findings",
    "finding_adapters",
    "reports",
    "evidence_store",
    "analyzer",
    "classifier",
    "code_analysis",
    "scanner",
    "dashboard",
    "main",
}

# Imported dotted prefix -> the distribution that provides it. Longest prefix
# wins, so `azure.storage.blob` is attributed to azure-storage-blob rather than
# to whichever azure-* distribution happens to own the `azure` namespace root.
IMPORT_TO_DISTRIBUTION = {
    "pandas": "pandas",
    "cryptography": "cryptography",
    "certifi": "certifi",
    "boto3": "boto3",
    "botocore": "botocore",
    "azure.core": "azure-core",
    "azure.identity": "azure-identity",
    "azure.storage.blob": "azure-storage-blob",
    "google.api_core": "google-api-core",
    "google.auth": "google-auth",
    "google.cloud": "google-cloud-storage",
}


def _requirement_name(requirement: str) -> str:
    """Distribution name from a requirement line, normalized for comparison."""
    name = re.split(r"[<>=!~;\[\s]", requirement, maxsplit=1)[0]
    return name.strip().lower().replace("_", "-")


def _declared_cli_dependencies() -> list[str]:
    """`[project].dependencies` from pyproject.toml, as written."""
    text = PYPROJECT.read_text(encoding="utf-8")
    try:
        import tomllib
    except ModuleNotFoundError:  # Python 3.10 has no tomllib in the stdlib
        block = re.search(r"^dependencies = \[(.*?)^\]", text, re.DOTALL | re.MULTILINE)
        assert block is not None, "pyproject.toml must declare [project].dependencies"
        return re.findall(r'"([^"]+)"', block.group(1))
    return list(tomllib.loads(text)["project"]["dependencies"])


def _requirements_lines() -> list[str]:
    """Requirement specifiers from requirements.txt, comments stripped."""
    lines = []
    for raw in REQUIREMENTS.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            lines.append(line)
    return lines


def _packaged_source_files() -> list[Path]:
    files = [REPO_ROOT / name for name in PACKAGED_MODULES]
    for package in PACKAGED_PACKAGES:
        files.extend(sorted((REPO_ROOT / package).rglob("*.py")))
    return files


def _imported_modules(source: Path) -> set[str]:
    """Absolute dotted module paths imported by ``source``, at any nesting."""
    tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            imported.add(node.module)
    return imported


def _third_party_imports() -> dict[str, set[str]]:
    """Third-party dotted import -> the packaged files that import it."""
    third_party: dict[str, set[str]] = {}
    for source in _packaged_source_files():
        for module in _imported_modules(source):
            root = module.split(".", 1)[0]
            if root in sys.stdlib_module_names or root in FIRST_PARTY_NAMES:
                continue
            third_party.setdefault(module, set()).add(
                str(source.relative_to(REPO_ROOT))
            )
    return third_party


def _distribution_for(module: str) -> str | None:
    parts = module.split(".")
    for size in range(len(parts), 0, -1):
        prefix = ".".join(parts[:size])
        if prefix in IMPORT_TO_DISTRIBUTION:
            return IMPORT_TO_DISTRIBUTION[prefix]
    return None


# --- pyproject.toml is authoritative for the installed CLI -----------------


def test_pyproject_declares_the_installed_cli_runtime_dependencies():
    # The HG-028 defect in one assertion: an install whose `Requires:` list is
    # empty produces a `harvestguard` entry point that fails on `import pandas`.
    declared = {_requirement_name(spec) for spec in _declared_cli_dependencies()}

    assert declared == EXPECTED_CLI_DEPENDENCIES


def test_every_declared_dependency_pins_a_minimum_version():
    # A floor-less dependency is how an install silently resolves a version that
    # predates an API a scanner relies on.
    for specifier in _declared_cli_dependencies():
        assert ">=" in specifier, f"no minimum version declared for: {specifier}"


def test_declared_dependencies_do_not_include_dashboard_only_packages():
    # The Streamlit dashboard is run from the repository root, not installed.
    declared = {_requirement_name(spec) for spec in _declared_cli_dependencies()}

    assert declared.isdisjoint(NON_CLI_REQUIREMENTS)


def test_requires_python_matches_the_documented_floor():
    text = PYPROJECT.read_text(encoding="utf-8")

    assert 'requires-python = ">=3.10"' in text


# --- pyproject.toml and requirements.txt stay in step ----------------------


def test_requirements_txt_repeats_every_cli_dependency_verbatim():
    # Same distribution, same specifier: a floor raised in one file and not the
    # other means the dashboard path and the installed path resolve differently.
    requirements = {_requirement_name(line): line for line in _requirements_lines()}

    for specifier in _declared_cli_dependencies():
        name = _requirement_name(specifier)
        assert name in requirements, (
            f"{name} is declared for the CLI but missing from requirements.txt"
        )
        assert requirements[name] == specifier, (
            f"{name} drifted: pyproject.toml says {specifier!r}, "
            f"requirements.txt says {requirements[name]!r}"
        )


def test_every_requirements_txt_entry_is_classified():
    # A new requirement has to be declared for the installed CLI or recorded as
    # dashboard/repository-root convenience -- never silently neither.
    declared = {_requirement_name(spec) for spec in _declared_cli_dependencies()}
    classified = declared | NON_CLI_REQUIREMENTS

    unclassified = {
        _requirement_name(line)
        for line in _requirements_lines()
        if _requirement_name(line) not in classified
    }

    assert not unclassified, (
        f"unclassified requirements.txt entries: {sorted(unclassified)}. Add each "
        "to pyproject.toml's [project].dependencies (installed CLI) or to "
        "NON_CLI_REQUIREMENTS (dashboard/repository-root convenience)."
    )


# --- packaged source imports nothing undeclared ----------------------------


def test_every_third_party_import_in_packaged_code_is_declared():
    # The drift guard that would have caught HG-028 before an evaluator did:
    # walk what the installed modules actually import, not what a document says
    # they import.
    declared = {_requirement_name(spec) for spec in _declared_cli_dependencies()}

    undeclared: dict[str, set[str]] = {}
    for module, importers in _third_party_imports().items():
        distribution = _distribution_for(module)
        if distribution is None or distribution not in declared:
            undeclared[module] = importers

    assert not undeclared, (
        "packaged modules import third-party code that pyproject.toml does not "
        f"declare (or that IMPORT_TO_DISTRIBUTION does not map): {undeclared}"
    )


def test_packaged_code_does_not_import_the_unpackaged_dashboard():
    # `dashboard/` and `main.py` are not shipped, so importing either from a
    # packaged module would break the installed CLI while passing in a checkout.
    offenders = {
        str(source.relative_to(REPO_ROOT)): sorted(
            module
            for module in _imported_modules(source)
            if module.split(".", 1)[0] in {"dashboard", "main"}
        )
        for source in _packaged_source_files()
    }

    assert not {path: names for path, names in offenders.items() if names}


def test_semgrep_is_declared_because_the_cli_shells_out_to_it():
    # `--type code` runs the `semgrep` console script off PATH rather than
    # importing it, so no import scan can infer this one -- assert it directly.
    scanner_source = (REPO_ROOT / "code_analysis" / "scanner.py").read_text(encoding="utf-8")
    declared = {_requirement_name(spec) for spec in _declared_cli_dependencies()}

    assert 'shutil.which("semgrep")' in scanner_source
    assert "semgrep" in declared
