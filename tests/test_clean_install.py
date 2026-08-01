"""A real clean-virtual-environment install of the CLI (HG-028).

The scenario these tests reproduce is a fresh technical evaluator's, not a
contributor's: clone, make a virtual environment, run one documented install
command, then use `harvestguard` from somewhere else on the machine. Nothing
here may lean on the checkout, on `requirements.txt`, on `requirements-dev.txt`,
or on whatever happens to be installed on the host -- so, unlike the packaging
fixture in `tests/test_end_to_end_validation.py`, the environment is created
*without* `--system-site-packages` and the install runs *without* `--no-deps`.
Missing dependency metadata therefore surfaces as the `ModuleNotFoundError` a
real evaluator would hit.

Both documented install forms are covered: `python -m pip install .` and
`python -m pip install -e .`.

These tests download and install real packages, so they need network access and
take longer than the rest of the suite (a few seconds with a warm pip cache,
minutes cold -- pip's resolver backtracking over the semgrep/OpenTelemetry
dependency graph is the slow part, and is normal). Set
`HARVESTGUARD_SKIP_CLEAN_INSTALL_TESTS=1` to skip them when working offline; an
install failure when they do run is a real failure, never something to skip past.

No assertion here depends on wall-clock time: scan timestamps and durations are
genuinely volatile, so the checks are on version identity, output shape, and
import provenance instead.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from harvestguard_version import __version__, version_string

REPO_ROOT = Path(__file__).resolve().parents[1]

SKIP_ENV_VAR = "HARVESTGUARD_SKIP_CLEAN_INSTALL_TESTS"

pytestmark = pytest.mark.skipif(
    os.environ.get(SKIP_ENV_VAR, "") == "1",
    reason=f"{SKIP_ENV_VAR}=1: clean-install tests need network access",
)

# Synthetic content for the scan target built outside the checkout. Matches no
# real credential shape; it exists so the scan has something to report.
SYNTHETIC_SECRET = "SYNTHETIC-CLEAN-INSTALL-SECRET-0000"


def _venv_bin(venv_dir: Path, name: str) -> Path:
    if sys.platform == "win32":
        return venv_dir / "Scripts" / f"{name}.exe"
    return venv_dir / "bin" / name


@pytest.fixture(scope="module", params=["standard", "editable"])
def clean_install(request, tmp_path_factory) -> tuple[Path, str]:
    """HarvestGuard installed into an isolated venv by dependency metadata alone.

    Returns the environment directory and which install form produced it.
    """
    venv_dir = tmp_path_factory.mktemp(f"clean-{request.param}") / "venv"
    subprocess.run(
        [sys.executable, "-m", "venv", str(venv_dir)],
        capture_output=True,
        text=True,
        timeout=300,
        check=True,
    )

    install = [str(_venv_bin(venv_dir, "python")), "-m", "pip", "install"]
    if request.param == "editable":
        install.append("--editable")
    completed = subprocess.run(
        [*install, str(REPO_ROOT)],
        capture_output=True,
        text=True,
        timeout=1800,
        check=False,
    )
    assert completed.returncode == 0, (completed.stdout + completed.stderr)[-4000:]
    return venv_dir, request.param


@pytest.fixture(scope="module")
def outside_target(tmp_path_factory) -> Path:
    """A scan target built outside the repository checkout."""
    target = tmp_path_factory.mktemp("outside") / "evaluation-target"
    (target / "config").mkdir(parents=True)
    (target / "config" / "runtime.env").write_text(
        "# Synthetic values written by the HG-028 clean-install tests. Not real.\n"
        f'PASSWORD="{SYNTHETIC_SECRET}"\n',
        encoding="utf-8",
    )
    (target / "notes.txt").write_text("plain text\n", encoding="utf-8")
    # Weak-crypto usage, so the code-analysis pass has something the vendored
    # Semgrep rules must match -- proving the rules shipped as package data.
    (target / "src").mkdir()
    (target / "src" / "hashing.py").write_text(
        "import hashlib\n\n\ndef fingerprint(value):\n    return hashlib.md5(value).hexdigest()\n",
        encoding="utf-8",
    )
    return target


def _run(venv_dir: Path, cwd: Path, *args: str) -> subprocess.CompletedProcess[str]:
    """Run the installed console script from a directory outside the checkout."""
    assert REPO_ROOT not in cwd.parents and cwd != REPO_ROOT
    return subprocess.run(
        [str(_venv_bin(venv_dir, "harvestguard")), *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )


def _assert_no_missing_module(completed: subprocess.CompletedProcess[str]) -> None:
    assert "ModuleNotFoundError" not in completed.stderr, completed.stderr[-2000:]
    assert "ModuleNotFoundError" not in completed.stdout


# --- The install itself ----------------------------------------------------


def test_clean_install_records_its_runtime_dependencies(clean_install):
    # `pip show harvestguard` reporting an empty `Requires:` list is the exact
    # field symptom HG-028 was reported for.
    venv_dir, _ = clean_install
    completed = subprocess.run(
        [str(_venv_bin(venv_dir, "python")), "-m", "pip", "show", "harvestguard"],
        capture_output=True,
        text=True,
        timeout=300,
        check=True,
    )

    requires = next(
        line.split(":", 1)[1] for line in completed.stdout.splitlines()
        if line.startswith("Requires:")
    )
    installed = {name.strip() for name in requires.split(",") if name.strip()}
    for dependency in ["pandas", "cryptography", "certifi", "semgrep", "boto3"]:
        assert dependency in installed


def test_clean_install_imports_every_packaged_module_from_outside_the_checkout(
    clean_install, tmp_path
):
    # The CLI imports all six scanners eagerly, so a single missing dependency
    # breaks every scan type, not just the one that needs it.
    venv_dir, _ = clean_install
    completed = subprocess.run(
        [
            str(_venv_bin(venv_dir, "python")),
            "-c",
            "import harvestguard, findings, finding_adapters, reports\n"
            "import scanner.filesystem, scanner.cloud, scanner.gcs, scanner.azure_blob\n"
            "import scanner.crypto_inventory\n"
            "import analyzer.risk, classifier.scanner, code_analysis.scanner\n"
            "print('ok')\n",
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )

    _assert_no_missing_module(completed)
    assert completed.returncode == 0, completed.stderr[-2000:]
    assert completed.stdout.strip() == "ok"


def test_clean_install_ships_the_semgrep_console_script(clean_install):
    # `--type code` shells out to `semgrep` off PATH, so the dependency has to
    # arrive as an executable in the environment, not merely as an import.
    venv_dir, _ = clean_install

    assert _venv_bin(venv_dir, "semgrep").exists()


def test_standard_install_resolves_outside_the_checkout(clean_install, tmp_path):
    # A non-editable install must satisfy every import from site-packages. If
    # `harvestguard` resolved back into the repository, a passing scan would
    # prove nothing about what an evaluator receives.
    venv_dir, install_form = clean_install
    completed = subprocess.run(
        [
            str(_venv_bin(venv_dir, "python")),
            "-c",
            "import harvestguard, scanner.filesystem\n"
            "print(harvestguard.__file__)\nprint(scanner.filesystem.__file__)\n",
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr[-2000:]
    locations = [Path(line) for line in completed.stdout.split()]
    if install_form == "standard":
        for location in locations:
            assert venv_dir in location.parents
            assert REPO_ROOT not in location.parents
    else:
        # An editable install is *supposed* to point back at the checkout --
        # that is what makes it editable. What matters is that it does so
        # through installed metadata rather than through the caller's cwd.
        for location in locations:
            assert REPO_ROOT in location.parents


# --- The documented CLI paths, run from outside the checkout ---------------


def test_version_flags_report_harvestguard_identity(clean_install, tmp_path):
    venv_dir, _ = clean_install

    long_flag = _run(venv_dir, tmp_path, "--version")
    short_flag = _run(venv_dir, tmp_path, "-V")

    for completed in (long_flag, short_flag):
        _assert_no_missing_module(completed)
        assert completed.returncode == 0, completed.stderr[-2000:]
        assert completed.stdout.strip() == version_string()


def test_filesystem_summary_scan_works_from_outside_the_checkout(
    clean_install, outside_target, tmp_path
):
    venv_dir, _ = clean_install

    completed = _run(
        venv_dir, tmp_path, "scan", str(outside_target), "--type", "filesystem", "--summary"
    )

    _assert_no_missing_module(completed)
    assert completed.returncode == 0, completed.stderr[-2000:]
    assert "HarvestGuard Scan Complete" in completed.stdout
    assert "Total normalized records:" in completed.stdout


def test_all_local_scanners_run_from_outside_the_checkout(
    clean_install, outside_target, tmp_path
):
    # `--type all` exercises every scanner the install has to support at once,
    # including the code-analysis pass that shells out to semgrep.
    venv_dir, _ = clean_install

    completed = _run(venv_dir, tmp_path, "scan", str(outside_target), "--type", "all", "--summary")

    _assert_no_missing_module(completed)
    assert completed.returncode == 0, completed.stderr[-2000:]
    for scanner in ["filesystem", "crypto inventory", "sensitive data", "code analysis"]:
        assert f"Running {scanner} scanner..." in completed.stderr
    # A `--type code` execution failure exits 0 and reports only to stderr
    # (docs/CLI.md, "Exit Codes"), so the exit code alone would not catch a
    # semgrep that failed to install or vendored rules that failed to ship.
    assert "Error running code analysis" not in completed.stderr
    assert "Semgrep Findings: 1" in completed.stdout


def test_json_output_remains_a_bare_array_of_normalized_findings(
    clean_install, outside_target, tmp_path
):
    venv_dir, _ = clean_install

    completed = _run(
        venv_dir, tmp_path, "scan", str(outside_target), "--type", "all", "--json", "--quiet"
    )

    _assert_no_missing_module(completed)
    assert completed.returncode == 0, completed.stderr[-2000:]
    payload = json.loads(completed.stdout)
    # A bare array, not a report envelope: no wrapper object, no run metadata.
    assert isinstance(payload, list) and payload
    for record in payload:
        assert isinstance(record, dict)
        assert record["schema_version"] == "1.0.0"
        assert record["finding_id"]
    # Sensitive-data findings report categories and counts, never the value.
    assert SYNTHETIC_SECRET not in completed.stdout


def test_markdown_report_records_the_harvestguard_version(
    clean_install, outside_target, tmp_path
):
    # Version identity is what lets a reviewer trace an evidence artifact back
    # to the release that produced it (docs/RELEASE.md).
    venv_dir, _ = clean_install

    report_path = tmp_path / "report.md"
    completed = _run(
        venv_dir,
        tmp_path,
        "scan",
        str(outside_target),
        "--type",
        "all",
        "--markdown",
        str(report_path),
        "--quiet",
    )

    _assert_no_missing_module(completed)
    assert completed.returncode == 0, completed.stderr[-2000:]
    report = report_path.read_text(encoding="utf-8")
    assert f"| HarvestGuard Version | {__version__} |" in report
    for section in ["## Executive Summary", "## Scan Information", "## Detailed Findings"]:
        assert section in report
    assert SYNTHETIC_SECRET not in report
