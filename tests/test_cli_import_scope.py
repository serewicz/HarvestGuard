"""`harvestguard evidence` must not import scanner dependencies (Issue #152).

`harvestguard evidence ...` reads back a previously stored scan run; it never
runs a scanner. Before this fix, `harvestguard.py` imported every scanner
module (classifier, code_analysis, scanner.*) at module scope, so merely
importing the CLI pulled in google-cloud-storage, boto3, the Azure SDKs, and
semgrep regardless of the subcommand actually requested. On Python 3.10,
google-cloud-storage's `google.api_core` prints a `FutureWarning` to stderr
the instant it is imported -- so an otherwise-successful, quiet
`evidence export` produced stderr output and broke the documented "no stderr
on success" contract (docs/CLI.md), which is what
`tests/test_clean_install.py::test_executive_exports_work_offline_from_outside_the_checkout`
caught.

Each check here runs the CLI in a subprocess and inspects the *child's* own
`sys.modules`: checking the current test process's `sys.modules` would be
contaminated by whatever other test module in the same pytest session already
imported a scanner. Running under whatever interpreter executes this test file
also means that on the Python 3.10 CI job specifically, these tests exercise
the exact interpreter version the original bug depended on.
"""

from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from evidence_store import store_scan_run
from findings import NormalizedFinding
from reports import make_report_context

ROOT = Path(__file__).parent.parent

# A `harvestguard evidence ...` command must never import any of these: the
# three cloud provider SDKs, semgrep, and every scanner implementation module
# -- whether or not that particular one happens to carry a heavy or
# warning-emitting dependency.
UNUSED_SCANNER_MODULE_PREFIXES = (
    "boto3",
    "botocore",
    "google",
    "azure",
    "semgrep",
    "scanner.filesystem",
    "scanner.cloud",
    "scanner.gcs",
    "scanner.azure_blob",
    "scanner.crypto_inventory",
    "classifier.scanner",
    "code_analysis.scanner",
)


def _finding(location: str) -> NormalizedFinding:
    return NormalizedFinding(
        source_type="local_filesystem",
        asset_type="file",
        location=location,
        scanner_name="test",
        scanner_version="0.1.0",
        evidence="observed",
        confidence="High",
    )


def _make_evidence_db(tmp_path: Path) -> tuple[Path, str]:
    """Store one synthetic run directly through the evidence store.

    Deliberately does not run a real scanner to produce this fixture: these
    tests are about what `evidence` commands import, not about scanning.
    """
    database = tmp_path / "evidence.db"
    scan_id = "cli-import-scope-test-run"
    context = make_report_context(
        target_path="/synthetic/target",
        scan_type="filesystem",
        scanners=["filesystem"],
        scanner_versions={"filesystem": "0.1.0"},
    )
    store_scan_run(
        database,
        scan_id=scan_id,
        context=context,
        findings=[_finding("/synthetic/target/a.txt")],
    )
    return database, scan_id


def _run_cli_in_subprocess(*cli_args: str) -> dict:
    """Run `harvestguard.main(cli_args)` in a fresh subprocess.

    Returns exit code, stderr, and every module name the child imported that
    matches `UNUSED_SCANNER_MODULE_PREFIXES` -- all from the child's own
    perspective.
    """
    script = textwrap.dedent(
        f"""
        import json
        import sys

        import harvestguard

        exit_code = harvestguard.main({list(cli_args)!r})
        offending = sorted(
            name for name in sys.modules if name.startswith({UNUSED_SCANNER_MODULE_PREFIXES!r})
        )
        sys.stdout.write(json.dumps({{"exit_code": exit_code, "offending": offending}}) + "\\n")
        """
    )
    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    result = json.loads(completed.stdout.strip().splitlines()[-1])
    result["stderr"] = completed.stderr
    return result


@pytest.mark.parametrize(
    "command",
    [
        pytest.param(lambda db, scan_id: ["evidence", "list", "--evidence-db", str(db)], id="list"),
        pytest.param(
            lambda db, scan_id: ["evidence", "verify", scan_id, "--evidence-db", str(db)],
            id="verify",
        ),
        pytest.param(
            lambda db, scan_id: [
                "evidence",
                "export",
                scan_id,
                "--evidence-db",
                str(db),
                "--json",
                "-",
                "--quiet",
            ],
            id="export",
        ),
    ],
)
def test_evidence_commands_do_not_import_scanner_modules(tmp_path, command):
    database, scan_id = _make_evidence_db(tmp_path)

    result = _run_cli_in_subprocess(*command(database, scan_id))

    assert result["exit_code"] == 0, result["stderr"][-2000:]
    assert result["offending"] == []


def test_quiet_executive_export_produces_no_stderr_and_no_scanner_imports(tmp_path):
    """The exact HG-152 regression: a quiet, successful executive export must
    be silent on stderr. This does not weaken or replace the equivalent
    assertion in the clean-install suite -- it adds a fast, non-network check
    that runs on every CI Python version, including 3.10.
    """
    database, scan_id = _make_evidence_db(tmp_path)
    json_destination = tmp_path / "executive.json"
    markdown_destination = tmp_path / "executive.md"

    for option, destination in (
        ("--executive-json", json_destination),
        ("--executive-markdown", markdown_destination),
    ):
        result = _run_cli_in_subprocess(
            "evidence",
            "export",
            scan_id,
            "--evidence-db",
            str(database),
            option,
            str(destination),
            "--quiet",
        )

        assert result["exit_code"] == 0, result["stderr"][-2000:]
        assert result["stderr"] == ""
        assert result["offending"] == []
        assert destination.exists()


@pytest.mark.parametrize(
    ("scan_type", "expected_module"),
    [
        ("filesystem", "scanner.filesystem"),
        ("crypto", "scanner.crypto_inventory"),
        ("sensitive-data", "classifier.scanner"),
        ("code", "code_analysis.scanner"),
    ],
)
def test_local_scan_types_load_exactly_their_own_scanner_module(
    tmp_path, scan_type, expected_module
):
    """A requested scan type must still import and successfully run its real
    scanner -- the lazy-import restructuring must not have broken any of
    them -- while every *other* local scanner module stays unimported.
    """
    target = tmp_path / "target"
    target.mkdir()
    (target / "notes.txt").write_text("plain text\n", encoding="utf-8")

    script = textwrap.dedent(
        f"""
        import json
        import sys

        import harvestguard

        exit_code = harvestguard.main(
            ["scan", {str(target)!r}, "--type", {scan_type!r}, "--summary", "--quiet"]
        )
        loaded = sorted(
            name
            for name in sys.modules
            if name.startswith((
                "scanner.filesystem",
                "scanner.crypto_inventory",
                "classifier.scanner",
                "code_analysis.scanner",
            ))
        )
        sys.stdout.write(json.dumps({{"exit_code": exit_code, "loaded": loaded}}) + "\\n")
        """
    )
    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    result = json.loads(completed.stdout.strip().splitlines()[-1])

    assert result["exit_code"] == 0, completed.stderr[-2000:]
    assert result["loaded"] == [expected_module]


@pytest.mark.parametrize(
    ("scan_type", "target", "expected_module"),
    [
        ("s3", "some-bucket", "scanner.cloud"),
        ("gcs", "some-bucket", "scanner.gcs"),
        ("azure", "account/container", "scanner.azure_blob"),
    ],
)
def test_cloud_scan_types_load_exactly_their_own_scanner_module(
    scan_type, target, expected_module
):
    """Cloud scan types import only their own provider SDK -- never the other
    two cloud SDKs, and never a local scanner.

    Builds the scanner spec directly rather than running a full scan: running
    one for real (particularly `azure`) can spend tens of seconds walking
    `DefaultAzureCredential`'s real credential chain, which is a live-network
    question this suite already covers with mocks in `tests/test_cli.py`
    (`test_scan_type_*_invokes_*_scanner`). What is under test here is import
    provenance -- that building the spec resolves and imports exactly the one
    provider SDK the requested scan type needs, without a
    `ModuleNotFoundError` and without touching either of the other two.
    """
    script = textwrap.dedent(
        f"""
        import json
        import sys

        import harvestguard

        specs, usage_error = harvestguard._cloud_scanner_specs({scan_type!r}, {target!r}, "")
        loaded = sorted(
            name
            for name in sys.modules
            if name.startswith(("scanner.cloud", "scanner.gcs", "scanner.azure_blob"))
        )
        sys.stdout.write(
            json.dumps(
                {{"usage_error": usage_error, "spec_count": len(specs or []), "loaded": loaded}}
            )
            + "\\n"
        )
        """
    )
    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert "ModuleNotFoundError" not in completed.stderr, completed.stderr[-2000:]
    result = json.loads(completed.stdout.strip().splitlines()[-1])

    assert result["usage_error"] is None, completed.stderr[-2000:]
    assert result["spec_count"] == 1
    assert result["loaded"] == [expected_module]
