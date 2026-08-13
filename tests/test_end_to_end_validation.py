"""End-to-end validation of the documented HarvestGuard CLI paths (HG-008).

These tests validate already-supported capabilities rather than adding scanner
breadth. They exercise the public CLI entry point -- as the `harvestguard`
console script from a real install into a throwaway virtual environment, as a
subprocess (`python -m harvestguard ...`, the documented no-install path), or
through `harvestguard.main([...])` -- so a passing run is evidence that a fresh
user following the documentation gets the documented artifacts.

Two rules shape what is mocked here:

- Local scanners are never mocked. They run against real files: the committed
  `demo/sample_target` fixture, and a representative non-demo target built at
  runtime from the crypto-inventory fixtures plus synthetic sensitive data, so
  no assertion can pass by relying on demo-only content.
- Cloud providers are faked at the **provider SDK boundary only** (`boto3`,
  `google.cloud.storage`, `azure.storage.blob`). The scanner adapters, the
  normalization layer, the report generators, and the CLI's error/exit handling
  all run for real -- mocking `scan_*_findings` itself would mock away the very
  behavior these tests claim to verify.

Coverage-status vocabulary asserted below (documented in docs/CLI.md and
docs/SCAN_COVERAGE.md): `No limits recorded` (complete), `Bounded by configured
scan scope` (limited), `Not complete` plus a "Coverage was not complete"
statement (partial or failed).
"""

from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from azure.core.exceptions import AzureError
from botocore.exceptions import ClientError
from google.api_core.exceptions import GoogleAPIError

import harvestguard

REPO_ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = REPO_ROOT / "pyproject.toml"
DEMO_TARGET = REPO_ROOT / "demo" / "sample_target"
CRYPTO_FIXTURES = REPO_ROOT / "tests" / "fixtures" / "crypto_inventory"

# Synthetic values written into the representative target at test runtime. They
# are not committed anywhere and match no real service credential shape; they
# exist so the privacy assertions below have something concrete to prove is
# absent from every output stream.
SYNTHETIC_EMAIL = "dd-reviewer@example.com"
SYNTHETIC_SECRET = "SYNTHETIC-RUNTIME-SECRET-0000"

# Section headings docs/CLI.md promises in every Markdown report.
DOCUMENTED_MARKDOWN_SECTIONS = (
    "## Executive Summary",
    "## Scan Information",
    "## Scanner Versions",
    "## Scope",
    "## Findings Summary",
    "## Finding Breakdown by Type",
    "## Detailed Findings",
    "## Errors and Warnings",
    "## Known Limitations",
    "## Appendix",
)


def _run_documented_cli(*args: str) -> subprocess.CompletedProcess[str]:
    """Run the CLI the way docs/CLI.md tells an uninstalled fresh user to."""
    return subprocess.run(
        [sys.executable, "-m", "harvestguard", *args],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )


def _venv_bin(venv_dir: Path, name: str) -> Path:
    """Path to an executable inside a virtual environment, per platform."""
    if sys.platform == "win32":
        return venv_dir / "Scripts" / f"{name}.exe"
    return venv_dir / "bin" / name


@pytest.fixture(scope="module", params=["standard", "editable"])
def installed_cli(request, tmp_path_factory) -> Path:
    """HarvestGuard really installed into a throwaway virtual environment.

    Covers both install forms docs/CLI.md documents: `pip install .` and
    `pip install -e .`. The environment is created fresh per parameter and the
    install runs through pip's real PEP 517 path, so a flat-layout discovery
    failure, a missing top-level module, a broken console-script entry point, or
    Semgrep rules that fail to ship as package data all surface here.

    Two deliberate narrowings. The venv is created with
    `--system-site-packages` and the install passes `--no-deps`, so these tests
    stay fast and offline: what they validate is HarvestGuard's own packaging --
    flat-layout discovery, the console-script entry point, package data -- not
    dependency resolution. Whether the declared dependency metadata is complete
    enough for a fresh user is a different question, and it is answered by
    `tests/test_clean_install.py`, which installs into a genuinely isolated venv
    with neither narrowing. Build isolation is skipped here when setuptools is
    already importable, purely to avoid a network round trip.
    """
    venv_dir = tmp_path_factory.mktemp(f"install-{request.param}") / "venv"
    subprocess.run(
        [sys.executable, "-m", "venv", "--system-site-packages", str(venv_dir)],
        capture_output=True,
        text=True,
        timeout=300,
        check=True,
    )

    install = [str(_venv_bin(venv_dir, "python")), "-m", "pip", "install", "--no-deps"]
    if importlib.util.find_spec("setuptools") is not None:
        install.append("--no-build-isolation")
    if request.param == "editable":
        install.append("--editable")
    completed = subprocess.run(
        [*install, str(REPO_ROOT)],
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )
    assert completed.returncode == 0, (completed.stdout + completed.stderr)[-3000:]
    return venv_dir


def _run_installed_cli(
    venv_dir: Path, cwd: Path, *args: str
) -> subprocess.CompletedProcess[str]:
    """Run the installed `harvestguard` console script from outside the repo."""
    return subprocess.run(
        [str(_venv_bin(venv_dir, "harvestguard")), *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )


@pytest.fixture(scope="module")
def representative_target(tmp_path_factory) -> Path:
    """A repository-shaped, non-demo scan target built at runtime.

    Real cryptographic assets (the committed crypto-inventory fixtures: PEM and
    DER certificates, an encrypted key, a PKCS#12 bundle, a JKS keystore, an
    SSH key pair, a malformed PEM), a source file with weak crypto usage, and a
    config file with synthetic sensitive data -- laid out like a small
    repository rather than like the demo fixture.
    """
    target = tmp_path_factory.mktemp("representative") / "acquisition-target"
    (target / "certs").mkdir(parents=True)
    for asset in sorted(CRYPTO_FIXTURES.glob("*")):
        if asset.is_file() and asset.name != "EXPECTED_OUTPUT.md":
            shutil.copy2(asset, target / "certs" / asset.name)
    # Since HG-038/HG-040, encrypted PKCS#8 and traditional Proc-Type encrypted
    # PEM are both claimed by dedicated structural detectors with no error.
    # The legacy fixture is still copied so the representative target includes
    # a real encrypted traditional PEM asset under its own rule.
    shutil.copy2(
        CRYPTO_FIXTURES / "pkcs8_encrypted" / "legacy_encrypted_rsa.pem",
        target / "certs" / "legacy_encrypted_rsa.pem",
    )
    (target / "src").mkdir()
    (target / "src" / "hashing.py").write_text(
        "import hashlib\n\n\ndef fingerprint(value):\n    return hashlib.md5(value).hexdigest()\n",
        encoding="utf-8",
    )
    (target / "config").mkdir()
    (target / "config" / "runtime.env").write_text(
        "# Synthetic values written by the HG-008 validation tests. Not real.\n"
        f"OWNER_CONTACT={SYNTHETIC_EMAIL}\n"
        f'PASSWORD="{SYNTHETIC_SECRET}"\n',
        encoding="utf-8",
    )
    return target


def _iterate_then_fail(items: list, error: Exception):
    """A provider SDK iterator that yields blobs and then fails.

    Models the partial-scan case both SDK-paging scanners document: iteration
    already yielded findings when a later page or an expired credential fails.
    """

    def generator():
        yield from items
        raise error

    return generator()


def _gcs_blob(name: str, kms_key_name: str | None = None) -> MagicMock:
    blob = MagicMock()
    blob.name = name
    blob.size = 128
    blob.updated = "2026-01-01"
    blob.kms_key_name = kms_key_name
    return blob


def _azure_blob(name: str, encryption_scope: str | None = None) -> MagicMock:
    blob = MagicMock()
    blob.name = name
    blob.size = 128
    blob.last_modified = "2026-01-01"
    blob.encryption_scope = encryption_scope
    return blob


# --- Fresh-user install and invocation ------------------------------------


def test_documented_module_invocation_produces_the_documented_demo_summary():
    # docs/CLI.md's no-install path ("python -m harvestguard scan ...") run as a
    # real subprocess from a clean shell, against the documented demo command.
    completed = _run_documented_cli(
        "scan", "demo/sample_target", "--type", "all", "--summary"
    )

    assert completed.returncode == 0, completed.stderr
    for documented_line in [
        "HarvestGuard Scan Complete",
        "Files scanned: 1",
        "Private Keys: 1",
        "Sensitive Files: 1",
        "Semgrep Findings: 0",
        "Malformed Assets: 1",
        "Errors: 1",
        "Total normalized records: 3",
    ]:
        assert documented_line in completed.stdout
    # Progress goes to stderr, so stdout stays usable on its own.
    for scanner in ["filesystem", "crypto inventory", "sensitive data", "code analysis"]:
        assert f"Running {scanner} scanner..." in completed.stderr


def test_pyproject_declares_the_documented_installable_cli():
    # Regression guard for the documented `pip install -e .` path: the flat
    # repository layout has several top-level modules and packages, so
    # setuptools' automatic discovery refuses to guess and the install fails
    # outright unless discovery and the build backend are declared explicitly.
    try:
        import tomllib
    except ModuleNotFoundError:  # Python 3.10 has no tomllib in the stdlib
        text = PYPROJECT.read_text(encoding="utf-8")
        assert "[build-system]" in text
        assert '"setuptools.build_meta"' in text
        assert 'harvestguard = "harvestguard:main"' in text
        assert "[tool.setuptools]" in text
        assert '"harvestguard"' in text
    else:
        config = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
        assert config["build-system"]["build-backend"] == "setuptools.build_meta"
        assert config["project"]["scripts"]["harvestguard"] == "harvestguard:main"
        setuptools_config = config["tool"]["setuptools"]
        assert "harvestguard" in setuptools_config["py-modules"]
        assert config["tool"]["setuptools"]["packages"]["find"]["include"]

    # The console script's target must actually exist and be callable.
    assert callable(harvestguard.main)


def test_fresh_install_exposes_the_documented_console_script(installed_cli, tmp_path):
    # The install itself is the fixture's assertion; this checks what a fresh
    # user gets afterward: a `harvestguard` executable on the environment's PATH,
    # and every module the CLI imports resolvable from *outside* the checkout
    # (run from tmp_path, so nothing can be satisfied by the repository cwd).
    assert _venv_bin(installed_cli, "harvestguard").exists()

    completed = subprocess.run(
        [
            str(_venv_bin(installed_cli, "python")),
            "-c",
            "import harvestguard, findings, finding_adapters, reports\n"
            "import scanner.filesystem, scanner.cloud, scanner.gcs, scanner.azure_blob\n"
            "import analyzer.risk, classifier.scanner, code_analysis.scanner\n"
            "print(harvestguard.main.__name__)\n",
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr[-2000:]
    assert completed.stdout.strip() == "main"


def test_installed_console_script_produces_the_documented_demo_artifacts(
    installed_cli, tmp_path
):
    # docs/CLI.md's install path, end to end: the console script (not `python -m`
    # from a checkout), invoked from a directory outside the repository, must
    # produce the documented summary, JSON, and Markdown artifacts.
    summary = _run_installed_cli(
        installed_cli, tmp_path, "scan", str(DEMO_TARGET), "--type", "all", "--summary"
    )

    assert summary.returncode == 0, summary.stderr[-2000:]
    for documented_line in [
        "HarvestGuard Scan Complete",
        "Files scanned: 1",
        "Private Keys: 1",
        "Sensitive Files: 1",
        "Semgrep Findings: 0",
        "Malformed Assets: 1",
        "Errors: 1",
        "Total normalized records: 3",
    ]:
        assert documented_line in summary.stdout

    json_run = _run_installed_cli(
        installed_cli, tmp_path, "scan", str(DEMO_TARGET), "--type", "all", "--json", "--quiet"
    )
    assert json_run.returncode == 0, json_run.stderr[-2000:]
    payload = json.loads(json_run.stdout)
    assert isinstance(payload, list) and len(payload) == 3
    assert {record["source_type"] for record in payload} == {
        "local_filesystem",
        "crypto_inventory",
        "local_sensitive_data",
    }

    markdown_run = _run_installed_cli(
        installed_cli,
        tmp_path,
        "scan",
        str(DEMO_TARGET),
        "--type",
        "all",
        "--markdown",
        "--quiet",
    )
    assert markdown_run.returncode == 0, markdown_run.stderr[-2000:]
    for section in DOCUMENTED_MARKDOWN_SECTIONS:
        assert section in markdown_run.stdout
    # The vendored Semgrep rules shipped with the install, so the code-analysis
    # scanner ran rather than erroring out on a missing rule file.
    assert "| semgrep_crypto_rules | 0.1.0 |" in markdown_run.stdout
    assert "- Scanner error:" not in markdown_run.stdout

    for stream in (summary.stdout, summary.stderr, json_run.stdout, markdown_run.stdout):
        assert "FAKE-DEMO-PASSWORD-VALUE-0000000000" not in stream


# --- Demo target through the CLI -------------------------------------------


def test_demo_summary_matches_the_documented_walkthrough(capsys):
    exit_code = harvestguard.main(
        ["scan", str(DEMO_TARGET), "--type", "all", "--summary", "--quiet"]
    )

    output = capsys.readouterr().out
    assert exit_code == 0
    # The counts docs/CLI.md's demo walkthrough prints verbatim.
    assert "Files scanned: 1" in output
    assert "Certificates: 0" in output
    assert "Private Keys: 1" in output
    assert "Sensitive Files: 1" in output
    assert "Malformed Assets: 1" in output
    assert "Errors: 1" in output
    assert "Total normalized records: 3" in output


def test_demo_json_output_is_a_valid_normalized_finding_array(capsys):
    exit_code = harvestguard.main(
        ["scan", str(DEMO_TARGET), "--type", "all", "--json", "--quiet"]
    )

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 0
    assert isinstance(payload, list) and len(payload) == 3
    assert {record["source_type"] for record in payload} == {
        "local_filesystem",
        "crypto_inventory",
        "local_sensitive_data",
    }
    assert {record["schema_version"] for record in payload} == {"1.0.0"}

    sensitive = next(r for r in payload if r["source_type"] == "local_sensitive_data")
    assert "Email" in sensitive["technical_metadata"]["Categories"]
    # Categories and counts only -- never the fixture's fake matched values.
    for stream in (captured.out, captured.err):
        assert "FAKE-DEMO-PASSWORD-VALUE-0000000000" not in stream
        assert "NOT-A-REAL-KEY-THIS-IS-FAKE-DEMO-CONTENT-ONLY-DO-NOT-USE" not in stream


def test_demo_markdown_report_contains_every_documented_section(capsys):
    exit_code = harvestguard.main(
        ["scan", str(DEMO_TARGET), "--type", "all", "--markdown", "--quiet"]
    )

    captured = capsys.readouterr()
    report = captured.out
    assert exit_code == 0
    for section in DOCUMENTED_MARKDOWN_SECTIONS:
        assert section in report
    # Every scanner the run invoked is named with its version, including the
    # code-analysis scanner that produced no findings for this fixture.
    for scanner in [
        "filesystem",
        "crypto_inventory",
        "sensitive_data_classifier",
        "semgrep_crypto_rules",
    ]:
        assert f"| {scanner} | 0.1.0 |" in report
    assert "- Scanners run: filesystem, crypto inventory, sensitive data, code analysis" in report
    # A default `--max-depth` still bounds coverage, so the demo report reads as
    # limited rather than as unlimited (docs/CLI.md, "Partial and limited scans").
    assert "| Coverage | Bounded by configured scan scope |" in report
    assert "  - Maximum directory depth: 3" in report
    for stream in (captured.out, captured.err):
        assert "FAKE-DEMO-PASSWORD-VALUE-0000000000" not in stream


# --- Representative non-demo local target ---------------------------------


def test_representative_target_all_local_scanners_emit_valid_json(
    representative_target, capsys
):
    exit_code = harvestguard.main(
        ["scan", str(representative_target), "--type", "all", "--json", "--quiet"]
    )

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    # Every local scanner contributed evidence for a target that shares nothing
    # with the demo fixture.
    assert {record["source_type"] for record in payload} == {
        "local_filesystem",
        "crypto_inventory",
        "local_sensitive_data",
        "code_analysis",
    }
    assert all(record["schema_version"] == "1.0.0" for record in payload)
    assert all(record["finding_id"] for record in payload)
    assert all(record["provenance"]["scanner_name"] for record in payload)


def test_representative_target_markdown_reports_the_real_target_and_scanners(
    representative_target, capsys
):
    exit_code = harvestguard.main(
        ["scan", str(representative_target), "--type", "all", "--markdown", "--quiet"]
    )

    captured = capsys.readouterr()
    report = captured.out
    assert exit_code == 0
    for section in DOCUMENTED_MARKDOWN_SECTIONS:
        assert section in report
    assert f"| Target Path | {representative_target} |" in report
    assert "- Scanners run: filesystem, crypto inventory, sensitive data, code analysis" in report
    assert "| PEM Certificate |" in report
    # Privacy holds on a non-demo target too: no raw matched value in either
    # stream, in the report a reviewer would actually circulate.
    for stream in (captured.out, captured.err):
        assert SYNTHETIC_SECRET not in stream
        assert SYNTHETIC_EMAIL not in stream


def test_representative_target_crypto_inventory_reports_real_asset_types(
    representative_target, capsys
):
    exit_code = harvestguard.main(
        ["scan", str(representative_target), "--type", "crypto", "--json", "--quiet"]
    )

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    asset_types = {record["asset_type"] for record in payload}
    # Real certificates and keys, not the demo fixture's single malformed PEM.
    for expected in [
        "PEM Certificate",
        "DER Certificate",
        "PEM Private Key",
        "Encrypted PKCS#8 Private Key",
        "PKCS#12 Certificate",
        "Java Keystore",
    ]:
        assert expected in asset_types
    certificate = next(r for r in payload if r["asset_type"] == "PEM Certificate")
    assert certificate["technical_metadata"]["Fingerprint"]
    assert certificate["provenance"]["scanner_name"] == "crypto_inventory"


def test_representative_target_code_analysis_reports_the_weak_hash_rule(
    representative_target, capsys
):
    exit_code = harvestguard.main(
        ["scan", str(representative_target), "--type", "code", "--json", "--quiet"]
    )

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    finding = next(r for r in payload if r["source_type"] == "code_analysis")
    assert finding["rule_id"] == "weak-hash-md5"
    assert finding["location"].endswith("src/hashing.py:5")
    assert finding["provenance"]["scanner_name"] == "semgrep_crypto_rules"


def test_representative_target_sensitive_data_reports_categories_not_values(
    representative_target, capsys
):
    json_exit = harvestguard.main(
        ["scan", str(representative_target), "--type", "sensitive-data", "--json", "--quiet"]
    )
    json_captured = capsys.readouterr()
    payload = json.loads(json_captured.out)

    markdown_exit = harvestguard.main(
        ["scan", str(representative_target), "--type", "sensitive-data", "--markdown", "--quiet"]
    )
    markdown_captured = capsys.readouterr()

    assert json_exit == 0 and markdown_exit == 0
    config_finding = next(r for r in payload if r["location"].endswith("runtime.env"))
    assert config_finding["technical_metadata"]["Categories"] == "Email, Generic Secret"
    assert config_finding["technical_metadata"]["Total Matches"] == 2
    assert "Email, Generic Secret" in markdown_captured.out

    # Category names and counts only: the synthetic email address and secret
    # written into the target must not appear in any output stream.
    for stream in (
        json_captured.out,
        json_captured.err,
        markdown_captured.out,
        markdown_captured.err,
    ):
        assert SYNTHETIC_EMAIL not in stream
        assert SYNTHETIC_SECRET not in stream


# --- Cloud scans, faked at the provider SDK boundary ----------------------


def test_s3_success_emits_valid_json_and_markdown(capsys, monkeypatch):
    client = MagicMock()
    client.list_objects_v2.return_value = {
        "Contents": [{"Key": "data.txt", "Size": 10, "LastModified": "2026-01-01"}]
    }
    client.head_object.return_value = {"ServerSideEncryption": "aws:kms"}
    monkeypatch.setattr("scanner.cloud.boto3.client", lambda *a, **k: client)

    json_exit = harvestguard.main(["scan", "my-bucket", "--type", "s3", "--json", "--quiet"])
    payload = json.loads(capsys.readouterr().out)

    markdown_exit = harvestguard.main(
        ["scan", "my-bucket", "--type", "s3", "--markdown", "--quiet"]
    )
    report = capsys.readouterr().out

    assert json_exit == 0 and markdown_exit == 0
    assert [record["location"] for record in payload] == ["s3://my-bucket/data.txt"]
    assert payload[0]["source_type"] == "aws_s3"
    assert payload[0]["technical_metadata"]["Encryption"] == "aws:kms"
    for section in DOCUMENTED_MARKDOWN_SECTIONS:
        assert section in report
    assert "s3://my-bucket/data.txt" in report
    assert "| s3 | 0.1.0 | 1 |" in report
    # No scanner error, no limitation finding, and no configured scope: the one
    # documented status that means fully complete coverage.
    assert "| Coverage | No limits recorded |" in report
    assert "No scanner errors, finding-level errors, or limitations were reported." in report


def test_gcs_success_emits_valid_json_and_markdown(capsys, monkeypatch):
    client = MagicMock()
    client.list_blobs.return_value = [
        _gcs_blob("secrets.csv", kms_key_name="projects/p/keyRings/r/cryptoKeys/k")
    ]
    monkeypatch.setattr("scanner.gcs.storage.Client", lambda *a, **k: client)

    json_exit = harvestguard.main(["scan", "my-bucket", "--type", "gcs", "--json", "--quiet"])
    payload = json.loads(capsys.readouterr().out)

    markdown_exit = harvestguard.main(
        ["scan", "my-bucket", "--type", "gcs", "--markdown", "--quiet"]
    )
    report = capsys.readouterr().out

    assert json_exit == 0 and markdown_exit == 0
    assert [record["location"] for record in payload] == ["gs://my-bucket/secrets.csv"]
    assert payload[0]["source_type"] == "gcs"
    assert payload[0]["technical_metadata"]["Encryption"] == "CMEK"
    for section in DOCUMENTED_MARKDOWN_SECTIONS:
        assert section in report
    assert "gs://my-bucket/secrets.csv" in report
    assert "| gcs | 0.1.0 | 1 |" in report
    assert "| Coverage | No limits recorded |" in report


def test_azure_success_emits_valid_json_and_markdown(capsys, monkeypatch):
    service_client = MagicMock()
    service_client.get_container_client.return_value.list_blobs.return_value = [
        _azure_blob("archive.zip", encryption_scope="my-cmk-scope")
    ]
    monkeypatch.setattr(
        "scanner.azure_blob.BlobServiceClient", lambda *a, **k: service_client
    )
    monkeypatch.setattr("scanner.azure_blob.DefaultAzureCredential", lambda *a, **k: MagicMock())

    json_exit = harvestguard.main(
        ["scan", "acct/my-container", "--type", "azure", "--json", "--quiet"]
    )
    payload = json.loads(capsys.readouterr().out)

    markdown_exit = harvestguard.main(
        ["scan", "acct/my-container", "--type", "azure", "--markdown", "--quiet"]
    )
    report = capsys.readouterr().out

    assert json_exit == 0 and markdown_exit == 0
    assert [record["location"] for record in payload] == [
        "https://acct.blob.core.windows.net/my-container/archive.zip"
    ]
    assert payload[0]["source_type"] == "azure_blob"
    assert payload[0]["technical_metadata"]["Encryption"] == (
        "Customer-managed (scope: my-cmk-scope)"
    )
    for section in DOCUMENTED_MARKDOWN_SECTIONS:
        assert section in report
    assert "| azure_blob | 0.1.0 | 1 |" in report
    assert "| Coverage | No limits recorded |" in report


def test_cloud_prefix_is_reported_as_configured_scope_not_a_failure(capsys, monkeypatch):
    client = MagicMock()
    client.list_objects_v2.return_value = {
        "Contents": [{"Key": "logs/a.txt", "Size": 10, "LastModified": "2026-01-01"}]
    }
    client.head_object.return_value = {"ServerSideEncryption": "AES256"}
    monkeypatch.setattr("scanner.cloud.boto3.client", lambda *a, **k: client)

    exit_code = harvestguard.main(
        ["scan", "my-bucket", "--type", "s3", "--prefix", "logs/", "--markdown", "--quiet"]
    )

    report = capsys.readouterr().out
    assert exit_code == 0  # a scope the user asked for is not a scanner failure
    assert "  - Object/blob prefix: logs/" in report
    assert "| Coverage | Bounded by configured scan scope |" in report
    assert "Coverage was not complete" not in report
    # The provider was asked for the narrowed listing, not filtered afterward.
    assert client.list_objects_v2.call_args.kwargs["Prefix"] == "logs/"


# --- Partial cloud scans: findings kept, failure still visible ------------


def test_gcs_partial_failure_keeps_findings_in_json_and_markdown(capsys, monkeypatch):
    def client_factory(*args, **kwargs):
        client = MagicMock()
        client.list_blobs.return_value = _iterate_then_fail(
            [_gcs_blob("page-one.csv")], GoogleAPIError("503 backend error on later page")
        )
        return client

    monkeypatch.setattr("scanner.gcs.storage.Client", client_factory)

    json_exit = harvestguard.main(["scan", "my-bucket", "--type", "gcs", "--json"])
    json_captured = capsys.readouterr()
    payload = json.loads(json_captured.out)

    markdown_exit = harvestguard.main(["scan", "my-bucket", "--type", "gcs", "--markdown"])
    markdown_captured = capsys.readouterr()
    report = markdown_captured.out

    assert json_exit == 1 and markdown_exit == 1
    # Evidence collected before the failure survives in both outputs...
    assert [record["location"] for record in payload] == ["gs://my-bucket/page-one.csv"]
    assert "gs://my-bucket/page-one.csv" in report
    # ...and the failure stays visible: stderr and exit code for JSON, the
    # Errors and Warnings section plus the coverage statement for Markdown.
    assert "Error scanning GCS" in json_captured.err
    assert "- Scanner error: gcs: Error scanning GCS" in report
    assert "Coverage was not complete" in report
    assert "| Coverage | Not complete |" in report


def test_azure_partial_failure_keeps_findings_in_json_and_markdown(capsys, monkeypatch):
    def service_factory(*args, **kwargs):
        service_client = MagicMock()
        service_client.get_container_client.return_value.list_blobs.return_value = (
            _iterate_then_fail([_azure_blob("page-one.bin")], AzureError("credential expired"))
        )
        return service_client

    monkeypatch.setattr("scanner.azure_blob.BlobServiceClient", service_factory)
    monkeypatch.setattr("scanner.azure_blob.DefaultAzureCredential", lambda *a, **k: MagicMock())

    json_exit = harvestguard.main(["scan", "acct/my-container", "--type", "azure", "--json"])
    json_captured = capsys.readouterr()
    payload = json.loads(json_captured.out)

    markdown_exit = harvestguard.main(
        ["scan", "acct/my-container", "--type", "azure", "--markdown"]
    )
    report = capsys.readouterr().out

    assert json_exit == 1 and markdown_exit == 1
    assert [record["location"] for record in payload] == [
        "https://acct.blob.core.windows.net/my-container/page-one.bin"
    ]
    assert "page-one.bin" in report
    assert "Error scanning Azure Blob" in json_captured.err
    assert "- Scanner error: azure blob: Error scanning Azure Blob" in report
    assert "| Coverage | Not complete |" in report


def test_s3_partial_failure_keeps_findings_in_json_and_markdown(capsys, monkeypatch):
    def client_factory(*args, **kwargs):
        # A fresh client per CLI invocation, so the paging side effects below are
        # replayed for the JSON run and the Markdown run alike: first page lists
        # an object and reports more to come, then the credential expires.
        client = MagicMock()
        client.list_objects_v2.side_effect = [
            {
                "Contents": [{"Key": "page-one.txt", "Size": 10, "LastModified": "2026-01-01"}],
                "IsTruncated": True,
                "NextContinuationToken": "token-1",
            },
            ClientError({"Error": {"Code": "ExpiredToken"}}, "ListObjectsV2"),
        ]
        client.head_object.return_value = {"ServerSideEncryption": "AES256"}
        return client

    monkeypatch.setattr("scanner.cloud.boto3.client", client_factory)

    json_exit = harvestguard.main(["scan", "my-bucket", "--type", "s3", "--json"])
    json_captured = capsys.readouterr()
    payload = json.loads(json_captured.out)  # must parse: no error text in stdout

    markdown_exit = harvestguard.main(["scan", "my-bucket", "--type", "s3", "--markdown"])
    markdown_captured = capsys.readouterr()
    report = markdown_captured.out

    assert json_exit == 1 and markdown_exit == 1
    # The object listed before the failure survives in both artifacts...
    assert [record["location"] for record in payload] == ["s3://my-bucket/page-one.txt"]
    assert payload[0]["technical_metadata"]["Encryption"] == "AES256"
    assert "s3://my-bucket/page-one.txt" in report
    # ...and the failure stays visible: stderr and exit code for JSON, the Errors
    # and Warnings section plus the coverage statement for Markdown.
    assert "Error scanning S3" in json_captured.err
    assert "ExpiredToken" in json_captured.err
    assert "- Scanner error: s3: Error scanning S3" in report
    assert "Coverage was not complete" in report
    assert "| Coverage | Not complete |" in report
    assert "No scanner errors, finding-level errors, or limitations were reported." not in report


def test_s3_partial_failure_summary_reports_the_warning_and_incomplete_coverage(
    capsys, monkeypatch
):
    # The console summary must carry the same truth as JSON and Markdown.
    client = MagicMock()
    client.list_objects_v2.side_effect = [
        {
            "Contents": [{"Key": "good.txt", "Size": 10, "LastModified": "2026-01-01"}],
            "IsTruncated": True,
            "NextContinuationToken": "token-1",
        },
        ClientError({"Error": {"Code": "ExpiredToken"}}, "ListObjectsV2"),
    ]
    client.head_object.return_value = {"ServerSideEncryption": "AES256"}
    monkeypatch.setattr("scanner.cloud.boto3.client", lambda *a, **k: client)

    exit_code = harvestguard.main(["scan", "my-bucket", "--type", "s3", "--summary", "--quiet"])

    output = capsys.readouterr().out
    assert exit_code == 1
    assert "Scanner Warnings:" in output
    assert "ExpiredToken" in output
    assert "Coverage was not complete" in output


# --- Scanner failures and configured limits ------------------------------


def test_local_scanner_failure_keeps_stdout_valid_json(tmp_path, capsys, monkeypatch):
    (tmp_path / "notes.txt").write_text("hello world", encoding="utf-8")
    monkeypatch.setattr(
        harvestguard,
        "scan_crypto_inventory_findings",
        lambda path, exclude_patterns=None, stats=None: (_ for _ in ()).throw(
            RuntimeError("crypto inventory exploded")
        ),
    )

    exit_code = harvestguard.main(["scan", str(tmp_path), "--type", "all", "--json"])

    captured = capsys.readouterr()
    payload = json.loads(captured.out)  # must parse: no error text mixed into stdout
    assert exit_code == 1
    assert isinstance(payload, list)
    # The scanners that did run still contribute their findings.
    assert any(record["source_type"] == "local_filesystem" for record in payload)
    assert "crypto inventory exploded" in captured.err


def test_local_scanner_failure_markdown_does_not_imply_complete_coverage(
    tmp_path, capsys, monkeypatch
):
    (tmp_path / "notes.txt").write_text("hello world", encoding="utf-8")
    monkeypatch.setattr(
        harvestguard,
        "scan_crypto_inventory_findings",
        lambda path, exclude_patterns=None, stats=None: (_ for _ in ()).throw(
            RuntimeError("crypto inventory exploded")
        ),
    )

    exit_code = harvestguard.main(["scan", str(tmp_path), "--type", "all", "--markdown", "--quiet"])

    report = capsys.readouterr().out
    assert exit_code == 1
    assert "- Scanner error: crypto inventory: crypto inventory exploded" in report
    assert "Coverage was not complete" in report
    assert "| Coverage | Not complete |" in report
    assert "No scanner errors, finding-level errors, or limitations were reported." not in report
    # The scanner that failed is still named with its version rather than
    # silently dropped, so the report cannot read as "it never ran".
    assert "| crypto_inventory | 0.1.0 | 0 |" in report


def test_configured_exclude_is_reported_as_limited_scope_not_a_failure(
    representative_target, capsys
):
    exit_code = harvestguard.main(
        [
            "scan",
            str(representative_target),
            "--type",
            "sensitive-data",
            "--exclude",
            "*.pem",
            "--markdown",
            "--quiet",
        ]
    )

    report = capsys.readouterr().out
    assert exit_code == 0  # a configured limit is not a scanner failure
    assert "| Excluded Paths | *.pem |" in report
    assert "  - Excluded patterns: *.pem" in report
    assert "  - Maximum directory depth: 3" in report
    assert "| Coverage | Bounded by configured scan scope |" in report
    assert "Coverage was not complete" not in report
    assert "valid_key.pem" not in report  # the excluded finding really is gone


def test_max_depth_boundary_is_reported_as_a_limitation_not_an_error(tmp_path, capsys):
    (tmp_path / "top.txt").write_text("hello", encoding="utf-8")
    (tmp_path / "deeper").mkdir()
    (tmp_path / "deeper" / "buried.txt").write_text("buried", encoding="utf-8")

    exit_code = harvestguard.main(
        [
            "scan",
            str(tmp_path),
            "--type",
            "filesystem",
            "--max-depth",
            "0",
            "--markdown",
            "--quiet",
        ]
    )

    report = capsys.readouterr().out
    assert exit_code == 0  # bounded, not failed
    assert "`max_depth_boundary`: 1" in report
    assert "| Coverage | Not complete |" in report
    # The distinguishing detail for a reviewer: the coverage statement counts a
    # limitation finding, and no scanner error is listed.
    assert "1 finding(s) with recorded limitations" in report
    assert "- Scanner error:" not in report


def test_finding_level_errors_are_visible_without_being_a_scanner_failure(
    representative_target, capsys
):
    # Documented reading (docs/SCAN_COVERAGE.md, "Markdown and console
    # reporting"): a per-finding `errors` entry -- an unparsable PEM, a JKS
    # entry the MVP scanner cannot read -- is an observation that partly failed,
    # not a scanner execution failure. It exits 0 and does not change the
    # Coverage row, so it must stay visible through Errors and Warnings and
    # Detailed Findings. (Traditional Proc-Type encrypted PEM is now owned by
    # HG-040 and no longer produces a passphrase-required finding-level error.)
    exit_code = harvestguard.main(
        ["scan", str(representative_target), "--type", "crypto", "--markdown", "--quiet"]
    )

    report = capsys.readouterr().out
    assert exit_code == 0
    assert "- Finding-level errors are listed in Detailed Findings." in report
    assert "JKS entry parsing is not implemented in the MVP scanner" in report
    assert "- Scanner error:" not in report
