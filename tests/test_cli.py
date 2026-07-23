from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

import harvestguard
from findings import NormalizedFinding


def _finding(
    source_type: str,
    asset_type: str,
    location: str,
    evidence: str = "observed",
    metadata: dict | None = None,
) -> NormalizedFinding:
    return NormalizedFinding(
        source_type=source_type,
        asset_type=asset_type,
        location=location,
        scanner_name="test",
        scanner_version="0.1.0",
        evidence=evidence,
        confidence="High",
        technical_metadata=metadata or {},
    )


def _patch_local_scanners(monkeypatch, findings_by_scanner):
    monkeypatch.setattr(
        harvestguard,
        "scan_filesystem_findings",
        lambda path, max_depth=3: findings_by_scanner.get("filesystem", []),
    )
    monkeypatch.setattr(
        harvestguard,
        "scan_crypto_inventory_findings",
        lambda path, exclude_patterns=None: findings_by_scanner.get("crypto", []),
    )
    monkeypatch.setattr(
        harvestguard,
        "scan_filesystem_for_sensitive_data_findings",
        lambda path, max_depth=3: findings_by_scanner.get("sensitive", []),
    )
    monkeypatch.setattr(
        harvestguard,
        "scan_source_for_crypto_usage_findings",
        lambda path: findings_by_scanner.get("code", []),
    )


def test_scan_command_summary_output(tmp_path, capsys, monkeypatch):
    findings_by_scanner = {
        "filesystem": [
            _finding("local_filesystem", "file", str(tmp_path / "cert.pem")),
            _finding("local_filesystem", "file", str(tmp_path / "secret.txt")),
        ],
        "crypto": [
            _finding(
                "crypto_inventory",
                "PEM Certificate",
                str(tmp_path / "cert.pem"),
                metadata={"Expiration": "2020-01-01T00:00:00+00:00"},
            ),
            _finding("crypto_inventory", "PEM Private Key", str(tmp_path / "key.pem")),
        ],
        "sensitive": [_finding("local_sensitive_data", "file", str(tmp_path / "secret.txt"))],
        "code": [_finding("code_analysis", "source_code", str(tmp_path / "app.py:3"))],
    }
    _patch_local_scanners(monkeypatch, findings_by_scanner)

    exit_code = harvestguard.main(["scan", str(tmp_path), "--quiet"])

    output = capsys.readouterr().out
    assert exit_code == 0
    assert "HarvestGuard Scan Complete" in output
    assert "Files scanned: 2" in output
    assert "Certificates: 1" in output
    assert "Private Keys: 1" in output
    assert "Encrypted Keys: 0" in output
    assert "SSH Keys: 0" in output
    assert "PKCS#12: 0" in output
    assert "Expired Certificates: 1" in output
    assert "Sensitive Files: 1" in output
    assert "Semgrep Findings: 1" in output
    assert "Malformed Assets: 0" in output
    assert "Total Findings: 6" in output


def test_scan_command_json_output(tmp_path, capsys, monkeypatch):
    _patch_local_scanners(
        monkeypatch,
        {"crypto": [_finding("crypto_inventory", "PEM Certificate", str(tmp_path / "cert.pem"))]},
    )

    exit_code = harvestguard.main(["scan", str(tmp_path), "--json", "--quiet"])

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert payload[0]["source_type"] == "crypto_inventory"
    assert payload[0]["schema_version"] == "1.0.0"


def test_scan_command_markdown_output(tmp_path, capsys, monkeypatch):
    _patch_local_scanners(
        monkeypatch,
        {"sensitive": [_finding("local_sensitive_data", "file", str(tmp_path / "data.csv"))]},
    )

    exit_code = harvestguard.main(["scan", str(tmp_path), "--markdown", "--quiet"])

    output = capsys.readouterr().out
    assert exit_code == 0
    assert "# HarvestGuard Scan Report" in output
    assert "## Executive Summary" in output
    assert "## Detailed Findings" in output
    assert (
        "| Location | Asset Type | Algorithm | Key Size | Expiration | Issuer | "
        "Subject | Fingerprint | Confidence | Observed Evidence | Errors |"
    ) in output
    assert str(tmp_path / "data.csv") in output


def test_scan_command_markdown_writes_report_file(tmp_path, capsys, monkeypatch):
    report_path = tmp_path / "report.md"
    _patch_local_scanners(
        monkeypatch,
        {"crypto": [_finding("crypto_inventory", "PEM Certificate", str(tmp_path / "cert.pem"))]},
    )

    exit_code = harvestguard.main([
        "scan",
        str(tmp_path),
        "--markdown",
        str(report_path),
        "--quiet",
    ])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.out == ""
    assert captured.err == ""
    assert report_path.read_text(encoding="utf-8").startswith("# HarvestGuard Scan Report")


def test_scan_command_json_writes_findings_file(tmp_path, capsys, monkeypatch):
    output_path = tmp_path / "findings.json"
    _patch_local_scanners(
        monkeypatch,
        {"crypto": [_finding("crypto_inventory", "PEM Certificate", str(tmp_path / "cert.pem"))]},
    )

    exit_code = harvestguard.main([
        "scan",
        str(tmp_path),
        "--json",
        str(output_path),
        "--quiet",
    ])

    captured = capsys.readouterr()
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert exit_code == 0
    assert captured.out == ""
    assert captured.err == ""
    assert payload[0]["source_type"] == "crypto_inventory"


def test_scan_command_invalid_path_returns_usage_error(capsys):
    exit_code = harvestguard.main(["scan", "/definitely/not/a/real/path"])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "path does not exist" in captured.err


def test_scan_command_exclude_patterns_filter_output(tmp_path, capsys, monkeypatch):
    _patch_local_scanners(
        monkeypatch,
        {
            "filesystem": [
                _finding("local_filesystem", "file", str(tmp_path / "keep.pem")),
                _finding("local_filesystem", "file", str(tmp_path / "skip.pem")),
            ],
            "crypto": [
                _finding("crypto_inventory", "PEM Certificate", str(tmp_path / "skip.pem")),
            ],
        },
    )

    exit_code = harvestguard.main(
        ["scan", str(tmp_path), "--json", "--quiet", "--exclude", "skip.pem"]
    )

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert len(payload) == 1
    assert payload[0]["asset_name"] == "keep.pem"


def test_scan_command_scanner_failure_continues(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(
        harvestguard,
        "scan_filesystem_findings",
        lambda path, max_depth=3: [
            _finding("local_filesystem", "file", str(tmp_path / "file.txt"))
        ],
    )
    monkeypatch.setattr(
        harvestguard,
        "scan_crypto_inventory_findings",
        lambda path, exclude_patterns=None: (_ for _ in ()).throw(RuntimeError("boom")),
    )
    monkeypatch.setattr(
        harvestguard,
        "scan_filesystem_for_sensitive_data_findings",
        lambda path, max_depth=3: [],
    )
    monkeypatch.setattr(
        harvestguard,
        "scan_source_for_crypto_usage_findings",
        lambda path: [],
    )

    exit_code = harvestguard.main(["scan", str(tmp_path), "--summary", "--quiet"])

    output = capsys.readouterr().out
    assert exit_code == 1
    assert "Files scanned: 1" in output
    assert "Scanner Warnings:" in output
    assert "crypto inventory: boom" in output


def test_scan_command_progress_is_suppressed_by_quiet(tmp_path, capsys, monkeypatch):
    _patch_local_scanners(monkeypatch, {"filesystem": []})

    exit_code = harvestguard.main(["scan", str(tmp_path), "--quiet"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.err == ""


def test_scan_type_filesystem_runs_only_filesystem_scanner(tmp_path, capsys, monkeypatch):
    called = {"filesystem": False, "sensitive": False, "code": False}

    def _mark(key, result):
        def _scanner(path, **_kwargs):
            called[key] = True
            return result

        return _scanner

    monkeypatch.setattr(
        harvestguard,
        "scan_filesystem_findings",
        _mark("filesystem", [_finding("local_filesystem", "file", str(tmp_path / "a.pem"))]),
    )
    monkeypatch.setattr(
        harvestguard, "scan_filesystem_for_sensitive_data_findings", _mark("sensitive", [])
    )
    monkeypatch.setattr(harvestguard, "scan_source_for_crypto_usage_findings", _mark("code", []))

    exit_code = harvestguard.main(
        ["scan", str(tmp_path), "--type", "filesystem", "--json", "--quiet"]
    )

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert len(payload) == 1
    assert called == {"filesystem": True, "sensitive": False, "code": False}


def test_scan_max_depth_is_passed_to_filesystem_scanner(tmp_path, capsys, monkeypatch):
    seen = {}

    def _scanner(path, max_depth=3):
        seen["max_depth"] = max_depth
        return []

    monkeypatch.setattr(harvestguard, "scan_filesystem_findings", _scanner)

    exit_code = harvestguard.main(
        ["scan", str(tmp_path), "--type", "filesystem", "--max-depth", "5", "--json", "--quiet"]
    )

    assert exit_code == 0
    assert seen["max_depth"] == 5


def test_scan_negative_max_depth_is_usage_error(tmp_path, capsys):
    with pytest.raises(SystemExit) as excinfo:
        harvestguard.main(["scan", str(tmp_path), "--max-depth", "-1"])

    assert excinfo.value.code == 2
    assert "max-depth" in capsys.readouterr().err


def test_scan_unknown_type_is_usage_error(tmp_path, capsys):
    with pytest.raises(SystemExit) as excinfo:
        harvestguard.main(["scan", str(tmp_path), "--type", "network"])

    assert excinfo.value.code == 2
    assert "invalid choice" in capsys.readouterr().err


def test_local_scan_smoke_with_temp_files(tmp_path, capsys):
    (tmp_path / "app.py").write_text("import os\n", encoding="utf-8")
    (tmp_path / "notes.txt").write_text("hello world\n", encoding="utf-8")

    exit_code = harvestguard.main(
        ["scan", str(tmp_path), "--type", "filesystem", "--json", "--quiet"]
    )

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert all(item["source_type"] == "local_filesystem" for item in payload)
    assert {Path(item["location"]).name for item in payload} >= {"app.py", "notes.txt"}


def test_sensitive_data_scan_smoke_with_temp_files(tmp_path, capsys):
    # A synthetic value shaped like an AWS access key id; never a real secret.
    (tmp_path / "creds.txt").write_text(
        "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n", encoding="utf-8"
    )

    exit_code = harvestguard.main(
        ["scan", str(tmp_path), "--type", "sensitive-data", "--json", "--quiet"]
    )

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert any(item["source_type"] == "local_sensitive_data" for item in payload)
    # Evidence must report categories/counts only, never the matched value.
    serialized = json.dumps(payload)
    assert "AKIAIOSFODNN7EXAMPLE" not in serialized


def test_s3_scan_mocks_scanner_and_passes_prefix(capsys, monkeypatch):
    captured_args = {}

    def _fake_s3(bucket_name, prefix="", scan_id=None):
        captured_args["bucket"] = bucket_name
        captured_args["prefix"] = prefix
        return [_finding("aws_s3", "object", f"s3://{bucket_name}/data/report.csv")]

    monkeypatch.setattr(harvestguard, "scan_s3_bucket_findings", _fake_s3)

    exit_code = harvestguard.main(
        ["scan", "acme-bucket", "--type", "s3", "--prefix", "data/", "--json", "--quiet"]
    )

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert captured_args == {"bucket": "acme-bucket", "prefix": "data/"}
    assert payload[0]["source_type"] == "aws_s3"


def test_gcs_scan_mocks_scanner(capsys, monkeypatch):
    monkeypatch.setattr(
        harvestguard,
        "scan_gcs_bucket_findings",
        lambda bucket_name, prefix="", scan_id=None: [
            _finding("gcs", "object", f"gs://{bucket_name}/obj")
        ],
    )

    exit_code = harvestguard.main(["scan", "acme-bucket", "--type", "gcs", "--json", "--quiet"])

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert payload[0]["source_type"] == "gcs"


def test_azure_blob_scan_parses_target_and_builds_account_url(capsys, monkeypatch):
    captured_args = {}

    def _fake_azure(account_url, container_name, prefix="", scan_id=None):
        captured_args["account_url"] = account_url
        captured_args["container"] = container_name
        captured_args["prefix"] = prefix
        return [_finding("azure_blob", "blob", f"{account_url}/{container_name}/b")]

    monkeypatch.setattr(harvestguard, "scan_azure_container_findings", _fake_azure)

    exit_code = harvestguard.main(
        ["scan", "acct/container", "--type", "azure-blob", "--json", "--quiet"]
    )

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert captured_args["account_url"] == "https://acct.blob.core.windows.net"
    assert captured_args["container"] == "container"
    assert payload[0]["source_type"] == "azure_blob"


def test_azure_blob_scan_invalid_target_is_usage_error(capsys, monkeypatch):
    monkeypatch.setattr(
        harvestguard,
        "scan_azure_container_findings",
        lambda *args, **kwargs: pytest.fail("scanner should not run for a malformed target"),
    )

    exit_code = harvestguard.main(["scan", "just-an-account", "--type", "azure-blob"])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "account/container" in captured.err


def test_cloud_scan_failure_is_scan_execution_error(capsys, monkeypatch):
    def _boom(bucket_name, prefix="", scan_id=None):
        raise RuntimeError("credentials unavailable")

    monkeypatch.setattr(harvestguard, "scan_s3_bucket_findings", _boom)

    exit_code = harvestguard.main(["scan", "acme-bucket", "--type", "s3", "--summary"])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "Scanner Warnings:" in captured.out
    assert "s3: credentials unavailable" in captured.out


# The following tests exercise the real scanner caught-error paths by mocking
# the provider SDKs (not the harvestguard-level wrapper), confirming that an
# SDK/auth failure produces exit code 1 and leaves --json stdout uncorrupted.


def test_s3_scan_sdk_failure_exits_one_with_clean_json(capsys, monkeypatch):
    from botocore.exceptions import NoCredentialsError

    mock_client = MagicMock()
    mock_client.list_objects_v2.side_effect = NoCredentialsError()
    monkeypatch.setattr("scanner.cloud.boto3.client", lambda *a, **k: mock_client)

    exit_code = harvestguard.main(["scan", "acme-bucket", "--type", "s3", "--json"])

    captured = capsys.readouterr()
    assert exit_code == harvestguard.EXIT_SCANNER_ERROR
    # stdout must remain valid, empty JSON -- not corrupted by the error text.
    assert json.loads(captured.out) == []
    assert "Error scanning S3" not in captured.out
    # The failure is surfaced on stderr, where it does not corrupt output.
    assert "s3 scanner failed" in captured.err


def test_gcs_scan_credentials_failure_exits_one_with_clean_json(capsys, monkeypatch):
    from google.auth.exceptions import DefaultCredentialsError

    # storage.Client() resolves credentials eagerly at construction time, so an
    # auth failure surfaces from the constructor rather than from list_blobs().
    monkeypatch.setattr(
        "scanner.gcs.storage.Client",
        MagicMock(side_effect=DefaultCredentialsError("no credentials found")),
    )

    exit_code = harvestguard.main(["scan", "acme-bucket", "--type", "gcs", "--json"])

    captured = capsys.readouterr()
    assert exit_code == harvestguard.EXIT_SCANNER_ERROR
    assert json.loads(captured.out) == []
    assert "Error scanning GCS" not in captured.out
    assert "gcs scanner failed" in captured.err


def test_azure_blob_scan_sdk_failure_exits_one_with_clean_json(capsys, monkeypatch):
    from azure.core.exceptions import ClientAuthenticationError

    mock_service = MagicMock()
    mock_service.return_value.get_container_client.return_value.list_blobs.side_effect = (
        ClientAuthenticationError("authentication failed")
    )
    monkeypatch.setattr("scanner.azure_blob.BlobServiceClient", mock_service)
    monkeypatch.setattr("scanner.azure_blob.DefaultAzureCredential", MagicMock())

    exit_code = harvestguard.main(
        ["scan", "acct/container", "--type", "azure-blob", "--json"]
    )

    captured = capsys.readouterr()
    assert exit_code == harvestguard.EXIT_SCANNER_ERROR
    assert json.loads(captured.out) == []
    assert "Error scanning Azure Blob" not in captured.out
    assert "azure blob scanner failed" in captured.err
