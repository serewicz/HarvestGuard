from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import NoCredentialsError

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
        lambda path, max_depth=3, scan_id=None: findings_by_scanner.get("filesystem", []),
    )
    monkeypatch.setattr(
        harvestguard,
        "scan_crypto_inventory_findings",
        lambda path, exclude_patterns=None: findings_by_scanner.get("crypto", []),
    )
    monkeypatch.setattr(
        harvestguard,
        "scan_filesystem_for_sensitive_data_findings",
        lambda path, max_depth=3, scan_id=None: findings_by_scanner.get("sensitive", []),
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
        lambda path, max_depth=3, scan_id=None: [
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
        lambda path, max_depth=3, scan_id=None: [],
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


# --- Argument parsing -----------------------------------------------------


def test_build_parser_scan_defaults():
    parser = harvestguard.build_parser()

    args = parser.parse_args(["scan", "target"])

    assert args.command == "scan"
    assert args.type == "all"
    assert args.max_depth == 3
    assert args.prefix == ""
    assert args.fail_on_error is True
    assert args.exclude == []


def test_build_parser_scan_type_and_options():
    parser = harvestguard.build_parser()

    args = parser.parse_args(
        ["scan", "my-bucket", "--type", "s3", "--prefix", "logs/", "--no-fail-on-error"]
    )

    assert args.type == "s3"
    assert args.prefix == "logs/"
    assert args.fail_on_error is False


def test_scan_invalid_type_is_usage_error(capsys):
    with pytest.raises(SystemExit) as excinfo:
        harvestguard.main(["scan", "target", "--type", "not-a-type"])

    assert excinfo.value.code == 2
    assert "invalid choice" in capsys.readouterr().err


def test_scan_negative_max_depth_is_usage_error(tmp_path, capsys):
    exit_code = harvestguard.main(["scan", str(tmp_path), "--max-depth", "-1"])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "--max-depth" in captured.err


# --- Scan-type selection --------------------------------------------------


def test_scan_type_filesystem_runs_only_selected_scanner(tmp_path, capsys, monkeypatch):
    called: list[str] = []

    def recorder(name, result):
        def _scanner(*args, **kwargs):
            called.append(name)
            return result

        return _scanner

    monkeypatch.setattr(
        harvestguard,
        "scan_filesystem_findings",
        recorder("filesystem", [_finding("local_filesystem", "file", str(tmp_path / "a.txt"))]),
    )
    monkeypatch.setattr(harvestguard, "scan_crypto_inventory_findings", recorder("crypto", []))
    monkeypatch.setattr(
        harvestguard, "scan_filesystem_for_sensitive_data_findings", recorder("sensitive", [])
    )
    monkeypatch.setattr(
        harvestguard, "scan_source_for_crypto_usage_findings", recorder("code", [])
    )

    exit_code = harvestguard.main(
        ["scan", str(tmp_path), "--type", "filesystem", "--json", "--quiet"]
    )

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert called == ["filesystem"]
    assert len(payload) == 1
    assert payload[0]["source_type"] == "local_filesystem"


def test_scan_type_filesystem_passes_max_depth(tmp_path, capsys, monkeypatch):
    captured: dict[str, int] = {}

    def fake_filesystem(path, max_depth=3, scan_id=None):
        captured["max_depth"] = max_depth
        return []

    monkeypatch.setattr(harvestguard, "scan_filesystem_findings", fake_filesystem)

    exit_code = harvestguard.main(
        ["scan", str(tmp_path), "--type", "filesystem", "--max-depth", "5", "--json", "--quiet"]
    )

    assert exit_code == 0
    assert captured["max_depth"] == 5


# --- Cloud scan types (mocked) --------------------------------------------


def test_scan_type_s3_invokes_s3_scanner(capsys, monkeypatch):
    captured: dict[str, str] = {}

    def fake_s3(bucket_name, prefix=""):
        captured["bucket"] = bucket_name
        captured["prefix"] = prefix
        return [_finding("aws_s3", "object", f"s3://{bucket_name}/data.txt")]

    monkeypatch.setattr(harvestguard, "scan_s3_bucket_findings", fake_s3)

    exit_code = harvestguard.main(
        ["scan", "my-bucket", "--type", "s3", "--prefix", "logs/", "--json", "--quiet"]
    )

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert captured == {"bucket": "my-bucket", "prefix": "logs/"}
    assert payload[0]["source_type"] == "aws_s3"


def test_scan_type_gcs_invokes_gcs_scanner(capsys, monkeypatch):
    captured: dict[str, str] = {}

    def fake_gcs(bucket_name, prefix=""):
        captured["bucket"] = bucket_name
        captured["prefix"] = prefix
        return [_finding("gcs", "object", f"gs://{bucket_name}/data.txt")]

    monkeypatch.setattr(harvestguard, "scan_gcs_bucket_findings", fake_gcs)

    exit_code = harvestguard.main(["scan", "my-bucket", "--type", "gcs", "--json", "--quiet"])

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert captured == {"bucket": "my-bucket", "prefix": ""}
    assert payload[0]["source_type"] == "gcs"


def test_scan_type_azure_invokes_azure_scanner(capsys, monkeypatch):
    captured: dict[str, str] = {}

    def fake_azure(account_url, container_name, prefix=""):
        captured["account_url"] = account_url
        captured["container"] = container_name
        captured["prefix"] = prefix
        return [_finding("azure_blob", "blob", f"{account_url}/{container_name}/x")]

    monkeypatch.setattr(harvestguard, "scan_azure_container_findings", fake_azure)

    exit_code = harvestguard.main(
        ["scan", "acct/container", "--type", "azure", "--json", "--quiet"]
    )

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert captured["account_url"] == "https://acct.blob.core.windows.net"
    assert captured["container"] == "container"
    assert payload[0]["source_type"] == "azure_blob"


def test_scan_type_s3_swallowed_failure_exits_error_with_valid_json(capsys, monkeypatch):
    # Exercise the real scan_s3_bucket_findings wrapper: the S3 scanner swallows
    # provider/auth errors internally, so the CLI must still surface the failure
    # as a nonzero exit code AND keep --json stdout valid (no error text prefix).
    client = MagicMock()
    client.list_objects_v2.side_effect = NoCredentialsError()
    monkeypatch.setattr("scanner.cloud.boto3.client", lambda *a, **k: client)

    exit_code = harvestguard.main(["scan", "my-bucket", "--type", "s3", "--json", "--quiet"])

    captured = capsys.readouterr()
    assert exit_code == 1
    # stdout must be parseable JSON, not "Error scanning S3: ..." + JSON.
    assert json.loads(captured.out) == []


def test_scan_type_s3_swallowed_failure_no_fail_on_error_exits_zero(capsys, monkeypatch):
    client = MagicMock()
    client.list_objects_v2.side_effect = NoCredentialsError()
    monkeypatch.setattr("scanner.cloud.boto3.client", lambda *a, **k: client)

    exit_code = harvestguard.main(
        ["scan", "my-bucket", "--type", "s3", "--json", "--quiet", "--no-fail-on-error"]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert json.loads(captured.out) == []


def test_scan_type_s3_per_object_access_denied_exits_error(capsys, monkeypatch):
    # Regression: a per-object head_object AccessDenied is a coverage gap, not a
    # clean scan. The CLI must surface it as a nonzero exit rather than emitting
    # an empty finding set and exiting 0.
    from botocore.exceptions import ClientError

    client = MagicMock()
    client.list_objects_v2.return_value = {
        "Contents": [{"Key": "data.txt", "Size": 10, "LastModified": "2026-01-01"}]
    }
    client.head_object.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied"}}, "HeadObject"
    )
    monkeypatch.setattr("scanner.cloud.boto3.client", lambda *a, **k: client)

    exit_code = harvestguard.main(["scan", "my-bucket", "--type", "s3", "--json", "--quiet"])

    captured = capsys.readouterr()
    assert exit_code == 1
    # stdout stays valid JSON; the coverage failure is not silently dropped.
    assert json.loads(captured.out) == []


def test_scan_type_azure_invalid_target_is_usage_error(capsys):
    exit_code = harvestguard.main(["scan", "no-slash", "--type", "azure", "--json"])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "account-name/container-name" in captured.err


# --- Failure behavior -----------------------------------------------------


def test_scan_no_fail_on_error_exits_zero(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(
        harvestguard,
        "scan_filesystem_findings",
        lambda path, max_depth=3, scan_id=None: (_ for _ in ()).throw(RuntimeError("boom")),
    )
    monkeypatch.setattr(
        harvestguard,
        "scan_crypto_inventory_findings",
        lambda path, exclude_patterns=None: [],
    )
    monkeypatch.setattr(
        harvestguard, "scan_filesystem_for_sensitive_data_findings", lambda *a, **k: []
    )
    monkeypatch.setattr(harvestguard, "scan_source_for_crypto_usage_findings", lambda *a, **k: [])

    exit_code = harvestguard.main(
        ["scan", str(tmp_path), "--summary", "--quiet", "--no-fail-on-error"]
    )

    output = capsys.readouterr().out
    assert exit_code == 0
    assert "Scanner Warnings:" in output


# --- Smoke tests over real temporary files --------------------------------


def test_scan_filesystem_smoke_over_temp_files(tmp_path, capsys):
    (tmp_path / "notes.txt").write_text("hello world", encoding="utf-8")

    exit_code = harvestguard.main(
        ["scan", str(tmp_path), "--type", "filesystem", "--json", "--quiet"]
    )

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert isinstance(payload, list)
    assert any(item["source_type"] == "local_filesystem" for item in payload)


def test_scan_sensitive_data_smoke_over_temp_files(tmp_path, capsys):
    (tmp_path / "contacts.txt").write_text("reach me at alice@example.com", encoding="utf-8")

    exit_code = harvestguard.main(
        ["scan", str(tmp_path), "--type", "sensitive-data", "--json", "--quiet"]
    )

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert len(payload) == 1
    assert payload[0]["source_type"] == "local_sensitive_data"
    # Privacy: the raw matched value must never appear in scan output.
    assert "alice@example.com" not in json.dumps(payload)
