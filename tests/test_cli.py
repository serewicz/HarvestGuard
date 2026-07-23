from __future__ import annotations

import json

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
        lambda path: findings_by_scanner.get("filesystem", []),
    )
    monkeypatch.setattr(
        harvestguard,
        "scan_crypto_inventory_findings",
        lambda path, exclude_patterns=None: findings_by_scanner.get("crypto", []),
    )
    monkeypatch.setattr(
        harvestguard,
        "scan_filesystem_for_sensitive_data_findings",
        lambda path: findings_by_scanner.get("sensitive", []),
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
        lambda path: [_finding("local_filesystem", "file", str(tmp_path / "file.txt"))],
    )
    monkeypatch.setattr(
        harvestguard,
        "scan_crypto_inventory_findings",
        lambda path, exclude_patterns=None: (_ for _ in ()).throw(RuntimeError("boom")),
    )
    monkeypatch.setattr(
        harvestguard,
        "scan_filesystem_for_sensitive_data_findings",
        lambda path: [],
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


def test_parser_scan_defaults_to_all_local_scan():
    args = harvestguard.build_parser().parse_args(["scan", "/some/path"])
    assert args.command == "scan"
    assert args.scan_type == "all"
    assert args.prefix is None
    assert args.max_depth is None


def test_parser_accepts_every_documented_scan_type():
    parser = harvestguard.build_parser()
    for scan_type in ("filesystem", "crypto", "sensitive", "code", "s3", "gcs", "azure"):
        args = parser.parse_args(["scan", "target", "--type", scan_type])
        assert args.scan_type == scan_type


def test_parser_rejects_unknown_scan_type(capsys):
    with pytest.raises(SystemExit) as excinfo:
        harvestguard.build_parser().parse_args(["scan", "target", "--type", "nope"])
    assert excinfo.value.code == 2
    assert "invalid choice" in capsys.readouterr().err


def test_no_command_prints_help_and_returns_two(capsys):
    exit_code = harvestguard.main([])
    assert exit_code == 2
    assert "usage:" in capsys.readouterr().err


# --- Smoke tests over temporary files (no mocking) ------------------------


def test_scan_filesystem_smoke_over_temp_file(tmp_path, capsys):
    (tmp_path / "notes.txt").write_text("hello world", encoding="utf-8")

    exit_code = harvestguard.main(
        ["scan", str(tmp_path), "--type", "filesystem", "--json", "--quiet"]
    )

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert isinstance(payload, list)
    assert all(item["source_type"] == "local_filesystem" for item in payload)


def test_scan_sensitive_smoke_over_temp_file(tmp_path, capsys):
    (tmp_path / "contact.txt").write_text("reach me at test@example.com\n", encoding="utf-8")

    exit_code = harvestguard.main(
        ["scan", str(tmp_path), "--type", "sensitive", "--json", "--quiet"]
    )

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert any(item["source_type"] == "local_sensitive_data" for item in payload)


def test_scan_single_local_type_runs_only_that_scanner(tmp_path, capsys, monkeypatch):
    _patch_local_scanners(
        monkeypatch,
        {
            "filesystem": [_finding("local_filesystem", "file", str(tmp_path / "a.txt"))],
            "sensitive": [_finding("local_sensitive_data", "file", str(tmp_path / "a.txt"))],
        },
    )

    exit_code = harvestguard.main(
        ["scan", str(tmp_path), "--type", "sensitive", "--json", "--quiet"]
    )

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert [item["source_type"] for item in payload] == ["local_sensitive_data"]


def test_scan_max_depth_is_passed_to_filesystem_scanner(tmp_path, capsys, monkeypatch):
    received = {}

    def fake_filesystem(path, max_depth=3, scan_id=None):
        received["max_depth"] = max_depth
        return []

    monkeypatch.setattr(harvestguard, "scan_filesystem_findings", fake_filesystem)

    exit_code = harvestguard.main(
        ["scan", str(tmp_path), "--type", "filesystem", "--max-depth", "1", "--json", "--quiet"]
    )

    assert exit_code == 0
    assert received["max_depth"] == 1
    capsys.readouterr()


# --- Cloud scans (scanner calls mocked) -----------------------------------


def test_scan_s3_dispatches_with_prefix(capsys, monkeypatch):
    calls = {}

    def fake_s3(bucket_name, prefix="", scan_id=None):
        calls["bucket"] = bucket_name
        calls["prefix"] = prefix
        return [_finding("s3_object", "S3 Object", f"s3://{bucket_name}/data/report.csv")]

    monkeypatch.setattr(harvestguard, "scan_s3_bucket_findings", fake_s3)

    exit_code = harvestguard.main(
        ["scan", "my-bucket", "--type", "s3", "--prefix", "data/", "--json", "--quiet"]
    )

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert calls == {"bucket": "my-bucket", "prefix": "data/"}
    assert payload[0]["source_type"] == "s3_object"


def test_scan_gcs_dispatches_to_gcs_scanner(capsys, monkeypatch):
    calls = {}

    def fake_gcs(bucket_name, prefix="", scan_id=None):
        calls["bucket"] = bucket_name
        calls["prefix"] = prefix
        return []

    monkeypatch.setattr(harvestguard, "scan_gcs_bucket_findings", fake_gcs)

    exit_code = harvestguard.main(["scan", "my-gcs-bucket", "--type", "gcs", "--quiet"])

    capsys.readouterr()
    assert exit_code == 0
    assert calls == {"bucket": "my-gcs-bucket", "prefix": ""}


def test_scan_azure_parses_account_and_container(capsys, monkeypatch):
    calls = {}

    def fake_azure(account_url, container_name, prefix="", scan_id=None):
        calls["account_url"] = account_url
        calls["container"] = container_name
        calls["prefix"] = prefix
        return []

    monkeypatch.setattr(harvestguard, "scan_azure_container_findings", fake_azure)

    exit_code = harvestguard.main(
        ["scan", "myacct/mycontainer", "--type", "azure", "--prefix", "logs/", "--quiet"]
    )

    capsys.readouterr()
    assert exit_code == 0
    assert calls == {
        "account_url": "https://myacct.blob.core.windows.net",
        "container": "mycontainer",
        "prefix": "logs/",
    }


def test_scan_cloud_scanner_failure_returns_one(capsys, monkeypatch):
    def boom(bucket_name, prefix="", scan_id=None):
        raise RuntimeError("credential error")

    monkeypatch.setattr(harvestguard, "scan_s3_bucket_findings", boom)

    exit_code = harvestguard.main(["scan", "my-bucket", "--type", "s3", "--summary", "--quiet"])

    output = capsys.readouterr().out
    assert exit_code == 1
    assert "Scanner Warnings:" in output
    assert "s3: credential error" in output


# --- Invalid arguments ----------------------------------------------------


def test_scan_prefix_rejected_for_local_type(tmp_path, capsys):
    exit_code = harvestguard.main(
        ["scan", str(tmp_path), "--type", "filesystem", "--prefix", "data/"]
    )
    assert exit_code == 2
    assert "--prefix applies to cloud scan types" in capsys.readouterr().err


def test_scan_max_depth_rejected_for_cloud_type(capsys):
    exit_code = harvestguard.main(["scan", "my-bucket", "--type", "s3", "--max-depth", "2"])
    assert exit_code == 2
    assert "--max-depth applies to local scan types" in capsys.readouterr().err


def test_scan_azure_target_without_container_fails(capsys):
    exit_code = harvestguard.main(["scan", "just-account", "--type", "azure"])
    assert exit_code == 2
    assert "account/container" in capsys.readouterr().err


def test_scan_negative_max_depth_fails(tmp_path, capsys):
    exit_code = harvestguard.main(["scan", str(tmp_path), "--max-depth", "-1"])
    assert exit_code == 2
    assert "--max-depth must not be negative" in capsys.readouterr().err
