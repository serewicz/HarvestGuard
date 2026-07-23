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


# --- argument parsing -------------------------------------------------------


def test_parser_defaults():
    args = harvestguard.build_parser().parse_args(["scan", "/tmp/target"])

    assert args.command == "scan"
    assert args.target == "/tmp/target"
    assert args.type == "all"
    assert args.fail_on == "error"
    assert args.max_depth is None
    assert args.prefix is None


def test_parser_rejects_unknown_scan_type():
    with pytest.raises(SystemExit) as exc:
        harvestguard.build_parser().parse_args(["scan", "/tmp/target", "--type", "bogus"])
    assert exc.value.code == 2


def test_parser_rejects_negative_max_depth():
    with pytest.raises(SystemExit) as exc:
        harvestguard.build_parser().parse_args(["scan", "/tmp/target", "--max-depth", "-1"])
    assert exc.value.code == 2


def test_parser_rejects_non_integer_max_depth():
    with pytest.raises(SystemExit) as exc:
        harvestguard.build_parser().parse_args(["scan", "/tmp/target", "--max-depth", "deep"])
    assert exc.value.code == 2


def test_no_command_prints_help_and_returns_two(capsys):
    exit_code = harvestguard.main([])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "usage" in captured.err.lower()


# --- scan type selection ----------------------------------------------------


def test_type_filesystem_runs_only_filesystem_scanner(tmp_path, capsys, monkeypatch):
    called: list[str] = []

    def _tracked(name, value):
        def scanner(path, **kwargs):
            called.append(name)
            return value

        return scanner

    monkeypatch.setattr(
        harvestguard,
        "scan_filesystem_findings",
        _tracked("filesystem", [_finding("local_filesystem", "file", str(tmp_path / "a.pem"))]),
    )
    monkeypatch.setattr(harvestguard, "scan_crypto_inventory_findings", _tracked("crypto", []))
    monkeypatch.setattr(
        harvestguard, "scan_filesystem_for_sensitive_data_findings", _tracked("sensitive", [])
    )
    monkeypatch.setattr(
        harvestguard, "scan_source_for_crypto_usage_findings", _tracked("code", [])
    )

    exit_code = harvestguard.main(
        ["scan", str(tmp_path), "--type", "filesystem", "--json", "--quiet"]
    )

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert called == ["filesystem"]
    assert len(payload) == 1


def test_type_max_depth_forwarded_to_filesystem_scanner(tmp_path, capsys, monkeypatch):
    seen: dict[str, object] = {}

    def scanner(path, max_depth=None):
        seen["max_depth"] = max_depth
        return []

    monkeypatch.setattr(harvestguard, "scan_filesystem_findings", scanner)

    exit_code = harvestguard.main(
        ["scan", str(tmp_path), "--type", "filesystem", "--max-depth", "1", "--json", "--quiet"]
    )

    assert exit_code == 0
    assert seen["max_depth"] == 1
    assert json.loads(capsys.readouterr().out) == []


# --- cloud scans (mocked) ---------------------------------------------------


def test_type_s3_calls_s3_scanner_with_prefix(capsys, monkeypatch):
    calls: dict[str, object] = {}

    def scanner(bucket, prefix=""):
        calls["bucket"] = bucket
        calls["prefix"] = prefix
        return [_finding("aws_s3", "object", "s3://bucket/data.txt")]

    monkeypatch.setattr(harvestguard, "scan_s3_bucket_findings", scanner)

    exit_code = harvestguard.main(
        ["scan", "my-bucket", "--type", "s3", "--prefix", "reports/", "--json", "--quiet"]
    )

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert calls == {"bucket": "my-bucket", "prefix": "reports/"}
    assert payload[0]["source_type"] == "aws_s3"


def test_type_gcs_calls_gcs_scanner(capsys, monkeypatch):
    def scanner(bucket, prefix=""):
        return [_finding("gcs", "object", "gs://bucket/data.txt")]

    monkeypatch.setattr(harvestguard, "scan_gcs_bucket_findings", scanner)

    exit_code = harvestguard.main(["scan", "my-bucket", "--type", "gcs", "--json", "--quiet"])

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert payload[0]["source_type"] == "gcs"


def test_type_azure_blob_parses_account_and_container(capsys, monkeypatch):
    calls: dict[str, object] = {}

    def scanner(account_url, container, prefix=""):
        calls["account_url"] = account_url
        calls["container"] = container
        return [_finding("azure_blob", "blob", "azure://container/data.txt")]

    monkeypatch.setattr(harvestguard, "scan_azure_container_findings", scanner)

    exit_code = harvestguard.main(
        ["scan", "acct/container", "--type", "azure-blob", "--json", "--quiet"]
    )

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert calls["account_url"] == "https://acct.blob.core.windows.net"
    assert calls["container"] == "container"
    assert payload[0]["source_type"] == "azure_blob"


def test_type_azure_blob_rejects_malformed_target(capsys):
    exit_code = harvestguard.main(["scan", "just-an-account", "--type", "azure-blob"])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "account/container" in captured.err


def test_cloud_scanner_failure_reports_error(capsys, monkeypatch):
    def scanner(bucket, prefix=""):
        raise RuntimeError("no credentials")

    monkeypatch.setattr(harvestguard, "scan_s3_bucket_findings", scanner)

    exit_code = harvestguard.main(["scan", "my-bucket", "--type", "s3", "--summary"])

    output = capsys.readouterr().out
    assert exit_code == 1
    assert "Scanner Warnings:" in output
    assert "s3: no credentials" in output


# --- argument-compatibility guards ------------------------------------------


def test_prefix_rejected_for_local_scan(capsys):
    exit_code = harvestguard.main(["scan", "/tmp/x", "--prefix", "foo"])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "--prefix" in captured.err


def test_max_depth_rejected_for_cloud_scan(capsys):
    exit_code = harvestguard.main(["scan", "bucket", "--type", "s3", "--max-depth", "2"])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "--max-depth" in captured.err


# --- failure behavior -------------------------------------------------------


def test_fail_on_findings_returns_one_when_findings_present(tmp_path, capsys, monkeypatch):
    _patch_local_scanners(
        monkeypatch,
        {"crypto": [_finding("crypto_inventory", "PEM Certificate", str(tmp_path / "cert.pem"))]},
    )

    exit_code = harvestguard.main(
        ["scan", str(tmp_path), "--fail-on", "findings", "--json", "--quiet"]
    )

    assert exit_code == 1
    assert len(json.loads(capsys.readouterr().out)) == 1


def test_fail_on_findings_returns_zero_when_empty(tmp_path, capsys, monkeypatch):
    _patch_local_scanners(monkeypatch, {})

    exit_code = harvestguard.main(
        ["scan", str(tmp_path), "--fail-on", "findings", "--json", "--quiet"]
    )

    assert exit_code == 0
    assert json.loads(capsys.readouterr().out) == []


def test_fail_on_never_suppresses_scanner_error_exit(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(
        harvestguard,
        "scan_filesystem_findings",
        lambda path: (_ for _ in ()).throw(RuntimeError("boom")),
    )
    monkeypatch.setattr(
        harvestguard,
        "scan_crypto_inventory_findings",
        lambda path, exclude_patterns=None: [],
    )
    monkeypatch.setattr(
        harvestguard, "scan_filesystem_for_sensitive_data_findings", lambda path: []
    )
    monkeypatch.setattr(harvestguard, "scan_source_for_crypto_usage_findings", lambda path: [])

    exit_code = harvestguard.main(
        ["scan", str(tmp_path), "--fail-on", "never", "--summary", "--quiet"]
    )

    assert exit_code == 0


# --- smoke tests with real temporary files ----------------------------------


def test_smoke_local_filesystem_scan(tmp_path, capsys):
    (tmp_path / "notes.txt").write_text("hello world", encoding="utf-8")

    exit_code = harvestguard.main(
        ["scan", str(tmp_path), "--type", "filesystem", "--json", "--quiet"]
    )

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert isinstance(payload, list)
    assert all(item["source_type"] == "local_filesystem" for item in payload)


def test_smoke_sensitive_data_scan(tmp_path, capsys):
    (tmp_path / "contacts.txt").write_text(
        "reach me at person@example.com for details", encoding="utf-8"
    )

    exit_code = harvestguard.main(
        ["scan", str(tmp_path), "--type", "sensitive-data", "--json", "--quiet"]
    )

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    locations = {item["location"] for item in payload}
    assert str(tmp_path / "contacts.txt") in locations
    assert all(item["source_type"] == "local_sensitive_data" for item in payload)
    # Evidence reports categories/counts, never the matched value itself.
    blob = json.dumps(payload)
    assert "person@example.com" not in blob
