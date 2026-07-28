from __future__ import annotations

import json
from datetime import datetime, timezone

from findings import NormalizedFinding
from reports import (
    findings_json,
    format_console_summary,
    format_markdown_report,
    make_report_context,
    summarize_findings,
)


def _finding(
    source_type: str,
    asset_type: str,
    location: str,
    evidence: str = "observed",
    confidence: str = "High",
    metadata: dict | None = None,
    errors: list[str] | None = None,
    scanner_name: str = "test-scanner",
    limitations: list[str] | None = None,
    unknowns: list[str] | None = None,
    rule_id: str | None = None,
) -> NormalizedFinding:
    return NormalizedFinding(
        source_type=source_type,
        asset_type=asset_type,
        location=location,
        scanner_name=scanner_name,
        scanner_version="0.1.0",
        evidence=evidence,
        confidence=confidence,
        technical_metadata=metadata or {},
        errors=errors or [],
        limitations=limitations or [],
        unknowns=unknowns or [],
        rule_id=rule_id,
        observed_at="2026-07-20T00:00:00+00:00",
    )


def _context() -> object:
    return make_report_context(
        target_path="/scan/root",
        started_at=datetime(2026, 7, 20, tzinfo=timezone.utc),
        duration_seconds=1.25,
        excluded_paths=["vendor/*"],
        scanner_errors=[],
    )


def test_console_summary_includes_professional_totals() -> None:
    findings = [
        _finding("local_filesystem", "file", "/scan/root/cert.pem"),
        _finding(
            "crypto_inventory",
            "PEM Certificate",
            "/scan/root/cert.pem",
            metadata={"Expiration": "2020-01-01T00:00:00+00:00"},
        ),
        _finding("crypto_inventory", "Encrypted PEM Private Key", "/scan/root/key.pem"),
        _finding("crypto_inventory", "OpenSSH Private Key", "/scan/root/id_rsa"),
        _finding("crypto_inventory", "PKCS#12", "/scan/root/bundle.p12"),
        _finding("local_sensitive_data", "file", "/scan/root/secret.txt"),
        _finding("code_analysis", "source_code", "/scan/root/app.py:4"),
        _finding(
            "crypto_inventory",
            "Malformed Certificate",
            "/scan/root/bad.pem",
            errors=["parse failed"],
        ),
    ]

    summary = format_console_summary(findings, _context())

    assert "HarvestGuard Scan Complete" in summary
    assert "Files scanned: 1" in summary
    assert "Certificates: 2" in summary
    assert "Private Keys: 2" in summary
    assert "Encrypted Keys: 1" in summary
    assert "SSH Keys: 1" in summary
    assert "PKCS#12: 1" in summary
    assert "Expired Certificates: 1" in summary
    assert "Sensitive Files: 1" in summary
    assert "Semgrep Findings: 1" in summary
    assert "Malformed Assets: 1" in summary
    assert "Errors: 1" in summary
    assert "Total Findings: 8" in summary


def test_markdown_report_has_required_sections_and_evidence_fields() -> None:
    findings = [
        _finding(
            "crypto_inventory",
            "PEM Certificate",
            "/scan/root/cert.pem",
            evidence="PEM X.509 certificate parsed",
            metadata={
                "Algorithm": "RSA",
                "Key Size": 2048,
                "Expiration": "2027-01-01T00:00:00+00:00",
                "Issuer": "CN=Issuer",
                "Subject": "CN=Subject",
                "Fingerprint": "AA:BB",
            },
        )
    ]

    report = format_markdown_report(findings, _context())

    for heading in [
        "# HarvestGuard Scan Report",
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
    ]:
        assert heading in report
    assert "PEM X.509 certificate parsed" in report
    assert "CN=Issuer" in report
    assert "AA:BB" in report
    assert "business risk" in report
    assert "Executive Priority Index" not in report


def test_markdown_report_orders_findings_by_type_then_location() -> None:
    findings = [
        _finding("local_sensitive_data", "file", "/scan/root/z.txt"),
        _finding("crypto_inventory", "PEM Certificate", "/scan/root/b.pem"),
        _finding("crypto_inventory", "PEM Certificate", "/scan/root/a.pem"),
    ]

    report = format_markdown_report(findings, _context())

    assert report.index("/scan/root/a.pem") < report.index("/scan/root/b.pem")
    assert report.index("### PEM Certificate") < report.index("### file")


def test_markdown_report_handles_empty_scan() -> None:
    report = format_markdown_report([], _context())

    assert "No findings." in report
    assert "| None | None | 0 |" in report
    assert "0 cryptographic assets" in report


def test_markdown_report_preserves_malformed_errors_and_warnings() -> None:
    context = make_report_context(
        target_path="/scan/root",
        scanner_errors=["crypto inventory: permission denied"],
    )
    finding = _finding(
        "crypto_inventory",
        "Malformed Certificate",
        "/scan/root/bad.pem",
        confidence="Low",
        errors=["unable to parse certificate"],
    )

    report = format_markdown_report([finding], context)

    assert "Malformed Certificate" in report
    assert "unable to parse certificate" in report
    assert "crypto inventory: permission denied" in report
    assert "Low" in report


def test_json_output_preserves_normalized_schema() -> None:
    finding = _finding(
        "crypto_inventory",
        "PEM Certificate",
        "/scan/root/cert.pem",
        metadata={"Scanner-Specific": "preserved"},
    )

    payload = json.loads(findings_json([finding]))

    assert payload == [finding.to_dict()]
    assert payload[0]["technical_metadata"]["Scanner-Specific"] == "preserved"
    assert payload[0]["schema_version"] == "1.0.0"


def _coverage_limitation_finding(location: str, rule_id: str) -> NormalizedFinding:
    return _finding(
        "local_filesystem",
        "directory",
        location,
        evidence="Directory was not inspected because it exceeds the configured scan depth",
        rule_id=rule_id,
        limitations=[f"Not inspected: scan depth boundary reached ({rule_id})."],
        unknowns=["Encryption status beneath this directory cannot be established."],
    )


def test_markdown_report_shows_limitation_text_for_coverage_findings() -> None:
    findings = [
        _finding("local_filesystem", "file", "/scan/root/a.txt"),
        _coverage_limitation_finding("/scan/root/deep", "max_depth_boundary"),
    ]

    report = format_markdown_report(findings, _context())

    # The limitation text itself is rendered, not just a count -- a technical
    # reviewer must be able to see which scope was skipped and why.
    assert "Not inspected: scan depth boundary reached (max_depth_boundary)." in report
    assert "| Limitations |" in report
    assert "`max_depth_boundary`: 1" in report


def test_markdown_report_does_not_claim_complete_coverage_when_limited() -> None:
    findings = [
        _finding("local_filesystem", "file", "/scan/root/a.txt"),
        _coverage_limitation_finding("/scan/root/deep", "max_depth_boundary"),
    ]

    report = format_markdown_report(findings, _context())

    assert "Coverage was not complete" in report
    assert "| Coverage | Not complete |" in report
    assert "Absence of a finding is not evidence that an asset was inspected" in report
    # Coverage findings are not counted as files that were scanned.
    assert "| Files Scanned | 1 |" in report


def test_markdown_report_reports_scanner_errors_as_incomplete_coverage() -> None:
    context = make_report_context(
        target_path="/scan/root",
        scanner_errors=["s3: Error scanning S3: ClientError: ExpiredToken"],
    )

    report = format_markdown_report([_finding("aws_s3", "object", "s3://b/a.txt")], context)

    assert "Coverage was not complete" in report
    assert "1 scanner error(s)" in report
    assert "Scanner error: s3: Error scanning S3: ClientError: ExpiredToken" in report


def test_markdown_report_without_limits_states_no_limits_recorded() -> None:
    report = format_markdown_report([_finding("local_filesystem", "file", "/a.txt")], _context())

    assert "Coverage was not complete" not in report
    assert "| Coverage | No limits recorded |" in report
    assert "No scanner errors, finding-level errors, or limitations were reported." in report


def test_console_summary_states_incomplete_coverage() -> None:
    context = make_report_context(
        target_path="/scan/root", scanner_errors=["gcs: Error scanning GCS: GoogleAPIError: boom"]
    )

    summary = format_console_summary([_finding("gcs", "object", "gs://b/a.csv")], context)

    assert "Coverage was not complete" in summary
    assert "Scanner Warnings:" in summary


def test_summarize_findings_excludes_coverage_findings_from_files_scanned() -> None:
    findings = [
        _finding("local_filesystem", "file", "/scan/root/a.txt"),
        _coverage_limitation_finding("/scan/root/deep", "max_depth_boundary"),
        _finding(
            "local_filesystem",
            "special_file",
            "/scan/root/link",
            rule_id="skipped_special_file",
            limitations=["Not inspected: symbolic link skipped for safety."],
        ),
    ]

    assert summarize_findings(findings)["files_scanned"] == 1


def test_summarize_findings_counts_empty_scan() -> None:
    assert summarize_findings([]) == {
        "files_scanned": 0,
        "certificates": 0,
        "private_keys": 0,
        "encrypted_keys": 0,
        "ssh_keys": 0,
        "pkcs12": 0,
        "expired_certificates": 0,
        "sensitive_files": 0,
        "semgrep_findings": 0,
        "malformed_assets": 0,
        "errors": 0,
    }
