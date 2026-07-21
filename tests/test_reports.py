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
