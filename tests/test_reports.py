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


def test_markdown_detailed_findings_include_scanner_identity_and_observed_at() -> None:
    # Provenance must be readable per finding, not only as an aggregate
    # Scanner Versions table: which scanner observed this, and when.
    findings = [
        _finding(
            "crypto_inventory",
            "PEM Certificate",
            "/scan/root/cert.pem",
            scanner_name="crypto-inventory",
        ),
        _finding(
            "code_analysis", "source_code", "/scan/root/app.py:4", scanner_name="semgrep"
        ),
    ]

    report = format_markdown_report(findings, _context())

    assert (
        "| Location | Asset Type | Scanner | Scanner Version | Observed At | "
        "Algorithm | Key Size | Expiration | Issuer | Subject | Fingerprint | "
        "Confidence | Observed Evidence | Unknowns | Limitations | Errors |"
    ) in report
    assert (
        "| /scan/root/cert.pem | PEM Certificate | crypto-inventory | 0.1.0 | "
        "2026-07-20T00:00:00+00:00 |"
    ) in report
    assert (
        "| /scan/root/app.py:4 | source_code | semgrep | 0.1.0 | "
        "2026-07-20T00:00:00+00:00 |"
    ) in report


def test_markdown_scope_lists_only_the_scanners_that_ran() -> None:
    context = make_report_context(
        target_path="/scan/root",
        scan_type="filesystem",
        scanners=["filesystem"],
        scope_constraints=["Maximum directory depth: 3"],
    )

    report = format_markdown_report(
        [_finding("local_filesystem", "file", "/scan/root/a.txt")], context
    )

    assert "- Scan type: `filesystem`" in report
    assert "- Scanners run: filesystem" in report
    assert "  - Maximum directory depth: 3" in report
    # A single-scanner run must not claim the other local scanners ran.
    for absent in ["crypto inventory", "sensitive data", "code analysis"]:
        assert absent not in report


def test_markdown_scope_states_scanners_not_recorded_when_context_omits_them() -> None:
    report = format_markdown_report(
        [_finding("local_filesystem", "file", "/scan/root/a.txt")], _context()
    )

    assert "- Scanners run: Not recorded" in report


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


def test_markdown_report_renders_unknowns_alongside_limitations_and_errors() -> None:
    # Unknowns are what HarvestGuard could not establish at all; a reviewer has
    # to see them next to the observation they qualify, not only in JSON.
    finding = _finding(
        "local_filesystem",
        "file",
        "/scan/root/notes.txt",
        confidence="Low",
        errors=["stat failed"],
        limitations=["Volume-level fallback used."],
        unknowns=[
            "Business ownership cannot be established from filesystem metadata.",
            "File-level encryption status cannot be established conclusively.",
        ],
    )

    report = format_markdown_report([finding], _context())

    assert "| Unknowns |" in report
    assert "Business ownership cannot be established from filesystem metadata." in report
    assert "File-level encryption status cannot be established conclusively." in report
    assert "Volume-level fallback used." in report
    assert "stat failed" in report


def test_markdown_report_adds_no_risk_or_remediation_language() -> None:
    findings = [
        _finding("local_filesystem", "file", "/scan/root/a.txt"),
        _coverage_limitation_finding("/scan/root/deep", "max_depth_boundary"),
    ]

    report = format_markdown_report(findings, _context())

    # The Known Limitations section states what is *not* included; every other
    # mention of these concepts would be an inference the product boundary
    # (ADR-005/ADR-006) keeps out of evidence reports.
    boundary_statement = (
        "- No risk scores, executive priority, remediation recommendations, or ownership "
        "inference are included."
    )
    assert boundary_statement in report
    remainder = report.replace(boundary_statement, "")
    for term in [
        "Risk Score",
        "HNDL",
        "Exposure Probability",
        "Remediation",
        "Recommendation",
        "Business Impact",
        "Compliance",
        "Quantum",
        "Executive Priority",
    ]:
        assert term.lower() not in remainder.lower()


def test_markdown_report_sensitive_data_finding_shows_categories_not_values() -> None:
    # Mirrors the classifier adapter's shape: categories and counts only.
    finding = _finding(
        "local_sensitive_data",
        "file",
        "/scan/root/contacts.csv",
        evidence="Sensitive data categories detected: Email, Phone; total matches: 4",
        confidence="Medium",
        metadata={"Categories": "Email, Phone", "Total Matches": 4},
    )

    report = format_markdown_report([finding], _context())

    assert "Sensitive data categories detected: Email, Phone; total matches: 4" in report
    assert "| Sensitive Files | 1 |" in report


def test_markdown_scanner_version_rows_are_deterministically_ordered() -> None:
    findings = [
        _finding("code_analysis", "source_code", "/scan/root/app.py:2", scanner_name="semgrep"),
        _finding("local_filesystem", "file", "/scan/root/a.txt", scanner_name="filesystem"),
        _finding("crypto_inventory", "PEM Certificate", "/scan/root/a.pem", scanner_name="crypto"),
        _finding("local_filesystem", "file", "/scan/root/b.txt", scanner_name="filesystem"),
    ]

    report = format_markdown_report(findings, _context())

    assert "| crypto | 0.1.0 | 1 |" in report
    assert "| filesystem | 0.1.0 | 2 |" in report
    assert "| semgrep | 0.1.0 | 1 |" in report
    assert report.index("| crypto | ") < report.index("| filesystem | ") < report.index(
        "| semgrep | "
    )


def test_markdown_scanner_versions_include_scanners_that_found_nothing() -> None:
    # A scanner that ran and found nothing is evidence too: omitting it would
    # hide both its version and the fact that it ran at all.
    context = make_report_context(
        target_path="/scan/root",
        scanners=["filesystem", "code analysis"],
        scanner_versions={"filesystem": "0.1.0", "semgrep_crypto_rules": "0.2.0"},
    )

    report = format_markdown_report(
        [_finding("local_filesystem", "file", "/scan/root/a.txt", scanner_name="filesystem")],
        context,
    )

    assert "| filesystem | 0.1.0 | 1 |" in report
    assert "| semgrep_crypto_rules | 0.2.0 | 0 |" in report
    assert "| None | None | 0 |" not in report


def test_markdown_scanner_versions_include_a_scanner_that_failed_outright() -> None:
    # The scanner failed before producing anything; its version and the fact
    # that it was invoked must still be reported alongside the error.
    context = make_report_context(
        target_path="my-bucket",
        scanners=["s3"],
        scanner_versions={"s3": "0.1.0"},
        scanner_errors=["s3: Error scanning S3: ClientError: ExpiredToken"],
    )

    report = format_markdown_report([], context)

    assert "| s3 | 0.1.0 | 0 |" in report
    assert "| None | None | 0 |" not in report
    assert "Scanner error: s3: Error scanning S3: ClientError: ExpiredToken" in report


def test_markdown_scanner_versions_keep_findings_from_undeclared_scanners() -> None:
    # Declared scanners are additive: a finding whose scanner the caller never
    # declared is still counted rather than dropped from the table.
    context = make_report_context(
        target_path="/scan/root",
        scanners=["filesystem"],
        scanner_versions={"filesystem": "0.1.0"},
    )

    finding = _finding(
        "crypto_inventory", "PEM Certificate", "/scan/root/a.pem", scanner_name="crypto"
    )

    report = format_markdown_report([finding], context)

    assert "| crypto | 0.1.0 | 1 |" in report
    assert "| filesystem | 0.1.0 | 0 |" in report


def test_markdown_report_scan_metadata_is_present() -> None:
    report = format_markdown_report([_finding("local_filesystem", "file", "/a.txt")], _context())

    assert "| Scan Time | 2026-07-20T00:00:00+00:00 |" in report
    assert "| Report Generator | harvestguard-report 0.1.0 |" in report
    assert "| Target Path | /scan/root |" in report
    assert "| Duration | 1.25 seconds |" in report
    assert "| Excluded Paths | vendor/* |" in report
    assert "- Normalized schema version: `1.0.0`" in report


def test_markdown_report_states_duration_not_recorded_when_absent() -> None:
    context = make_report_context(target_path="/scan/root")

    report = format_markdown_report([], context)

    assert "| Duration | Not recorded |" in report


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


def test_json_output_is_an_array_of_findings_not_a_report_envelope() -> None:
    # HG-007 contract: --json stays a bare array of normalized findings; run
    # metadata and scan-level scanner errors are not wrapped around it.
    findings = [
        _finding("local_filesystem", "file", "/scan/root/a.txt"),
        _finding("crypto_inventory", "PEM Certificate", "/scan/root/a.pem"),
    ]

    payload = json.loads(findings_json(findings))

    assert isinstance(payload, list)
    assert len(payload) == 2
    assert all(isinstance(item, dict) for item in payload)


def test_json_output_is_ordered_by_asset_type_location_and_finding_id() -> None:
    # docs/CLI.md promises the same deterministic ordering for JSON as for
    # Markdown, so input order must not leak into the array.
    findings = [
        _finding("local_sensitive_data", "file", "/scan/root/z.txt"),
        _finding("crypto_inventory", "PEM Certificate", "/scan/root/b.pem"),
        _finding("crypto_inventory", "PEM Certificate", "/scan/root/a.pem"),
    ]

    payload = json.loads(findings_json(findings))
    reversed_payload = json.loads(findings_json(list(reversed(findings))))

    assert [(item["asset_type"], item["location"]) for item in payload] == [
        ("PEM Certificate", "/scan/root/a.pem"),
        ("PEM Certificate", "/scan/root/b.pem"),
        ("file", "/scan/root/z.txt"),
    ]
    assert payload == reversed_payload


def test_json_output_serializes_frozen_structures_as_plain_json_values() -> None:
    finding = NormalizedFinding(
        source_type="local_filesystem",
        asset_type="file",
        location="/scan/root/a.txt",
        scanner_name="filesystem",
        scanner_version="0.1.0",
        evidence="Encryption status observed: Unencrypted",
        confidence="Low",
        confidence_rationale="Volume-level fallback only.",
        collection_method="stat+signature",
        collection_source="host",
        rule_id="volume_status:unencrypted",
        repeatable=True,
        verification_rationale="No file-level signature matched.",
        technical_metadata={"Nested": {"List": [1, 2], "Set": {"a"}}},
        ownership_signals={"uid": 0, "permissions": ["read", "write"]},
        unknowns=["Business ownership cannot be established from filesystem metadata."],
        limitations=["Volume-level fallback used."],
        errors=["stat failed"],
        observed_at="2026-07-20T00:00:00+00:00",
    )

    item = json.loads(findings_json([finding]))[0]

    # The finding freezes nested structures internally (MappingProxyType /
    # tuple / frozenset); serialization must still emit plain JSON types.
    assert item["technical_metadata"] == {"Nested": {"List": [1, 2], "Set": ["a"]}}
    assert item["ownership_signals"] == {"uid": 0, "permissions": ["read", "write"]}
    assert item["unknowns"] == [
        "Business ownership cannot be established from filesystem metadata."
    ]
    assert item["limitations"] == ["Volume-level fallback used."]
    assert item["errors"] == ["stat failed"]
    assert item["provenance"] == {
        "scanner_name": "filesystem",
        "scanner_version": "0.1.0",
        "collection_method": "stat+signature",
        "source": "host",
        "rule_id": "volume_status:unencrypted",
        "collected_at": "2026-07-20T00:00:00+00:00",
        "repeatable": True,
        "verification_rationale": "No file-level signature matched.",
    }
    assert item["finding_id"] and item["schema_version"] == "1.0.0"


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
    context = make_report_context(target_path="/scan/root")

    report = format_markdown_report([_finding("local_filesystem", "file", "/a.txt")], context)

    assert "Coverage was not complete" not in report
    assert "| Coverage | No limits recorded |" in report
    assert "No scanner errors, finding-level errors, or limitations were reported." in report


def test_markdown_report_marks_coverage_bounded_when_scope_was_constrained() -> None:
    # A configured constraint is not a failure, but "No limits recorded" would
    # be untrue: --prefix and --exclude bound coverage without producing any
    # limitation finding.
    context = make_report_context(
        target_path="my-bucket",
        excluded_paths=["vendor/*"],
        scope_constraints=["Object/blob prefix: logs/"],
    )

    report = format_markdown_report([_finding("aws_s3", "object", "s3://my-bucket/a.txt")], context)

    assert "Coverage was not complete" not in report
    assert "| Coverage | Bounded by configured scan scope |" in report
    assert "  - Object/blob prefix: logs/" in report
    assert "  - Excluded patterns: vendor/*" in report


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
