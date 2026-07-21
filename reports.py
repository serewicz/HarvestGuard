from __future__ import annotations

import json
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from findings import NormalizedFinding, findings_to_dicts

REPORT_GENERATOR = "harvestguard-report"
REPORT_VERSION = "0.1.0"


@dataclass(frozen=True)
class ScanReportContext:
    target_path: str
    scan_time: str
    duration_seconds: float | None = None
    excluded_paths: list[str] = field(default_factory=list)
    scanner_errors: list[str] = field(default_factory=list)


def make_report_context(
    target_path: str,
    started_at: datetime | None = None,
    duration_seconds: float | None = None,
    excluded_paths: list[str] | None = None,
    scanner_errors: list[str] | None = None,
) -> ScanReportContext:
    started = started_at or datetime.now(timezone.utc)
    if started.tzinfo is None:
        started = started.replace(tzinfo=timezone.utc)
    return ScanReportContext(
        target_path=target_path,
        scan_time=started.replace(microsecond=0).isoformat(),
        duration_seconds=duration_seconds,
        excluded_paths=excluded_paths or [],
        scanner_errors=scanner_errors or [],
    )


def findings_json(findings: list[NormalizedFinding]) -> str:
    return json.dumps(findings_to_dicts(findings), indent=2)


def format_console_summary(
    findings: list[NormalizedFinding], context: ScanReportContext | None = None
) -> str:
    counts = summarize_findings(findings)
    lines = [
        "HarvestGuard Scan Complete",
        "",
        f"Files scanned: {counts['files_scanned']}",
        "",
        "Findings",
        "",
        f"Certificates: {counts['certificates']}",
        f"Private Keys: {counts['private_keys']}",
        f"Encrypted Keys: {counts['encrypted_keys']}",
        f"SSH Keys: {counts['ssh_keys']}",
        f"PKCS#12: {counts['pkcs12']}",
        f"Expired Certificates: {counts['expired_certificates']}",
        f"Sensitive Files: {counts['sensitive_files']}",
        f"Semgrep Findings: {counts['semgrep_findings']}",
        f"Malformed Assets: {counts['malformed_assets']}",
        f"Errors: {counts['errors']}",
        "",
        f"Total Findings: {len(findings)}",
    ]
    if context and context.scanner_errors:
        lines.extend(["", "Scanner Warnings:"])
        lines.extend(f"- {error}" for error in context.scanner_errors)
    return "\n".join(lines)


def format_markdown_report(
    findings: list[NormalizedFinding], context: ScanReportContext
) -> str:
    counts = summarize_findings(findings)
    ordered = sorted(findings, key=_finding_sort_key)
    by_type = _group_by_type(ordered)
    lines = [
        "# HarvestGuard Scan Report",
        "",
        "## Executive Summary",
        "",
        _executive_summary(counts, findings),
        "",
        "The report summarizes observed evidence only. It does not infer business risk.",
        "",
        "## Scan Information",
        "",
        "| Field | Value |",
        "| --- | --- |",
        f"| Scan Time | {_md(context.scan_time)} |",
        f"| Report Generator | {REPORT_GENERATOR} {REPORT_VERSION} |",
        f"| Target Path | {_md(context.target_path)} |",
        f"| Duration | {_duration(context.duration_seconds)} |",
        f"| Files Scanned | {counts['files_scanned']} |",
        f"| Excluded Paths | {_md(', '.join(context.excluded_paths) or 'None')} |",
        "",
        "## Scanner Versions",
        "",
        "| Scanner | Version | Findings |",
        "| --- | --- | --- |",
    ]
    lines.extend(_scanner_version_rows(ordered))
    lines.extend([
        "",
        "## Scope",
        "",
        f"- Target path: `{_inline_code(context.target_path)}`",
        "- Local filesystem encryption evidence",
        "- Cryptographic asset inventory",
        "- Sensitive-data category detection",
        "- Local Semgrep crypto code analysis",
        "",
        "## Findings Summary",
        "",
        "| Category | Count |",
        "| --- | ---: |",
        f"| Certificates | {counts['certificates']} |",
        f"| Private Keys | {counts['private_keys']} |",
        f"| Encrypted Keys | {counts['encrypted_keys']} |",
        f"| SSH Keys | {counts['ssh_keys']} |",
        f"| PKCS#12 | {counts['pkcs12']} |",
        f"| Expired Certificates | {counts['expired_certificates']} |",
        f"| Sensitive Files | {counts['sensitive_files']} |",
        f"| Semgrep Findings | {counts['semgrep_findings']} |",
        f"| Malformed Assets | {counts['malformed_assets']} |",
        f"| Errors | {counts['errors']} |",
        f"| Total Findings | {len(findings)} |",
        "",
        "## Finding Breakdown by Type",
        "",
    ])
    if by_type:
        lines.extend(["| Finding Type | Count |", "| --- | ---: |"])
        lines.extend(
            f"| {_md(asset_type)} | {len(items)} |"
            for asset_type, items in by_type.items()
        )
    else:
        lines.append("No findings.")

    lines.extend(["", "## Detailed Findings", ""])
    if by_type:
        for asset_type, items in by_type.items():
            lines.extend([
                f"### {asset_type}",
                "",
                "| Location | Asset Type | Algorithm | Key Size | Expiration | Issuer | "
                "Subject | Fingerprint | Confidence | Observed Evidence | Errors |",
                "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
            ])
            for finding in items:
                metadata = finding.technical_metadata
                lines.append(
                    "| "
                    + " | ".join(
                        [
                            _md(finding.location),
                            _md(finding.asset_type),
                            _md(metadata.get("Algorithm")),
                            _md(metadata.get("Key Size")),
                            _md(metadata.get("Expiration")),
                            _md(metadata.get("Issuer")),
                            _md(metadata.get("Subject")),
                            _md(metadata.get("Fingerprint")),
                            _md(finding.confidence),
                            _md(finding.evidence),
                            _md("; ".join(finding.errors)),
                        ]
                    )
                    + " |"
                )
            lines.append("")
    else:
        lines.append("No findings.")

    lines.extend([
        "## Errors and Warnings",
        "",
    ])
    if context.scanner_errors:
        lines.extend(f"- {_md(error)}" for error in context.scanner_errors)
    elif counts["errors"]:
        lines.append("- Finding-level errors are listed in Detailed Findings.")
    else:
        lines.append("No scanner errors or finding-level errors were reported.")

    lines.extend([
        "",
        "## Known Limitations",
        "",
        "- Findings are observed evidence, not business risk conclusions.",
        "- No risk scores, executive priority, remediation recommendations, or ownership "
        "inference are included.",
        "- Sensitive-data findings report categories and counts only, not matched values.",
        "- Encrypted key containers may not expose algorithm or key-size metadata without "
        "a passphrase.",
        "- JKS support is limited to header evidence in the current scanner.",
        "",
        "## Appendix",
        "",
        f"- Normalized schema version: `{_inline_code(_schema_version(findings))}`",
        "- JSON output preserves the normalized finding schema exactly.",
        "- Scanner-specific observed values are preserved in each finding's "
        "`technical_metadata`.",
    ])
    return "\n".join(lines).rstrip() + "\n"


def summarize_findings(findings: list[NormalizedFinding]) -> dict[str, int]:
    by_source = Counter(finding.source_type for finding in findings)
    filesystem_locations = {
        finding.location for finding in findings if finding.source_type == "local_filesystem"
    }
    certificates = [
        finding for finding in findings if "Certificate" in finding.asset_type
    ]
    return {
        "files_scanned": len(filesystem_locations),
        "certificates": len(certificates),
        "private_keys": sum("Private Key" in finding.asset_type for finding in findings),
        "encrypted_keys": sum("Encrypted" in finding.asset_type for finding in findings),
        "ssh_keys": sum("OpenSSH" in finding.asset_type for finding in findings),
        "pkcs12": sum("PKCS#12" in finding.asset_type for finding in findings),
        "expired_certificates": sum(_is_expired_certificate(finding) for finding in certificates),
        "sensitive_files": by_source["local_sensitive_data"],
        "semgrep_findings": by_source["code_analysis"],
        "malformed_assets": sum("Malformed" in finding.asset_type for finding in findings),
        "errors": sum(1 for finding in findings if finding.errors),
    }


def _executive_summary(counts: dict[str, int], findings: list[NormalizedFinding]) -> str:
    crypto_assets = sum(
        finding.source_type == "crypto_inventory"
        and "Malformed" not in finding.asset_type
        for finding in findings
    )
    return (
        f"HarvestGuard scanned {counts['files_scanned']} files and identified "
        f"{crypto_assets} cryptographic assets, {counts['sensitive_files']} "
        f"sensitive-data findings, and {counts['semgrep_findings']} "
        f"code-analysis findings across {len(findings)} total findings."
    )


def _scanner_version_rows(findings: list[NormalizedFinding]) -> list[str]:
    if not findings:
        return ["| None | None | 0 |"]
    versions: dict[tuple[str, str], int] = Counter(
        (finding.scanner_name, finding.scanner_version) for finding in findings
    )
    return [
        f"| {_md(scanner)} | {_md(version)} | {count} |"
        for (scanner, version), count in sorted(versions.items())
    ]


def _group_by_type(findings: list[NormalizedFinding]) -> dict[str, list[NormalizedFinding]]:
    grouped: dict[str, list[NormalizedFinding]] = defaultdict(list)
    for finding in findings:
        grouped[finding.asset_type].append(finding)
    return dict(sorted(grouped.items(), key=lambda item: item[0]))


def _finding_sort_key(finding: NormalizedFinding) -> tuple[str, str, str]:
    return (finding.asset_type, finding.location, finding.finding_id or "")


def _is_expired_certificate(finding: NormalizedFinding) -> bool:
    expiration = finding.technical_metadata.get("Expiration")
    if not expiration:
        return False
    try:
        expires_at = datetime.fromisoformat(str(expiration))
    except ValueError:
        return False
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    return expires_at < datetime.now(timezone.utc)


def _schema_version(findings: list[NormalizedFinding]) -> str:
    versions = sorted({finding.schema_version for finding in findings})
    return ", ".join(versions) if versions else "1.0.0"


def _duration(duration_seconds: float | None) -> str:
    if duration_seconds is None:
        return "Not recorded"
    return f"{duration_seconds:.2f} seconds"


def _md(value: Any) -> str:
    return str(value if value is not None else "").replace("|", "\\|").replace("\n", " ")


def _inline_code(value: str) -> str:
    return value.replace("`", "\\`")
