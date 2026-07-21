from __future__ import annotations

import argparse
import fnmatch
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from classifier.scanner import scan_filesystem_for_sensitive_data_findings
from code_analysis.scanner import scan_source_for_crypto_usage_findings
from findings import NormalizedFinding, findings_to_dicts
from scanner.crypto_inventory import scan_crypto_inventory_findings
from scanner.filesystem import scan_filesystem_findings

ScanCallable = Callable[[str], list[NormalizedFinding]]


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        return run_scan_command(args)

    parser.print_help(sys.stderr)
    return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="harvestguard")
    subparsers = parser.add_subparsers(dest="command")

    scan = subparsers.add_parser("scan", help="Run local HarvestGuard scanners")
    scan.add_argument("path", help="Local file or directory to scan")
    output = scan.add_mutually_exclusive_group()
    output.add_argument("--json", action="store_true", help="Emit normalized findings as JSON")
    output.add_argument("--markdown", action="store_true", help="Emit a Markdown findings report")
    output.add_argument("--summary", action="store_true", help="Emit a human-readable summary")
    scan.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress progress messages; findings output is still emitted",
    )
    scan.add_argument(
        "--exclude",
        action="append",
        default=[],
        help="Glob pattern to exclude from output; may be supplied more than once",
    )
    return parser


def run_scan_command(args: argparse.Namespace) -> int:
    target = Path(args.path)
    if not target.exists():
        print(f"Error: path does not exist: {args.path}", file=sys.stderr)
        return 2

    scanner_errors: list[str] = []
    findings = run_local_scanners(
        str(target),
        exclude_patterns=args.exclude,
        quiet=args.quiet,
        scanner_errors=scanner_errors,
    )

    if args.json:
        print(json.dumps(findings_to_dicts(findings), indent=2))
    elif args.markdown:
        print(format_markdown(findings, scanner_errors=scanner_errors))
    else:
        print(format_summary(findings, scanner_errors=scanner_errors))

    return 1 if scanner_errors else 0


def run_local_scanners(
    path: str,
    exclude_patterns: list[str] | None = None,
    quiet: bool = False,
    scanner_errors: list[str] | None = None,
) -> list[NormalizedFinding]:
    patterns = exclude_patterns or []
    errors = scanner_errors if scanner_errors is not None else []
    scanners: list[tuple[str, ScanCallable]] = [
        ("filesystem", lambda target: scan_filesystem_findings(target)),
        (
            "crypto inventory",
            lambda target: scan_crypto_inventory_findings(target, exclude_patterns=patterns),
        ),
        ("sensitive data", lambda target: scan_filesystem_for_sensitive_data_findings(target)),
        ("code analysis", lambda target: scan_source_for_crypto_usage_findings(target)),
    ]

    findings: list[NormalizedFinding] = []
    for scanner_name, scanner in scanners:
        if not quiet:
            print(f"Running {scanner_name} scanner...", file=sys.stderr)
        try:
            scanner_findings = scanner(path)
        except Exception as exc:
            errors.append(f"{scanner_name}: {exc}")
            if not quiet:
                print(f"Warning: {scanner_name} scanner failed: {exc}", file=sys.stderr)
            continue
        findings.extend(
            finding
            for finding in scanner_findings
            if not _is_excluded(finding.location, patterns)
        )

    return findings


def format_summary(
    findings: list[NormalizedFinding], scanner_errors: list[str] | None = None
) -> str:
    counts = summarize_findings(findings)
    lines = [
        f"Files scanned: {counts['files_scanned']}",
        "",
        f"Certificates: {counts['certificates']}",
        f"Private Keys: {counts['private_keys']}",
        f"Expired Certificates: {counts['expired_certificates']}",
        f"Sensitive Files: {counts['sensitive_files']}",
        f"Semgrep Findings: {counts['semgrep_findings']}",
        "",
        f"Total Findings: {len(findings)}",
    ]
    if scanner_errors:
        lines.extend(["", "Scanner Warnings:"])
        lines.extend(f"- {error}" for error in scanner_errors)
    return "\n".join(lines)


def format_markdown(
    findings: list[NormalizedFinding], scanner_errors: list[str] | None = None
) -> str:
    counts = summarize_findings(findings)
    lines = [
        "# HarvestGuard Scan Report",
        "",
        "## Summary",
        "",
        f"- Files scanned: {counts['files_scanned']}",
        f"- Certificates: {counts['certificates']}",
        f"- Private Keys: {counts['private_keys']}",
        f"- Expired Certificates: {counts['expired_certificates']}",
        f"- Sensitive Files: {counts['sensitive_files']}",
        f"- Semgrep Findings: {counts['semgrep_findings']}",
        f"- Total Findings: {len(findings)}",
        "",
        "## Findings",
        "",
    ]
    if findings:
        lines.extend([
            "| Source | Asset Type | Location | Evidence | Confidence | Errors |",
            "| --- | --- | --- | --- | --- | --- |",
        ])
        for finding in findings:
            lines.append(
                "| "
                + " | ".join(
                    [
                        _md(finding.source_type),
                        _md(finding.asset_type),
                        _md(finding.location),
                        _md(finding.evidence),
                        _md(finding.confidence),
                        _md("; ".join(finding.errors)),
                    ]
                )
                + " |"
            )
    else:
        lines.append("No findings.")

    if scanner_errors:
        lines.extend(["", "## Scanner Warnings", ""])
        lines.extend(f"- {_md(error)}" for error in scanner_errors)
    return "\n".join(lines)


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
        "expired_certificates": sum(_is_expired_certificate(finding) for finding in certificates),
        "sensitive_files": by_source["local_sensitive_data"],
        "semgrep_findings": by_source["code_analysis"],
    }


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


def _is_excluded(location: str, patterns: list[str]) -> bool:
    if not patterns:
        return False
    name = Path(location).name
    return any(
        fnmatch.fnmatch(name, pattern) or fnmatch.fnmatch(location, pattern)
        for pattern in patterns
    )


def _md(value: object) -> str:
    return str(value or "").replace("|", "\\|").replace("\n", " ")


if __name__ == "__main__":
    raise SystemExit(main())
