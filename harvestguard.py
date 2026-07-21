from __future__ import annotations

import argparse
import fnmatch
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from classifier.scanner import scan_filesystem_for_sensitive_data_findings
from code_analysis.scanner import scan_source_for_crypto_usage_findings
from findings import NormalizedFinding
from reports import (
    findings_json,
    format_console_summary,
    format_markdown_report,
    make_report_context,
)
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
    output.add_argument(
        "--json",
        nargs="?",
        const="-",
        metavar="PATH",
        help="Emit normalized findings as JSON to stdout or an optional file",
    )
    output.add_argument(
        "--markdown",
        nargs="?",
        const="-",
        metavar="PATH",
        help="Emit a Markdown scan report to stdout or an optional file",
    )
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
    started_at = datetime.now(timezone.utc)
    started_perf = time.perf_counter()
    findings = run_local_scanners(
        str(target),
        exclude_patterns=args.exclude,
        quiet=args.quiet,
        scanner_errors=scanner_errors,
    )
    duration_seconds = time.perf_counter() - started_perf
    context = make_report_context(
        target_path=str(target),
        started_at=started_at,
        duration_seconds=duration_seconds,
        excluded_paths=args.exclude,
        scanner_errors=scanner_errors,
    )

    if args.json is not None:
        if not _emit_output(findings_json(findings), args.json, "JSON findings", args.quiet):
            return 2
    elif args.markdown is not None:
        report = format_markdown_report(findings, context)
        if not _emit_output(report, args.markdown, "Markdown report", args.quiet):
            return 2
    else:
        print(format_console_summary(findings, context))

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


def _emit_output(content: str, destination: str, label: str, quiet: bool) -> bool:
    output = content if content.endswith("\n") else content + "\n"
    if destination == "-":
        print(output, end="")
        return True

    try:
        Path(destination).write_text(output, encoding="utf-8")
    except OSError as exc:
        print(f"Error: could not write {label} to {destination}: {exc}", file=sys.stderr)
        return False

    if not quiet:
        print(f"Wrote {label}: {destination}", file=sys.stderr)
    return True


def _is_excluded(location: str, patterns: list[str]) -> bool:
    if not patterns:
        return False
    name = Path(location).name
    return any(
        fnmatch.fnmatch(name, pattern) or fnmatch.fnmatch(location, pattern)
        for pattern in patterns
    )


if __name__ == "__main__":
    raise SystemExit(main())
