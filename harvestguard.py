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
from scanner.azure_blob import scan_azure_container_findings
from scanner.cloud import scan_s3_bucket_findings
from scanner.crypto_inventory import scan_crypto_inventory_findings
from scanner.filesystem import scan_filesystem_findings
from scanner.gcs import scan_gcs_bucket_findings

# A scanner thunk closes over its target/options and returns normalized
# findings. Errors raised here are captured per scanner, not fatal.
ScannerThunk = Callable[[], list[NormalizedFinding]]

DEFAULT_MAX_DEPTH = 3

# Local scan types read a filesystem path; cloud scan types read a
# provider target (bucket, or Azure "account/container") using the
# provider SDK's default credential resolution.
LOCAL_SCAN_TYPES = ("all", "filesystem", "crypto", "sensitive-data", "code")
CLOUD_SCAN_TYPES = ("s3", "gcs", "azure")
SCAN_TYPES = LOCAL_SCAN_TYPES + CLOUD_SCAN_TYPES

# Exit codes deliberately separate invalid CLI input (2) from scan
# execution failures (1) so automation can branch on the difference.
EXIT_OK = 0
EXIT_SCAN_ERROR = 1
EXIT_USAGE = 2


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        return run_scan_command(args)

    parser.print_help(sys.stderr)
    return EXIT_USAGE


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="harvestguard",
        description=(
            "HarvestGuard command-line scanner. Runs the same evidence-only "
            "scanners as the dashboard and emits normalized findings as a "
            "summary, JSON, or a Markdown report."
        ),
    )
    subparsers = parser.add_subparsers(dest="command")

    scan = subparsers.add_parser(
        "scan",
        help="Run a HarvestGuard scanner and emit findings",
        description=(
            "Run one scan type against a target and emit normalized findings. "
            "Local scan types read a filesystem path; cloud scan types read a "
            "provider target using that provider SDK's default credentials."
        ),
    )
    scan.add_argument(
        "target",
        help=(
            "Scan target. For local scan types: a file or directory path. "
            "For s3/gcs: a bucket name. For azure: 'account-name/container-name'."
        ),
    )
    scan.add_argument(
        "--type",
        dest="type",
        choices=SCAN_TYPES,
        default="all",
        help=(
            "Scan type to run. 'all' (default) runs every local scanner. "
            "Cloud types (s3, gcs, azure) use provider SDK default credentials."
        ),
    )
    scan.add_argument(
        "--max-depth",
        type=int,
        default=DEFAULT_MAX_DEPTH,
        metavar="N",
        help=(
            "Maximum directory depth for local filesystem and sensitive-data "
            f"scans (default: {DEFAULT_MAX_DEPTH}). Ignored by cloud scans."
        ),
    )
    scan.add_argument(
        "--prefix",
        default="",
        help="Object/blob key prefix for cloud scans. Ignored by local scans.",
    )
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
    scan.add_argument(
        "--fail-on-error",
        action=argparse.BooleanOptionalAction,
        default=True,
        help=(
            "Exit with code 1 when a scanner fails (default). Use "
            "--no-fail-on-error to exit 0 even if a scanner reports an error."
        ),
    )
    return parser


def run_scan_command(args: argparse.Namespace) -> int:
    if args.max_depth < 0:
        print(f"Error: --max-depth must be zero or greater: {args.max_depth}", file=sys.stderr)
        return EXIT_USAGE

    scanner_errors: list[str] = []

    if args.type in LOCAL_SCAN_TYPES:
        target = Path(args.target)
        if not target.exists():
            print(f"Error: path does not exist: {args.target}", file=sys.stderr)
            return EXIT_USAGE
        target_repr = str(target)
        specs = _local_scanner_specs(args.type, target_repr, args.exclude, args.max_depth)
    else:
        specs, usage_error = _cloud_scanner_specs(args.type, args.target, args.prefix)
        if usage_error is not None:
            print(f"Error: {usage_error}", file=sys.stderr)
            return EXIT_USAGE
        target_repr = args.target

    started_at = datetime.now(timezone.utc)
    started_perf = time.perf_counter()
    findings = _run_scanners(specs, quiet=args.quiet, scanner_errors=scanner_errors)
    findings = [
        finding for finding in findings if not _is_excluded(finding.location, args.exclude)
    ]
    duration_seconds = time.perf_counter() - started_perf
    context = make_report_context(
        target_path=target_repr,
        started_at=started_at,
        duration_seconds=duration_seconds,
        excluded_paths=args.exclude,
        scanner_errors=scanner_errors,
    )

    if args.json is not None:
        if not _emit_output(findings_json(findings), args.json, "JSON findings", args.quiet):
            return EXIT_USAGE
    elif args.markdown is not None:
        report = format_markdown_report(findings, context)
        if not _emit_output(report, args.markdown, "Markdown report", args.quiet):
            return EXIT_USAGE
    else:
        print(format_console_summary(findings, context))

    if scanner_errors and args.fail_on_error:
        return EXIT_SCAN_ERROR
    return EXIT_OK


def _local_scanner_specs(
    scan_type: str, target: str, exclude_patterns: list[str], max_depth: int
) -> list[tuple[str, ScannerThunk]]:
    patterns = exclude_patterns or []
    specs: dict[str, tuple[str, ScannerThunk]] = {
        "filesystem": (
            "filesystem",
            lambda: scan_filesystem_findings(target, max_depth=max_depth),
        ),
        "crypto": (
            "crypto inventory",
            lambda: scan_crypto_inventory_findings(target, exclude_patterns=patterns),
        ),
        "sensitive-data": (
            "sensitive data",
            lambda: scan_filesystem_for_sensitive_data_findings(target, max_depth=max_depth),
        ),
        "code": (
            "code analysis",
            lambda: scan_source_for_crypto_usage_findings(target),
        ),
    }
    if scan_type == "all":
        return [specs["filesystem"], specs["crypto"], specs["sensitive-data"], specs["code"]]
    return [specs[scan_type]]


def _cloud_scanner_specs(
    scan_type: str, target: str, prefix: str
) -> tuple[list[tuple[str, ScannerThunk]] | None, str | None]:
    prefix = prefix or ""
    if scan_type == "s3":
        return [("s3", lambda: scan_s3_bucket_findings(target, prefix=prefix))], None
    if scan_type == "gcs":
        return [("gcs", lambda: scan_gcs_bucket_findings(target, prefix=prefix))], None
    if scan_type == "azure":
        account, separator, container = target.partition("/")
        if not separator or not account or not container:
            return None, (
                "azure target must be 'account-name/container-name', got: " + target
            )
        account_url = f"https://{account}.blob.core.windows.net"
        return (
            [
                (
                    "azure blob",
                    lambda: scan_azure_container_findings(account_url, container, prefix=prefix),
                )
            ],
            None,
        )
    return None, f"unknown scan type: {scan_type}"


def _run_scanners(
    specs: list[tuple[str, ScannerThunk]], quiet: bool, scanner_errors: list[str]
) -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []
    for scanner_name, scanner in specs:
        if not quiet:
            print(f"Running {scanner_name} scanner...", file=sys.stderr)
        try:
            findings.extend(scanner())
        except Exception as exc:
            scanner_errors.append(f"{scanner_name}: {exc}")
            if not quiet:
                print(f"Warning: {scanner_name} scanner failed: {exc}", file=sys.stderr)
    return findings


def run_local_scanners(
    path: str,
    exclude_patterns: list[str] | None = None,
    quiet: bool = False,
    scanner_errors: list[str] | None = None,
) -> list[NormalizedFinding]:
    """Run every local scanner against ``path`` and return filtered findings.

    Equivalent to a ``--type all`` scan. Retained as a stable helper for
    callers that want the aggregated local scan without going through
    argument parsing.
    """
    patterns = exclude_patterns or []
    errors = scanner_errors if scanner_errors is not None else []
    specs = _local_scanner_specs("all", path, patterns, DEFAULT_MAX_DEPTH)
    findings = _run_scanners(specs, quiet=quiet, scanner_errors=errors)
    return [finding for finding in findings if not _is_excluded(finding.location, patterns)]


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
