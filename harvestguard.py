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

ScanCallable = Callable[[str], list[NormalizedFinding]]

# Scan-type identifiers exposed on the CLI. "all" preserves the original
# behavior of running every local scanner against a single path.
ALL_SCAN = "all"
FILESYSTEM_SCAN = "filesystem"
CRYPTO_INVENTORY_SCAN = "crypto-inventory"
SENSITIVE_DATA_SCAN = "sensitive-data"
CODE_ANALYSIS_SCAN = "code-analysis"
S3_SCAN = "s3"
GCS_SCAN = "gcs"
AZURE_BLOB_SCAN = "azure-blob"

# Local scan types resolve their target as a filesystem path; cloud scan
# types resolve it as a bucket/container reference and use provider SDK
# credential defaults.
LOCAL_SCAN_TYPES = (
    ALL_SCAN,
    FILESYSTEM_SCAN,
    CRYPTO_INVENTORY_SCAN,
    SENSITIVE_DATA_SCAN,
    CODE_ANALYSIS_SCAN,
)
CLOUD_SCAN_TYPES = (S3_SCAN, GCS_SCAN, AZURE_BLOB_SCAN)
SCAN_TYPES = LOCAL_SCAN_TYPES + CLOUD_SCAN_TYPES

# Azure Blob targets are given as "account/container"; the storage endpoint is
# assembled the same way the Streamlit app does.
AZURE_BLOB_ENDPOINT = "blob.core.windows.net"

# Human-readable progress/error labels for the cloud scan types.
_CLOUD_SCANNER_NAMES = {
    S3_SCAN: "s3",
    GCS_SCAN: "gcs",
    AZURE_BLOB_SCAN: "azure blob",
}

# Exit codes: 0 = clean, 1 = a scanner failed during execution, 2 = invalid
# CLI usage (bad arguments, missing path, malformed cloud target, or an
# output file that could not be written).
EXIT_OK = 0
EXIT_SCANNER_ERROR = 1
EXIT_USAGE_ERROR = 2


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        return run_scan_command(args)

    parser.print_help(sys.stderr)
    return EXIT_USAGE_ERROR


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="harvestguard",
        description=(
            "HarvestGuard command-line scanner. Runs a chosen scan type and "
            "emits normalized, evidence-only findings. Telemetry is never "
            "enabled and sensitive matched values are never emitted."
        ),
    )
    subparsers = parser.add_subparsers(dest="command")

    scan = subparsers.add_parser(
        "scan",
        help="Run a HarvestGuard scanner and emit normalized findings",
        description=(
            "Run a HarvestGuard scanner against a target and emit normalized "
            "findings. Local scan types (all, filesystem, crypto-inventory, "
            "sensitive-data, code-analysis) treat TARGET as a filesystem "
            "path. Cloud scan types (s3, gcs, azure-blob) treat TARGET as a "
            "bucket or container reference and use provider SDK credential "
            "defaults. Azure Blob targets use the form 'account/container'."
        ),
    )
    scan.add_argument(
        "target",
        help=(
            "Scan target: a local file or directory for local scan types, or "
            "a bucket/container reference for cloud scan types"
        ),
    )
    scan.add_argument(
        "--type",
        dest="type",
        choices=SCAN_TYPES,
        default=ALL_SCAN,
        help="Scan type to run (default: all local scanners)",
    )
    scan.add_argument(
        "--max-depth",
        type=_nonnegative_int,
        default=3,
        metavar="N",
        help=(
            "Maximum directory depth for filesystem and sensitive-data scans "
            "(default: 3; ignored by scan types that do not walk directories)"
        ),
    )
    scan.add_argument(
        "--prefix",
        default="",
        help="Object/blob prefix filter for cloud scan types (ignored for local scans)",
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
    return parser


def run_scan_command(args: argparse.Namespace) -> int:
    scanner_errors: list[str] = []
    started_at = datetime.now(timezone.utc)
    started_perf = time.perf_counter()

    if args.type in CLOUD_SCAN_TYPES:
        findings = run_cloud_scanner(
            args.type,
            args.target,
            prefix=args.prefix,
            quiet=args.quiet,
            scanner_errors=scanner_errors,
        )
        if findings is None:
            # Malformed cloud target -- invalid usage, not a scan failure.
            return EXIT_USAGE_ERROR
    else:
        target = Path(args.target)
        if not target.exists():
            print(f"Error: path does not exist: {args.target}", file=sys.stderr)
            return EXIT_USAGE_ERROR
        findings = run_local_scanners(
            str(target),
            scan_type=args.type,
            max_depth=args.max_depth,
            exclude_patterns=args.exclude,
            quiet=args.quiet,
            scanner_errors=scanner_errors,
        )

    findings = _apply_exclusions(findings, args.exclude)
    duration_seconds = time.perf_counter() - started_perf
    context = make_report_context(
        target_path=args.target,
        started_at=started_at,
        duration_seconds=duration_seconds,
        excluded_paths=args.exclude,
        scanner_errors=scanner_errors,
    )

    if args.json is not None:
        if not _emit_output(findings_json(findings), args.json, "JSON findings", args.quiet):
            return EXIT_USAGE_ERROR
    elif args.markdown is not None:
        report = format_markdown_report(findings, context)
        if not _emit_output(report, args.markdown, "Markdown report", args.quiet):
            return EXIT_USAGE_ERROR
    else:
        print(format_console_summary(findings, context))

    return EXIT_SCANNER_ERROR if scanner_errors else EXIT_OK


def run_local_scanners(
    path: str,
    scan_type: str = ALL_SCAN,
    max_depth: int = 3,
    exclude_patterns: list[str] | None = None,
    quiet: bool = False,
    scanner_errors: list[str] | None = None,
) -> list[NormalizedFinding]:
    patterns = exclude_patterns or []
    errors = scanner_errors if scanner_errors is not None else []
    scanners = _local_scanner_registry(max_depth, patterns)
    if scan_type != ALL_SCAN:
        scanners = [entry for entry in scanners if entry[0] == scan_type]

    findings: list[NormalizedFinding] = []
    for _scan_type, scanner_name, scanner in scanners:
        if not quiet:
            print(f"Running {scanner_name} scanner...", file=sys.stderr)
        try:
            scanner_findings = scanner(path)
        except Exception as exc:
            errors.append(f"{scanner_name}: {exc}")
            if not quiet:
                print(f"Warning: {scanner_name} scanner failed: {exc}", file=sys.stderr)
            continue
        findings.extend(scanner_findings)

    return findings


def _local_scanner_registry(
    max_depth: int, exclude_patterns: list[str]
) -> list[tuple[str, str, ScanCallable]]:
    # (scan-type identifier, display name, scanner callable). max_depth is
    # threaded into the directory-walking scanners; the others accept only a
    # path (crypto inventory takes exclude_patterns for in-walk pruning).
    return [
        (
            FILESYSTEM_SCAN,
            "filesystem",
            lambda target: scan_filesystem_findings(target, max_depth=max_depth),
        ),
        (
            CRYPTO_INVENTORY_SCAN,
            "crypto inventory",
            lambda target: scan_crypto_inventory_findings(
                target, exclude_patterns=exclude_patterns
            ),
        ),
        (
            SENSITIVE_DATA_SCAN,
            "sensitive data",
            lambda target: scan_filesystem_for_sensitive_data_findings(
                target, max_depth=max_depth
            ),
        ),
        (
            CODE_ANALYSIS_SCAN,
            "code analysis",
            lambda target: scan_source_for_crypto_usage_findings(target),
        ),
    ]


def run_cloud_scanner(
    scan_type: str,
    target: str,
    prefix: str = "",
    quiet: bool = False,
    scanner_errors: list[str] | None = None,
) -> list[NormalizedFinding] | None:
    """Run a single cloud scanner.

    Returns the list of findings, or None if the target is malformed (an
    invalid-usage condition the caller maps to a nonzero usage exit code).
    Scanner execution failures are recorded in scanner_errors and surface as
    an empty finding list so the run still produces structured output.
    """
    errors = scanner_errors if scanner_errors is not None else []

    if scan_type == AZURE_BLOB_SCAN:
        account, separator, container = target.partition("/")
        if not separator or not account or not container:
            print(
                "Error: azure-blob target must be in the form 'account/container'",
                file=sys.stderr,
            )
            return None

    scanner_name = _CLOUD_SCANNER_NAMES[scan_type]
    if not quiet:
        print(f"Running {scanner_name} scanner...", file=sys.stderr)
    try:
        if scan_type == S3_SCAN:
            return scan_s3_bucket_findings(target, prefix=prefix)
        if scan_type == GCS_SCAN:
            return scan_gcs_bucket_findings(target, prefix=prefix)
        account_url = f"https://{account}.{AZURE_BLOB_ENDPOINT}"
        return scan_azure_container_findings(account_url, container, prefix=prefix)
    except Exception as exc:
        errors.append(f"{scanner_name}: {exc}")
        if not quiet:
            print(f"Warning: {scanner_name} scanner failed: {exc}", file=sys.stderr)
        return []


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


def _apply_exclusions(
    findings: list[NormalizedFinding], patterns: list[str]
) -> list[NormalizedFinding]:
    if not patterns:
        return findings
    return [finding for finding in findings if not _is_excluded(finding.location, patterns)]


def _is_excluded(location: str, patterns: list[str]) -> bool:
    if not patterns:
        return False
    name = Path(location).name
    return any(
        fnmatch.fnmatch(name, pattern) or fnmatch.fnmatch(location, pattern)
        for pattern in patterns
    )


def _nonnegative_int(value: str) -> int:
    try:
        depth = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"expected an integer, got {value!r}")
    if depth < 0:
        raise argparse.ArgumentTypeError("must be zero or greater")
    return depth


if __name__ == "__main__":
    raise SystemExit(main())
