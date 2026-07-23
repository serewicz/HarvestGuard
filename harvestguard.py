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

# Scan types the CLI exposes. "all" is the default and runs every local
# scanner together (the original CLI behavior). The remaining values select a
# single scanner so a caller can target one evidence source at a time. Cloud
# types take a bucket/container identifier as the target rather than a local
# path.
LOCAL_SCAN_TYPES = ("all", "filesystem", "crypto", "sensitive", "code")
CLOUD_SCAN_TYPES = ("s3", "gcs", "azure")
SCAN_TYPES = LOCAL_SCAN_TYPES + CLOUD_SCAN_TYPES


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        return run_scan_command(args)

    parser.print_help(sys.stderr)
    return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="harvestguard",
        description=(
            "HarvestGuard evidence-collection CLI. Runs the same scanners as the "
            "Streamlit dashboard and emits normalized findings as a summary, JSON, "
            "or a Markdown evidence report."
        ),
    )
    subparsers = parser.add_subparsers(dest="command")

    scan = subparsers.add_parser(
        "scan",
        help="Run a HarvestGuard scanner and emit normalized findings",
        description=(
            "Scan a target and emit normalized findings. Local scan types take a "
            "filesystem path as TARGET; cloud scan types take a bucket or "
            "container identifier (Azure uses 'account/container'). Cloud "
            "credentials use each provider SDK's default resolution."
        ),
    )
    scan.add_argument(
        "path",
        metavar="TARGET",
        help=(
            "Local file or directory for local scans, or a bucket/container "
            "identifier for cloud scans (Azure: 'account/container')"
        ),
    )
    scan.add_argument(
        "--type",
        dest="scan_type",
        choices=SCAN_TYPES,
        default="all",
        help=(
            "Scan type to run. 'all' (default) runs every local scanner; "
            "'filesystem', 'crypto', 'sensitive', and 'code' each run one local "
            "scanner; 's3', 'gcs', and 'azure' scan the matching cloud target."
        ),
    )
    scan.add_argument(
        "--prefix",
        default=None,
        help="Object/blob key prefix to limit a cloud scan (s3, gcs, azure only)",
    )
    scan.add_argument(
        "--max-depth",
        dest="max_depth",
        type=int,
        default=None,
        help=(
            "Maximum directory recursion depth for local filesystem and "
            "sensitive-data scans (local scan types only)"
        ),
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
    is_cloud = args.scan_type in CLOUD_SCAN_TYPES

    option_error = _validate_options(args, is_cloud)
    if option_error is not None:
        print(f"Error: {option_error}", file=sys.stderr)
        return 2

    if is_cloud:
        target_error = _validate_cloud_target(args.scan_type, args.path)
        if target_error is not None:
            print(f"Error: {target_error}", file=sys.stderr)
            return 2
        target_path = args.path
    else:
        target = Path(args.path)
        if not target.exists():
            print(f"Error: path does not exist: {args.path}", file=sys.stderr)
            return 2
        target_path = str(target)

    scanner_errors: list[str] = []
    started_at = datetime.now(timezone.utc)
    started_perf = time.perf_counter()
    findings = run_scanners(
        args.scan_type,
        target_path,
        prefix=args.prefix,
        max_depth=args.max_depth,
        exclude_patterns=args.exclude,
        quiet=args.quiet,
        scanner_errors=scanner_errors,
    )
    duration_seconds = time.perf_counter() - started_perf
    context = make_report_context(
        target_path=target_path,
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


def _validate_options(args: argparse.Namespace, is_cloud: bool) -> str | None:
    """Reject option/scan-type combinations that don't apply, so misuse fails
    with a clear message and a nonzero exit code rather than being silently
    ignored."""
    if is_cloud and args.max_depth is not None:
        return "--max-depth applies to local scan types only"
    if not is_cloud and args.prefix is not None:
        return "--prefix applies to cloud scan types (s3, gcs, azure) only"
    if args.max_depth is not None and args.max_depth < 0:
        return "--max-depth must not be negative"
    return None


def _validate_cloud_target(scan_type: str, target: str) -> str | None:
    if not target:
        return "cloud scan target must not be empty"
    if scan_type == "azure":
        account, separator, container = target.partition("/")
        if not separator or not account or not container:
            return "Azure target must be in the form 'account/container'"
    return None


def run_scanners(
    scan_type: str,
    target: str,
    prefix: str | None = None,
    max_depth: int | None = None,
    exclude_patterns: list[str] | None = None,
    quiet: bool = False,
    scanner_errors: list[str] | None = None,
) -> list[NormalizedFinding]:
    """Dispatch to the scanner(s) selected by ``scan_type`` and return the
    combined, exclude-filtered findings. ``scan_type == "all"`` runs every
    local scanner; any other value runs exactly one scanner."""
    patterns = exclude_patterns or []
    errors = scanner_errors if scanner_errors is not None else []

    if scan_type == "all":
        scanners = _local_scanners(patterns, max_depth)
    else:
        scanners = [_scanner_for_type(scan_type, target, prefix, patterns, max_depth)]

    return _run_scanners(scanners, target, patterns, quiet, errors)


def run_local_scanners(
    path: str,
    exclude_patterns: list[str] | None = None,
    quiet: bool = False,
    scanner_errors: list[str] | None = None,
    max_depth: int | None = None,
) -> list[NormalizedFinding]:
    """Run every local scanner against ``path``. Retained as a stable entry
    point; ``run_scanners("all", ...)`` is the general dispatch path."""
    patterns = exclude_patterns or []
    errors = scanner_errors if scanner_errors is not None else []
    return _run_scanners(_local_scanners(patterns, max_depth), path, patterns, quiet, errors)


def _local_scanners(
    patterns: list[str], max_depth: int | None
) -> list[tuple[str, ScanCallable]]:
    # When max_depth is unset, filesystem/sensitive scanners are called with a
    # single positional argument so their own defaults apply -- this also keeps
    # them trivially monkeypatchable in tests with a one-argument stub.
    depth_kwargs = {} if max_depth is None else {"max_depth": max_depth}
    return [
        ("filesystem", lambda target: scan_filesystem_findings(target, **depth_kwargs)),
        (
            "crypto inventory",
            lambda target: scan_crypto_inventory_findings(target, exclude_patterns=patterns),
        ),
        (
            "sensitive data",
            lambda target: scan_filesystem_for_sensitive_data_findings(target, **depth_kwargs),
        ),
        ("code analysis", lambda target: scan_source_for_crypto_usage_findings(target)),
    ]


def _scanner_for_type(
    scan_type: str,
    target: str,
    prefix: str | None,
    patterns: list[str],
    max_depth: int | None,
) -> tuple[str, ScanCallable]:
    depth_kwargs = {} if max_depth is None else {"max_depth": max_depth}
    prefix_value = prefix or ""

    if scan_type == "filesystem":
        return ("filesystem", lambda t: scan_filesystem_findings(t, **depth_kwargs))
    if scan_type == "crypto":
        return (
            "crypto inventory",
            lambda t: scan_crypto_inventory_findings(t, exclude_patterns=patterns),
        )
    if scan_type == "sensitive":
        return (
            "sensitive data",
            lambda t: scan_filesystem_for_sensitive_data_findings(t, **depth_kwargs),
        )
    if scan_type == "code":
        return ("code analysis", lambda t: scan_source_for_crypto_usage_findings(t))
    if scan_type == "s3":
        return ("s3", lambda t: scan_s3_bucket_findings(t, prefix=prefix_value))
    if scan_type == "gcs":
        return ("gcs", lambda t: scan_gcs_bucket_findings(t, prefix=prefix_value))
    if scan_type == "azure":
        account, _, container = target.partition("/")
        account_url = f"https://{account}.blob.core.windows.net"
        return (
            "azure blob",
            lambda t: scan_azure_container_findings(
                account_url, container, prefix=prefix_value
            ),
        )
    raise ValueError(f"unknown scan type: {scan_type}")


def _run_scanners(
    scanners: list[tuple[str, ScanCallable]],
    target: str,
    patterns: list[str],
    quiet: bool,
    errors: list[str],
) -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []
    for scanner_name, scanner in scanners:
        if not quiet:
            print(f"Running {scanner_name} scanner...", file=sys.stderr)
        try:
            scanner_findings = scanner(target)
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
