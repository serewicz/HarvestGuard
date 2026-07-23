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

ScanCallable = Callable[[], list[NormalizedFinding]]

# Scan types accept a local path.
LOCAL_SCAN_TYPES = (
    "all",
    "filesystem",
    "crypto-inventory",
    "sensitive-data",
    "code-analysis",
)
# Scan types accept a remote bucket / container target and use provider SDK
# default credential resolution.
CLOUD_SCAN_TYPES = ("s3", "gcs", "azure-blob")
SCAN_TYPES = LOCAL_SCAN_TYPES + CLOUD_SCAN_TYPES
# Local scan types whose underlying scanner honors a --max-depth boundary.
DEPTH_AWARE_SCAN_TYPES = ("all", "filesystem", "sensitive-data")
DEFAULT_SCAN_TYPE = "all"

# --fail-on values map user intent for the process exit code onto observed
# scan state. Exit codes remain evidence-only: they report what happened, they
# do not assign business risk.
FAIL_ON_CHOICES = ("error", "findings", "never")
DEFAULT_FAIL_ON = "error"


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
        description="Collect cryptographic evidence from local and cloud targets.",
    )
    subparsers = parser.add_subparsers(dest="command")

    scan = subparsers.add_parser(
        "scan",
        help="Run a HarvestGuard scanner and emit normalized findings",
        description=(
            "Run one or all HarvestGuard scanners against a local path or a "
            "cloud target and emit normalized findings. Cloud scans use the "
            "provider SDK's default credential resolution."
        ),
    )
    scan.add_argument(
        "target",
        help=(
            "Scan target. Local scans expect a file or directory; s3/gcs expect "
            "a bucket name; azure-blob expects 'account/container'."
        ),
    )
    scan.add_argument(
        "--type",
        dest="type",
        choices=SCAN_TYPES,
        default=DEFAULT_SCAN_TYPE,
        help=(
            "Scan type to run (default: all local scanners). Local: "
            + ", ".join(LOCAL_SCAN_TYPES)
            + ". Cloud: "
            + ", ".join(CLOUD_SCAN_TYPES)
            + "."
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
        "--max-depth",
        type=_non_negative_int,
        default=None,
        metavar="N",
        help=(
            "Directory recursion depth for local filesystem and sensitive-data "
            "scans (default: scanner default)"
        ),
    )
    scan.add_argument(
        "--prefix",
        default=None,
        help="Object/blob key prefix for cloud scans (s3, gcs, azure-blob)",
    )
    scan.add_argument(
        "--fail-on",
        dest="fail_on",
        choices=FAIL_ON_CHOICES,
        default=DEFAULT_FAIL_ON,
        help=(
            "Nonzero-exit policy: 'error' (default) exits 1 on scanner failure; "
            "'findings' also exits 1 when any findings are emitted; 'never' exits "
            "0 unless the input was invalid"
        ),
    )
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
    is_cloud = args.type in CLOUD_SCAN_TYPES

    # Argument-compatibility checks: reject nonsensical option combinations up
    # front with a clear message rather than silently ignoring them.
    if args.prefix is not None and not is_cloud:
        print(
            "Error: --prefix is only valid for cloud scans "
            f"({', '.join(CLOUD_SCAN_TYPES)})",
            file=sys.stderr,
        )
        return 2
    if args.max_depth is not None and args.type not in DEPTH_AWARE_SCAN_TYPES:
        print(
            "Error: --max-depth is only valid for local scans "
            f"({', '.join(DEPTH_AWARE_SCAN_TYPES)})",
            file=sys.stderr,
        )
        return 2

    scanner_errors: list[str] = []
    started_at = datetime.now(timezone.utc)
    started_perf = time.perf_counter()

    if is_cloud:
        scanners = _cloud_scanner_specs(args.type, args.target, args.prefix or "")
        if scanners is None:
            return 2  # invalid target; message already emitted
        target_display = args.target
        findings = _run_scanners(scanners, quiet=args.quiet, scanner_errors=scanner_errors)
        findings = [
            finding for finding in findings if not _is_excluded(finding.location, args.exclude)
        ]
    else:
        target = Path(args.target)
        if not target.exists():
            print(f"Error: path does not exist: {args.target}", file=sys.stderr)
            return 2
        target_display = str(target)
        findings = run_local_scanners(
            str(target),
            scan_type=args.type,
            exclude_patterns=args.exclude,
            max_depth=args.max_depth,
            quiet=args.quiet,
            scanner_errors=scanner_errors,
        )

    duration_seconds = time.perf_counter() - started_perf
    context = make_report_context(
        target_path=target_display,
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

    return _exit_code(args.fail_on, scanner_errors=scanner_errors, findings=findings)


def run_local_scanners(
    path: str,
    scan_type: str = DEFAULT_SCAN_TYPE,
    exclude_patterns: list[str] | None = None,
    max_depth: int | None = None,
    quiet: bool = False,
    scanner_errors: list[str] | None = None,
) -> list[NormalizedFinding]:
    patterns = exclude_patterns or []
    errors = scanner_errors if scanner_errors is not None else []
    scanners = _local_scanner_specs(scan_type, path, patterns, max_depth)
    findings = _run_scanners(scanners, quiet=quiet, scanner_errors=errors)
    return [finding for finding in findings if not _is_excluded(finding.location, patterns)]


def _local_scanner_specs(
    scan_type: str, path: str, patterns: list[str], max_depth: int | None
) -> list[tuple[str, ScanCallable]]:
    # max_depth is only forwarded when the user explicitly set it, so the
    # default call signature stays identical to the underlying scanner default.
    def filesystem() -> list[NormalizedFinding]:
        if max_depth is None:
            return scan_filesystem_findings(path)
        return scan_filesystem_findings(path, max_depth=max_depth)

    def crypto_inventory() -> list[NormalizedFinding]:
        return scan_crypto_inventory_findings(path, exclude_patterns=patterns)

    def sensitive_data() -> list[NormalizedFinding]:
        if max_depth is None:
            return scan_filesystem_for_sensitive_data_findings(path)
        return scan_filesystem_for_sensitive_data_findings(path, max_depth=max_depth)

    def code_analysis() -> list[NormalizedFinding]:
        return scan_source_for_crypto_usage_findings(path)

    specs: dict[str, tuple[str, ScanCallable]] = {
        "filesystem": ("filesystem", filesystem),
        "crypto-inventory": ("crypto inventory", crypto_inventory),
        "sensitive-data": ("sensitive data", sensitive_data),
        "code-analysis": ("code analysis", code_analysis),
    }
    if scan_type == "all":
        return [
            specs["filesystem"],
            specs["crypto-inventory"],
            specs["sensitive-data"],
            specs["code-analysis"],
        ]
    return [specs[scan_type]]


def _cloud_scanner_specs(
    scan_type: str, target: str, prefix: str
) -> list[tuple[str, ScanCallable]] | None:
    if not target.strip():
        print("Error: a scan target is required", file=sys.stderr)
        return None

    if scan_type == "s3":
        return [("s3", lambda: scan_s3_bucket_findings(target, prefix=prefix))]
    if scan_type == "gcs":
        return [("gcs", lambda: scan_gcs_bucket_findings(target, prefix=prefix))]

    # azure-blob
    account_name, separator, container_name = target.partition("/")
    if not separator or not account_name or not container_name:
        print(
            "Error: azure-blob target must be 'account/container' "
            f"(got: {target})",
            file=sys.stderr,
        )
        return None
    account_url = f"https://{account_name}.blob.core.windows.net"
    return [
        (
            "azure blob",
            lambda: scan_azure_container_findings(account_url, container_name, prefix=prefix),
        )
    ]


def _run_scanners(
    scanners: list[tuple[str, ScanCallable]],
    quiet: bool,
    scanner_errors: list[str],
) -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []
    for scanner_name, scanner in scanners:
        if not quiet:
            print(f"Running {scanner_name} scanner...", file=sys.stderr)
        try:
            findings.extend(scanner())
        except Exception as exc:
            scanner_errors.append(f"{scanner_name}: {exc}")
            if not quiet:
                print(f"Warning: {scanner_name} scanner failed: {exc}", file=sys.stderr)
    return findings


def _exit_code(
    fail_on: str, scanner_errors: list[str], findings: list[NormalizedFinding]
) -> int:
    if fail_on == "never":
        return 0
    if scanner_errors:
        return 1
    if fail_on == "findings" and findings:
        return 1
    return 0


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


def _non_negative_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"expected an integer, got: {value}") from None
    if parsed < 0:
        raise argparse.ArgumentTypeError(f"must be zero or greater, got: {value}")
    return parsed


if __name__ == "__main__":
    raise SystemExit(main())
