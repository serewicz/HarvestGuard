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
from finding_adapters import (
    AZURE_BLOB_SCANNER,
    CODE_ANALYSIS_SCANNER,
    CRYPTO_INVENTORY_SCANNER,
    FILESYSTEM_SCANNER,
    GCS_SCANNER,
    S3_SCANNER,
    SENSITIVE_DATA_SCANNER,
    ScannerIdentity,
)
from findings import NormalizedFinding
from harvestguard_version import version_string
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

# Scanner labels (as used in the scanner specs below) whose coverage is
# bounded by --max-depth; the other scanners ignore it.
DEPTH_BOUNDED_SCANNERS = ("filesystem", "sensitive data")

# Scanner label -> the normalized scanner identity its findings carry. The
# report needs this for every scanner that was invoked, including one that
# returned nothing or failed, so it cannot be read back off the findings.
SCANNER_IDENTITIES: dict[str, ScannerIdentity] = {
    "filesystem": FILESYSTEM_SCANNER,
    "crypto inventory": CRYPTO_INVENTORY_SCANNER,
    "sensitive data": SENSITIVE_DATA_SCANNER,
    "code analysis": CODE_ANALYSIS_SCANNER,
    "s3": S3_SCANNER,
    "gcs": GCS_SCANNER,
    "azure blob": AZURE_BLOB_SCANNER,
}

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
    # Version identity has to be readable from the CLI itself: a reviewer
    # holding an evidence artifact must be able to establish which
    # HarvestGuard produced it without reading source files (docs/RELEASE.md).
    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=version_string(),
        help="Print the HarvestGuard version and exit",
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
    # Populated by the crypto-inventory scanner thunk as a side channel (see
    # _local_scanner_specs): "files_inspected" -> count of files it visited,
    # for the HG-030 "Crypto files inspected" accounting line. Stays empty
    # when the crypto scanner did not run.
    crypto_stats: dict[str, int] = {}

    if args.type in LOCAL_SCAN_TYPES:
        target = Path(args.target)
        if not target.exists():
            print(f"Error: path does not exist: {args.target}", file=sys.stderr)
            return EXIT_USAGE
        target_repr = str(target)
        specs = _local_scanner_specs(
            args.type, target_repr, args.exclude, args.max_depth, crypto_stats
        )
    else:
        specs, usage_error = _cloud_scanner_specs(args.type, args.target, args.prefix)
        if usage_error is not None:
            print(f"Error: {usage_error}", file=sys.stderr)
            return EXIT_USAGE
        target_repr = args.target

    started_at = datetime.now(timezone.utc)
    started_perf = time.perf_counter()
    findings = _run_scanners(specs, quiet=args.quiet, scanner_errors=scanner_errors)
    findings = _deduplicate_openssl_encrypted_file_findings(findings)
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
        scan_type=args.type,
        scanners=[label for label, _ in specs],
        scope_constraints=_scope_constraints(args, specs),
        scanner_versions=_scanner_versions(specs),
        crypto_files_inspected=crypto_stats.get("files_inspected"),
    )

    if args.json is not None:
        # An output write failure is an execution error, not invalid CLI input:
        # exit 2 is reserved for bad arguments (see docs/CLI.md), so a failed
        # write returns the scan-error code instead.
        if not _emit_output(findings_json(findings), args.json, "JSON findings", args.quiet):
            return EXIT_SCAN_ERROR
    elif args.markdown is not None:
        report = format_markdown_report(findings, context)
        if not _emit_output(report, args.markdown, "Markdown report", args.quiet):
            return EXIT_SCAN_ERROR
    else:
        print(format_console_summary(findings, context))

    if scanner_errors and args.fail_on_error:
        return EXIT_SCAN_ERROR
    return EXIT_OK


def _local_scanner_specs(
    scan_type: str,
    target: str,
    exclude_patterns: list[str],
    max_depth: int,
    crypto_stats: dict[str, int] | None = None,
) -> list[tuple[str, ScannerThunk]]:
    patterns = exclude_patterns or []
    specs: dict[str, tuple[str, ScannerThunk]] = {
        "filesystem": (
            "filesystem",
            lambda: scan_filesystem_findings(target, max_depth=max_depth),
        ),
        "crypto": (
            "crypto inventory",
            lambda: scan_crypto_inventory_findings(
                target, exclude_patterns=patterns, stats=crypto_stats
            ),
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


def _scope_constraints(
    args: argparse.Namespace, specs: list[tuple[str, ScannerThunk]]
) -> list[str]:
    """Constraints that actually bounded this run, for the report's Scope.

    Only options the selected scanners honor are recorded: `--max-depth` is
    ignored by the crypto-inventory, code-analysis, and cloud scanners, and
    `--prefix` is ignored by every local scanner.
    """
    labels = [label for label, _ in specs]
    constraints: list[str] = []
    if any(label in DEPTH_BOUNDED_SCANNERS for label in labels):
        constraints.append(f"Maximum directory depth: {args.max_depth}")
    if args.type in CLOUD_SCAN_TYPES and args.prefix:
        constraints.append(f"Object/blob prefix: {args.prefix}")
    return constraints


def _scanner_versions(specs: list[tuple[str, ScannerThunk]]) -> dict[str, str]:
    """Normalized name -> version for every scanner this run invoked.

    Recorded before the scanners run, so the report can still name a scanner
    that produced no findings or failed outright.
    """
    return {
        SCANNER_IDENTITIES[label].name: SCANNER_IDENTITIES[label].version
        for label, _ in specs
        if label in SCANNER_IDENTITIES
    }


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
            # A scanner that failed partway through may still have collected
            # valid findings (CloudScanError.partial_findings). Keep them:
            # the run still exits nonzero via scanner_errors, but evidence
            # gathered before the failure is not discarded.
            partial = getattr(exc, "partial_findings", ())
            if partial:
                findings.extend(partial)
                if not quiet:
                    print(
                        f"Note: keeping {len(partial)} finding(s) {scanner_name} "
                        "collected before it failed.",
                        file=sys.stderr,
                    )
            if not quiet:
                print(f"Warning: {scanner_name} scanner failed: {exc}", file=sys.stderr)
    return findings


def _deduplicate_openssl_encrypted_file_findings(
    findings: list[NormalizedFinding],
) -> list[NormalizedFinding]:
    """When both the filesystem and crypto-inventory scanners run in the same
    scan (``--type all``), they can each independently recognize the same
    OpenSSL `Salted__` file. Crypto inventory owns this evidence (HG-030
    Product Decision), so the filesystem scanner's OpenSSL signature record
    (``rule_id`` ``file_signature:file_level_openssl`` -- the actual slug of
    the "File-level (OpenSSL)" label; Issue #66 refers to this as
    "file_signature:openssl", but that string does not appear anywhere in
    scanner/filesystem.py's `_FILE_SIGNATURES`/`_slug` output, confirmed by
    running the real scanner) is dropped for any location where a
    crypto-inventory `encrypted_file:openssl` record also exists -- exactly
    one record for that file survives in the combined output.

    Deterministic and scanner-order independent: the outcome depends only on
    which (source_type, rule_id, location) combinations are present in the
    final findings list, never on the order scanners ran in. A no-op when
    only one of the two scanners ran (--type filesystem or --type crypto
    alone), since no crypto-inventory `encrypted_file:openssl` location will
    be present to dedupe against.
    """
    crypto_openssl_locations = {
        finding.location
        for finding in findings
        if finding.source_type == "crypto_inventory"
        and finding.rule_id == "encrypted_file:openssl"
    }
    if not crypto_openssl_locations:
        return findings
    return [
        finding
        for finding in findings
        if not (
            finding.source_type == "local_filesystem"
            and finding.rule_id == "file_signature:file_level_openssl"
            and finding.location in crypto_openssl_locations
        )
    ]


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
    findings = _deduplicate_openssl_encrypted_file_findings(findings)
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
