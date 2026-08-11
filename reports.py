from __future__ import annotations

import json
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from finding_adapters import (
    FILESYSTEM_CONTEXT_ASSET_TYPE,
    FILESYSTEM_FILES_REPRESENTED_KEY,
)
from findings import NormalizedFinding, findings_to_dicts
from harvestguard_version import __version__ as HARVESTGUARD_VERSION

# Two distinct identities, deliberately not collapsed into one: the report
# generator/format version describes the shape of this document, while
# HARVESTGUARD_VERSION identifies the release of the tool that produced it.
# They happen to match at v0.1.0 and are free to diverge later.
REPORT_GENERATOR = "harvestguard-report"
REPORT_VERSION = "0.1.0"

# Primary summary categories. Every retained normalized record is classified
# into exactly one of them, deterministically, from fields the record already
# carries (source_type, asset_type, rule_id) -- so a reader can tell aggregate
# filesystem context from per-file evidence, and both from scope that was not
# inspected, instead of reading one undifferentiated total.
#
# Finding-level errors (a record's own `errors`) and scanner execution errors
# (`scanner_errors`) are deliberately *not* categories: a record can be in any
# category and also carry errors, so they are reported as separate overlays.
CATEGORY_FILESYSTEM_CONTEXT = "filesystem_context"
CATEGORY_FILESYSTEM_FILE_EVIDENCE = "filesystem_file_evidence"
CATEGORY_COVERAGE_LIMITATION = "coverage_limitation"
CATEGORY_SKIPPED_OR_INACCESSIBLE = "skipped_or_inaccessible"
CATEGORY_CRYPTO_INVENTORY = "crypto_inventory"
CATEGORY_SENSITIVE_DATA = "sensitive_data"
CATEGORY_CODE_ANALYSIS = "code_analysis"
CATEGORY_CLOUD_EVIDENCE = "cloud_evidence"
# Residual bucket so classification is total: any future source_type that has
# no category yet is still counted and shown rather than silently dropped.
CATEGORY_OTHER = "other_records"

SUMMARY_CATEGORIES = (
    CATEGORY_FILESYSTEM_CONTEXT,
    CATEGORY_FILESYSTEM_FILE_EVIDENCE,
    CATEGORY_COVERAGE_LIMITATION,
    CATEGORY_SKIPPED_OR_INACCESSIBLE,
    CATEGORY_CRYPTO_INVENTORY,
    CATEGORY_SENSITIVE_DATA,
    CATEGORY_CODE_ANALYSIS,
    CATEGORY_CLOUD_EVIDENCE,
    CATEGORY_OTHER,
)

# Display labels are deliberately not the scanner labels the CLI reports under
# Scope ("crypto inventory", "sensitive data", "code analysis"): a report must
# never contain the name of a scanner the run did not invoke, and these rows are
# always printed, including with a count of zero.
CATEGORY_LABELS = {
    CATEGORY_FILESYSTEM_CONTEXT: "Aggregate filesystem context records",
    CATEGORY_FILESYSTEM_FILE_EVIDENCE: "Per-file filesystem evidence records",
    CATEGORY_COVERAGE_LIMITATION: "Coverage limitation records",
    CATEGORY_SKIPPED_OR_INACCESSIBLE: "Skipped or inaccessible entry records",
    CATEGORY_CRYPTO_INVENTORY: "Cryptographic inventory records",
    CATEGORY_SENSITIVE_DATA: "Sensitive-data records",
    CATEGORY_CODE_ANALYSIS: "Code-analysis records",
    CATEGORY_CLOUD_EVIDENCE: "Cloud storage records",
    CATEGORY_OTHER: "Other records",
}

# Categories whose records are observed evidence about an asset. The remaining
# categories describe scan context or scope that was not inspected, which is
# exactly why a single combined total must never be labelled as if every
# counted item were a distinct material finding.
MATERIAL_EVIDENCE_CATEGORIES = (
    CATEGORY_FILESYSTEM_FILE_EVIDENCE,
    CATEGORY_CRYPTO_INVENTORY,
    CATEGORY_SENSITIVE_DATA,
    CATEGORY_CODE_ANALYSIS,
    CATEGORY_CLOUD_EVIDENCE,
)

# Filesystem rule families that record scope which was *not* inspected.
_COVERAGE_RULE_IDS = frozenset({"max_depth_boundary", "directory_traversal_error"})
_SKIPPED_RULE_IDS = frozenset({"skipped_special_file", "metadata_unavailable"})
_SOURCE_TYPE_CATEGORIES = {
    "crypto_inventory": CATEGORY_CRYPTO_INVENTORY,
    "local_sensitive_data": CATEGORY_SENSITIVE_DATA,
    "code_analysis": CATEGORY_CODE_ANALYSIS,
    "aws_s3": CATEGORY_CLOUD_EVIDENCE,
    "gcs": CATEGORY_CLOUD_EVIDENCE,
    "azure_blob": CATEGORY_CLOUD_EVIDENCE,
}


def classify_finding(finding: NormalizedFinding) -> str:
    """The one primary summary category a normalized record belongs to."""
    if finding.source_type != "local_filesystem":
        return _SOURCE_TYPE_CATEGORIES.get(finding.source_type, CATEGORY_OTHER)

    rule_id = finding.rule_id or ""
    if finding.asset_type == FILESYSTEM_CONTEXT_ASSET_TYPE:
        return CATEGORY_FILESYSTEM_CONTEXT
    if rule_id in _COVERAGE_RULE_IDS or finding.asset_type == "directory":
        return CATEGORY_COVERAGE_LIMITATION
    if rule_id in _SKIPPED_RULE_IDS or finding.asset_type == "special_file":
        return CATEGORY_SKIPPED_OR_INACCESSIBLE
    if rule_id.startswith("volume_status:"):
        # A per-file record on the volume-level fallback path only survives now
        # when the file's own content could not be read; the ordinary case has
        # no per-file record at all. That makes it an inaccessible entry, not
        # file-level evidence.
        return CATEGORY_SKIPPED_OR_INACCESSIBLE
    return CATEGORY_FILESYSTEM_FILE_EVIDENCE


def count_by_category(findings: list[NormalizedFinding]) -> dict[str, int]:
    """Every primary category, including the ones with no records this scan."""
    counted = Counter(classify_finding(finding) for finding in findings)
    return {category: counted.get(category, 0) for category in SUMMARY_CATEGORIES}


@dataclass(frozen=True)
class ScanReportContext:
    target_path: str
    scan_time: str
    duration_seconds: float | None = None
    excluded_paths: list[str] = field(default_factory=list)
    scanner_errors: list[str] = field(default_factory=list)
    # Which scan was actually run. The report must not claim a scanner ran
    # that the caller never invoked, so scope is reported from what the CLI
    # selected rather than from a fixed list of every scanner that exists.
    scan_type: str | None = None
    scanners: list[str] = field(default_factory=list)
    scope_constraints: list[str] = field(default_factory=list)
    # Normalized scanner name -> version for every scanner that was invoked.
    # Recorded separately from the findings so the report can state the version
    # of a scanner that produced no findings, or that failed before producing
    # any, instead of omitting it as if it had never run.
    scanner_versions: dict[str, str] = field(default_factory=dict)
    # Count of files the crypto-inventory scanner actually visited/opened,
    # regardless of whether they matched a candidate shape or produced a
    # finding (HG-029's `Files scanned` counts only local_filesystem findings,
    # so it is 0 for a pure --type crypto run -- that is correct, not a bug,
    # and is not redefined by this field). None when the crypto-inventory
    # scanner did not run this scan; additive and never merged with
    # `Files scanned` -- see summarize_findings()/format_console_summary().
    crypto_files_inspected: int | None = None
    # Run identity for this one scan execution, generated by the CLI before the
    # scanners run and shared by every finding the run emitted. None for library
    # callers that build a context directly without a run identity; the Markdown
    # Scan ID row is then omitted rather than shown empty. Declared last so
    # existing positional construction of this dataclass is unaffected.
    scan_id: str | None = None


def make_report_context(
    target_path: str,
    started_at: datetime | None = None,
    duration_seconds: float | None = None,
    excluded_paths: list[str] | None = None,
    scanner_errors: list[str] | None = None,
    scan_type: str | None = None,
    scanners: list[str] | None = None,
    scope_constraints: list[str] | None = None,
    scanner_versions: dict[str, str] | None = None,
    crypto_files_inspected: int | None = None,
    scan_id: str | None = None,
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
        scan_type=scan_type,
        scanners=list(scanners or []),
        scope_constraints=list(scope_constraints or []),
        scanner_versions=dict(scanner_versions or {}),
        crypto_files_inspected=crypto_files_inspected,
        scan_id=scan_id,
    )


def sort_findings(findings: list[NormalizedFinding]) -> list[NormalizedFinding]:
    """The canonical report ordering: asset type, location, finding ID.

    Exposed so a caller that persists findings (see `evidence_store`) can store
    them in exactly the order the JSON and Markdown reports emit, instead of
    reimplementing the sort key.
    """
    return sorted(findings, key=_finding_sort_key)


def findings_json(findings: list[NormalizedFinding]) -> str:
    # Same ordering as the Markdown report (asset type, location, finding ID)
    # so both outputs are deterministic and comparable. The shape stays a bare
    # array of serialized normalized findings.
    return json.dumps(findings_to_dicts(sort_findings(findings)), indent=2)


def format_console_summary(
    findings: list[NormalizedFinding], context: ScanReportContext | None = None
) -> str:
    counts = summarize_findings(findings)
    lines = [
        "HarvestGuard Scan Complete",
        "",
        # Inspected regular files, kept visually separate from every record
        # count below it: the two answer different questions, and conflating
        # them is what made a 20,091-file scan read as 20,632 "findings".
        f"Files scanned: {counts['files_scanned']}",
    ]
    if context is not None and context.crypto_files_inspected is not None:
        # Additive, independent of `Files scanned` (HG-030): a pure
        # --type crypto run correctly reports `Files scanned: 0` (no
        # local_filesystem findings), which would otherwise read as if
        # nothing was inspected. Never arithmetically merged or reconciled
        # with `Files scanned`, even when both scanners inspect the same
        # files under --type all.
        lines.append(f"Crypto files inspected: {context.crypto_files_inspected}")
    lines.extend([
        "",
        "Record Categories",
        "",
    ])
    lines.extend(_category_lines(counts))
    lines.extend([
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
        # Named for exactly what it counts. A combined total must never be
        # presented as "Total Findings", which would imply every counted item
        # is a distinct material finding -- aggregate context, coverage
        # limitation, and skipped/inaccessible records are not.
        f"Material evidence records: {counts['material_evidence']}",
        f"Total normalized records: {counts['total_records']}",
        f"Findings with finding-level errors: {counts['errors']}",
        f"Scanner execution errors: {len(context.scanner_errors) if context else 0}",
    ])
    if context and context.scanner_errors:
        lines.extend(["", "Scanner Warnings:"])
        lines.extend(f"- {error}" for error in context.scanner_errors)
    coverage_statement = _coverage_statement(findings, context) if context else None
    if coverage_statement:
        lines.extend(["", coverage_statement])
    return "\n".join(lines)


def format_markdown_report(
    findings: list[NormalizedFinding], context: ScanReportContext
) -> str:
    counts = summarize_findings(findings)
    ordered = sort_findings(findings)
    by_type = _group_by_type(ordered)
    coverage_statement = _coverage_statement(findings, context)
    lines = [
        "# HarvestGuard Scan Report",
        "",
        "## Executive Summary",
        "",
        _executive_summary(counts, findings),
        "",
        "The report summarizes observed evidence only. It does not infer business risk.",
        "",
    ]
    if coverage_statement:
        lines.extend([coverage_statement, ""])
    lines.extend([
        "## Scan Information",
        "",
        "| Field | Value |",
        "| --- | --- |",
        f"| Scan Time | {_md(context.scan_time)} |",
    ])
    if context.scan_id is not None:
        # Run identity, so a reader can tie this artifact back to one specific
        # scan execution -- and to that run's record in a local evidence store
        # if the scan was persisted with `--evidence-db`. Omitted rather than
        # shown blank for a library caller that supplied no run identity.
        lines.append(f"| Scan ID | {_md(context.scan_id)} |")
    lines.extend([
        # A shared artifact must name the release that produced it; the JSON
        # output deliberately stays a bare finding array (docs/RELEASE.md,
        # "Identifying the version that produced an artifact"), so this row is
        # where a reviewer reads tool identity off the evidence itself.
        f"| HarvestGuard Version | {_md(HARVESTGUARD_VERSION)} |",
        f"| Report Generator | {REPORT_GENERATOR} {REPORT_VERSION} |",
        f"| Target Path | {_md(context.target_path)} |",
        f"| Duration | {_duration(context.duration_seconds)} |",
        f"| Files Scanned | {counts['files_scanned']} |",
    ])
    if context.crypto_files_inspected is not None:
        # Additive accounting line (HG-030), independent of `Files Scanned`
        # above -- see format_console_summary for why the two are never
        # merged or reconciled.
        lines.append(f"| Crypto Files Inspected | {context.crypto_files_inspected} |")
    lines.extend([
        f"| Excluded Paths | {_md(', '.join(context.excluded_paths) or 'None')} |",
        f"| Coverage | {_md(_coverage_status(coverage_statement, context))} |",
        "",
        "## Scanner Versions",
        "",
        "| Scanner | Version | Findings |",
        "| --- | --- | --- |",
    ])
    lines.extend(_scanner_version_rows(ordered, context))
    lines.extend(["", "## Scope", ""])
    lines.extend(_scope_lines(context))
    lines.extend([
        "",
        "## Record Categories",
        "",
        "Every normalized record below is counted in exactly one category. "
        "`Files Scanned` above counts inspected regular files, not records: "
        "an ordinary readable file with no file-level evidence and no "
        "file-specific failure produces no record of its own, and is "
        "represented by its mount's aggregate filesystem context record.",
        "",
        "| Category | Count |",
        "| --- | ---: |",
    ])
    lines.extend(
        f"| {CATEGORY_LABELS[category]} | {counts[category]} |"
        for category in SUMMARY_CATEGORIES
        if category != CATEGORY_OTHER or counts[category]
    )
    lines.extend([
        f"| **Material evidence records** | {counts['material_evidence']} |",
        f"| **Total normalized records** | {counts['total_records']} |",
        "",
        # Overlays, not categories: a record in any category above can also
        # carry finding-level errors, and a scanner execution error is not a
        # record at all.
        f"- Findings with finding-level errors: {counts['errors']}",
        f"- Scanner execution errors: {len(context.scanner_errors)}",
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
        f"| Total normalized records | {counts['total_records']} |",
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
                # Scanner/version/observed-at are per finding, not only in the
                # aggregate Scanner Versions table: a reviewer must be able to
                # tell which scanner produced each observation and when it was
                # collected without leaving Detailed Findings.
                "| Location | Asset Type | Scanner | Scanner Version | Observed At | "
                "Algorithm | Key Size | Expiration | Issuer | Subject | Fingerprint | "
                "Confidence | Observed Evidence | Unknowns | Limitations | Errors |",
                "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | "
                "--- | --- | --- | --- | --- |",
            ])
            for finding in items:
                metadata = finding.technical_metadata
                lines.append(
                    "| "
                    + " | ".join(
                        [
                            _md(finding.location),
                            _md(finding.asset_type),
                            _md(finding.scanner_name),
                            _md(finding.scanner_version),
                            _md(finding.observed_at or "Not recorded"),
                            _md(metadata.get("Algorithm")),
                            _md(metadata.get("Key Size")),
                            _md(metadata.get("Expiration")),
                            _md(metadata.get("Issuer")),
                            _md(metadata.get("Subject")),
                            _md(metadata.get("Fingerprint")),
                            _md(finding.confidence),
                            _md(finding.evidence),
                            # Unknowns and limitations are rendered in full
                            # rather than counted: a reviewer needs to see
                            # exactly what could not be established and which
                            # scope was skipped or only partially observed.
                            _md("; ".join(finding.unknowns)),
                            _md("; ".join(finding.limitations)),
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
        lines.extend(f"- Scanner error: {_md(error)}" for error in context.scanner_errors)
    if counts["errors"]:
        lines.append("- Finding-level errors are listed in Detailed Findings.")
    limited = _limitation_findings(findings)
    if limited:
        lines.append(
            f"- {len(limited)} finding(s) record limitations on what could be "
            "observed or traversed; each is listed with its limitations in "
            "Detailed Findings. Coverage limitations by type:"
        )
        for rule_id, count in sorted(Counter(_limitation_kind(f) for f in limited).items()):
            lines.append(f"  - `{_inline_code(rule_id)}`: {count}")
    if not context.scanner_errors and not counts["errors"] and not limited:
        lines.append("No scanner errors, finding-level errors, or limitations were reported.")

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
        # Even a report showing "No limits recorded" describes a bounded
        # detection surface, so the absence caveat is unconditional rather
        # than tied to the coverage row.
        "- Every scanner has a deliberately narrow detection surface, so absence of a "
        "finding is not proof of absence. Each scanner's supported evidence, known "
        "blind spots, and confidence semantics are documented in "
        "`docs/DETECTION_CHARACTERIZATION.md`.",
    ])
    if "code analysis" in context.scanners:
        # Unlike the bullets above, this one names a specific scanner and its
        # execution-failure behavior, so it only belongs on a report that
        # actually ran that scanner -- a filesystem-only or cloud-only report
        # must not carry a caveat about a scanner it never invoked (see
        # test_markdown_scope_lists_only_the_scanners_that_ran and its CLI
        # counterparts, which assert exactly that). A code-analysis
        # environment failure returns no rows and is not recorded as a
        # scanner error (unlike a cloud failure), so a report cannot show it
        # any other way; this is the only place a reader of the artifact
        # alone can learn that an empty code-analysis result is ambiguous.
        lines.append(
            "- Source-code analysis matches Python source text only, and an execution "
            "failure (analyzer unavailable, timed out, or unreadable output) yields no "
            "findings without appearing above; its diagnostic goes only to the scan's "
            "standard error stream."
        )
    lines.extend([
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
    # Coverage-limitation findings (an unreadable directory, a directory beyond
    # max_depth, a symlink/special file skipped for safety) are deliberately
    # excluded: they record scope that was *not* inspected, so counting them as
    # files scanned would overstate coverage. Aggregate filesystem context
    # records are excluded here too -- one describes a mount, not a file -- but
    # each reports how many inspected regular files it stands in for, and those
    # files were inspected, so they are added back below. "Files scanned"
    # therefore still means inspected regular files, never a record count.
    filesystem_locations = {
        finding.location
        for finding in findings
        if finding.source_type == "local_filesystem" and finding.asset_type == "file"
    }
    files_represented_by_context = sum(
        _represented_file_count(finding)
        for finding in findings
        if classify_finding(finding) == CATEGORY_FILESYSTEM_CONTEXT
    )
    categories = count_by_category(findings)
    certificates = [
        finding for finding in findings if "Certificate" in finding.asset_type
    ]
    return {
        **categories,
        "total_records": len(findings),
        "material_evidence": sum(
            categories[category] for category in MATERIAL_EVIDENCE_CATEGORIES
        ),
        "files_scanned": len(filesystem_locations) + files_represented_by_context,
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


def _category_lines(counts: dict[str, int]) -> list[str]:
    """One line per primary category, in a fixed order.

    Categories with no records this scan are still printed: a reader must be
    able to see that there were zero coverage limitations, rather than having
    to infer it from the absence of a line.
    """
    return [
        f"{CATEGORY_LABELS[category]}: {counts[category]}"
        for category in SUMMARY_CATEGORIES
        # The residual bucket only means something when something landed in it.
        if category != CATEGORY_OTHER or counts[category]
    ]


def _represented_file_count(finding: NormalizedFinding) -> int:
    """How many inspected regular files an aggregate context record stands in
    for. Absent, malformed, or negative values count as zero rather than
    inventing coverage."""
    try:
        count = int(finding.technical_metadata.get(FILESYSTEM_FILES_REPRESENTED_KEY) or 0)
    except (TypeError, ValueError):
        return 0
    return max(count, 0)


def _limitation_findings(findings: list[NormalizedFinding]) -> list[NormalizedFinding]:
    """Findings that record a constraint on coverage or on the observation itself."""
    return [finding for finding in findings if finding.limitations]


def _limitation_kind(finding: NormalizedFinding) -> str:
    """Grouping label for a limitation finding: its rule_id when the scanner
    supplied one (``max_depth_boundary``, ``directory_traversal_error``,
    ``skipped_special_file``, ...), otherwise its source type."""
    return finding.rule_id or finding.source_type


def _coverage_statement(
    findings: list[NormalizedFinding], context: ScanReportContext
) -> str | None:
    """A truthful coverage caveat, or None when nothing constrained the scan.

    Evidence-only: it states what was not inspected and why the report cannot
    be read as proof of complete coverage. It draws no conclusion and assigns
    no score.
    """
    limited = _limitation_findings(findings)
    if not limited and not context.scanner_errors:
        return None
    parts = []
    if context.scanner_errors:
        parts.append(f"{len(context.scanner_errors)} scanner error(s)")
    if limited:
        parts.append(f"{len(limited)} finding(s) with recorded limitations")
    return (
        "Coverage was not complete: this scan recorded "
        + " and ".join(parts)
        + ". Absence of a finding is not evidence that an asset was inspected "
        "and found clean; see Errors and Warnings and each finding's "
        "`limitations` field."
    )


def _configured_scope(context: ScanReportContext) -> list[str]:
    """Scope constraints the caller configured, as report-ready statements.

    A configured constraint is not a failure (see docs/SCAN_COVERAGE.md), but
    it does bound what the scan could observe, so it is recorded rather than
    silently dropped.
    """
    constraints = list(context.scope_constraints)
    if context.excluded_paths:
        constraints.append("Excluded patterns: " + ", ".join(context.excluded_paths))
    return constraints


def _coverage_status(coverage_statement: str | None, context: ScanReportContext) -> str:
    if coverage_statement:
        return "Not complete"
    if _configured_scope(context):
        # `--prefix` and `--exclude` bound coverage without producing
        # limitation findings, so "No limits recorded" would be untrue here.
        return "Bounded by configured scan scope"
    return "No limits recorded"


def _scope_lines(context: ScanReportContext) -> list[str]:
    """What this specific run covered: only the scanners that actually ran and
    the constraints that were actually configured."""
    lines = [f"- Target path: `{_inline_code(context.target_path)}`"]
    if context.scan_type:
        lines.append(f"- Scan type: `{_inline_code(context.scan_type)}`")
    if context.scanners:
        lines.append("- Scanners run: " + ", ".join(_md(name) for name in context.scanners))
    else:
        lines.append("- Scanners run: Not recorded")
    constraints = _configured_scope(context)
    if constraints:
        lines.append("- Configured scope constraints:")
        lines.extend(f"  - {_md(constraint)}" for constraint in constraints)
    else:
        lines.append("- Configured scope constraints: None recorded")
    return lines


def _executive_summary(counts: dict[str, int], findings: list[NormalizedFinding]) -> str:
    crypto_assets = sum(
        finding.source_type == "crypto_inventory"
        and "Malformed" not in finding.asset_type
        for finding in findings
    )
    # Inspected files, material evidence, and un-inspected scope are stated as
    # three separate quantities. A single "N total findings" sentence read as
    # if every ordinary scanned file were a material finding.
    return (
        f"HarvestGuard inspected {counts['files_scanned']} regular file(s) and "
        f"recorded {counts['material_evidence']} material evidence record(s): "
        f"{crypto_assets} cryptographic asset(s), {counts['sensitive_files']} "
        f"sensitive-data finding(s), {counts['semgrep_findings']} code-analysis "
        f"finding(s), {counts[CATEGORY_CLOUD_EVIDENCE]} cloud storage "
        f"finding(s), and {counts[CATEGORY_FILESYSTEM_FILE_EVIDENCE]} "
        "per-file filesystem evidence finding(s). It also recorded "
        f"{counts[CATEGORY_FILESYSTEM_CONTEXT]} aggregate filesystem context "
        f"record(s), {counts[CATEGORY_COVERAGE_LIMITATION]} coverage "
        f"limitation(s), and {counts[CATEGORY_SKIPPED_OR_INACCESSIBLE]} skipped "
        "or inaccessible entry record(s), for "
        f"{counts['total_records']} total normalized records."
    )


def _scanner_version_rows(
    findings: list[NormalizedFinding], context: ScanReportContext
) -> list[str]:
    """One row per scanner, counting findings but not depending on them.

    Every scanner the caller invoked appears with its version and a count --
    including a scanner that produced nothing and one that failed before
    producing anything -- because omitting it would hide both the version that
    ran and the fact that it ran at all. Scanners are keyed by normalized
    identity (`scanner_name`, `scanner_version`), so a finding whose scanner
    the caller did not declare is still reported.
    """
    counts: dict[tuple[str, str], int] = {
        (name, version): 0 for name, version in context.scanner_versions.items()
    }
    for finding in findings:
        key = (finding.scanner_name, finding.scanner_version)
        counts[key] = counts.get(key, 0) + 1
    if not counts:
        return ["| None | None | 0 |"]
    return [
        f"| {_md(scanner)} | {_md(version)} | {count} |"
        for (scanner, version), count in sorted(counts.items())
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
