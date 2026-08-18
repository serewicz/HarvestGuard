#!/usr/bin/env python3
"""Structured manifest and result handling for the HG-045 validation harness.

The harness itself is shell-first (see ``validation/run-validation.sh``). This
module exists only where structured work materially helps: freezing a manifest
with hashes before the scan, summarizing raw scanner output for the stage 7
review, and comparing observed findings against frozen expectations in stage 8.

It imports nothing from HarvestGuard. The harness observes the tool from the
outside, through its documented CLI and its JSON output, exactly as an operator
would -- so this file cannot accidentally validate HarvestGuard against
HarvestGuard's own internals.

Privacy: no passphrase, key, plaintext, or decrypted byte is ever read, stored,
or printed here. The only secret-adjacent value this module handles is the
per-run *marker* -- a prefix shared by every disposable passphrase the harness
generated -- which exists so stage 8 can prove nothing leaked without the
harness ever recording a secret.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from collections import Counter
from pathlib import Path
from typing import Any

MANIFEST_SCHEMA_VERSION = "1.0"
RESULT_SCHEMA_VERSION = "1.0"

# Findings that record a scan-scope boundary rather than a cryptographic
# observation. They are reported as coverage limitations, never as unexpected
# findings.
COVERAGE_RULE_IDS = frozenset(
    {
        "max_depth_boundary",
        "directory_traversal_error",
        "skipped_special_file",
    }
)

# Categories that mean "an operator has to look at this".
DISCREPANCY_CATEGORIES = frozenset(
    {
        "expected_finding_missing",
        "false_positive",
        "duplicate_finding",
        "accounting_mismatch",
        "output_privacy_violation",
        "scanner_error",
    }
)


# --------------------------------------------------------------- helpers ----


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    if not path.exists():
        return records
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise SystemExit(f"{path}:{line_number}: not valid JSON: {exc}") from exc
    return records


def _read_text(path: Path | None) -> str:
    if path is None or not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def _is_coverage_rule(rule_id: str) -> bool:
    return rule_id in COVERAGE_RULE_IDS or rule_id.startswith("volume_status:")


# ------------------------------------------------------------ stage 6/6 ----


def _walk_corpus(corpus_root: Path) -> list[Path]:
    if corpus_root.is_symlink():
        raise SystemExit(f"refusing symbolic link in validation corpus: {corpus_root}")
    paths: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(corpus_root):
        dirnames.sort()
        for name in dirnames:
            path = Path(dirpath) / name
            if path.is_symlink():
                raise SystemExit(f"refusing symbolic link in validation corpus: {path}")
        for name in sorted(filenames):
            path = Path(dirpath) / name
            if path.is_symlink():
                raise SystemExit(f"refusing symbolic link in validation corpus: {path}")
            paths.append(path)
    return paths


def freeze(args: argparse.Namespace) -> int:
    corpus_root = Path(args.corpus_root).resolve()
    output = Path(args.out)
    if output.exists():
        raise SystemExit(f"refusing to overwrite frozen manifest: {output}")
    records = _read_jsonl(Path(args.records))

    artifacts: list[dict[str, Any]] = []
    for record in records:
        relative_path = record.get("relative_path", "")
        target = corpus_root / relative_path
        entry = dict(record)
        if target.is_symlink():
            raise SystemExit(f"refusing symbolic link in validation corpus: {target}")
        if target.is_dir():
            entry["path_type"] = "directory"
            entry["sha256"] = None
            entry["size_bytes"] = None
            entry["directory_file_count"] = len(_walk_corpus(target))
        elif target.is_file():
            entry["path_type"] = "file"
            entry["sha256"] = _sha256_file(target)
            entry["size_bytes"] = target.stat().st_size
        else:
            entry["path_type"] = "missing"
            entry["sha256"] = None
            entry["size_bytes"] = None
        artifacts.append(entry)

    covered: set[Path] = set()
    for entry in artifacts:
        target = corpus_root / entry.get("relative_path", "")
        if target.is_dir():
            covered.update(_walk_corpus(target))
        else:
            covered.add(target)

    unmanifested = [
        str(path.relative_to(corpus_root))
        for path in _walk_corpus(corpus_root)
        if path not in covered
    ]

    skipped: list[dict[str, str]] = []
    for line in _read_text(Path(args.skipped) if args.skipped else None).splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) >= 3 and parts[0] in {"SKIP", "UNSUPPORTED"}:
            outcome = parts[3] if len(parts) >= 4 else (
                "unsupported" if parts[0] == "UNSUPPORTED" else "skipped"
            )
            skipped.append(
                {"generator": parts[1], "reason": parts[2], "outcome": outcome}
            )

    manifest = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "harness_version": args.harness_version,
        "run_id": args.run_id,
        "frozen_at": args.frozen_at,
        "host_os": args.host_os,
        "harvestguard_version": args.harvestguard_version,
        "scan_root": str(corpus_root),
        "scan_commands": list(args.scan_command or []),
        "operator_notes": args.operator_note or "",
        "secret_marker": args.secret_marker,
        "artifacts": artifacts,
        "skipped_generators": skipped,
        "unmanifested_corpus_files": unmanifested,
    }

    output.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"Frozen manifest written: {args.out}")
    print(f"  artifacts:            {len(artifacts)}")
    generated_count = sum(1 for a in artifacts if a["source_category"] == "generated")
    print(f"  generated:            {generated_count}")
    print(
        "  operator-supplied:    "
        f"{sum(1 for a in artifacts if a['source_category'] == 'operator-supplied')}"
    )
    print(f"  blind:                {sum(1 for a in artifacts if a['source_category'] == 'blind')}")
    print(f"  negative controls:    {sum(1 for a in artifacts if a.get('negative_control'))}")
    print(f"  skipped generators:   {len(skipped)}")
    print(f"  unmanifested files:   {len(unmanifested)}")
    return 0


# -------------------------------------------------------------- stage 7 ----


def summarize(args: argparse.Namespace) -> int:
    findings = json.loads(_read_text(Path(args.findings)) or "[]")
    print(f"Findings in {args.findings}: {len(findings)}")

    by_rule = Counter(finding.get("rule_id") or "(none)" for finding in findings)
    by_asset = Counter(finding.get("asset_type") or "(none)" for finding in findings)

    print("\nRule IDs observed:")
    for rule_id, count in sorted(by_rule.items()):
        print(f"  {count:4d}  {rule_id}")

    print("\nAsset types observed:")
    for asset_type, count in sorted(by_asset.items()):
        print(f"  {count:4d}  {asset_type}")

    errored = [f for f in findings if f.get("errors")]
    print(f"\nFindings carrying scanner errors: {len(errored)}")
    for finding in errored:
        print(f"  {finding.get('location')}: {'; '.join(str(e) for e in finding['errors'])}")

    limited = [f for f in findings if _is_coverage_rule(f.get("rule_id") or "")]
    print(f"\nFindings recording a coverage limitation: {len(limited)}")
    for finding in limited:
        print(f"  {finding.get('rule_id')}: {finding.get('location')}")

    duplicates = [
        finding_id
        for finding_id, count in Counter(f.get("finding_id") for f in findings).items()
        if count > 1
    ]
    print(f"\nRepeated finding IDs: {len(duplicates)}")
    print("\nThis is a raw summary only. No expectation has been compared yet.")
    return 0


# -------------------------------------------------------------- stage 8 ----


def _findings_for(location: str, findings: list[dict[str, Any]], is_directory: bool) -> list[dict]:
    matched = []
    for finding in findings:
        observed = finding.get("location") or ""
        if observed == location or observed.startswith(location + "#"):
            matched.append(finding)
        elif is_directory and observed.startswith(location + os.sep):
            matched.append(finding)
    return matched


def _validation_class(artifact: dict[str, Any]) -> str:
    category = artifact.get("source_category")
    if category == "generated":
        return "generated_validation"
    if category == "blind":
        return "blind_observation"
    return "operator_declared_validation"


def _finding_label(finding: dict[str, Any]) -> str:
    """How a finding is named in a report.

    HarvestGuard publishes a `rule_id` for some detectors and leaves it unset
    for others (the generic certificate, private-key, PKCS#12, and JKS-magic
    paths). A harness that could only match on `rule_id` would score every
    correctly detected artifact from those families as a false negative, so a
    finding without a rule ID is identified by its asset type instead -- which
    is the observable the CLI documents for those families.
    """
    rule_id = finding.get("rule_id")
    if rule_id:
        return str(rule_id)
    return f"asset_type={finding.get('asset_type') or '(none)'}"


def _match_mode(artifact: dict[str, Any]) -> str:
    if artifact.get("expected_rule_id"):
        return "rule_id"
    if artifact.get("expected_asset_type"):
        return "asset_type"
    return "none"


def _matches_expectation(finding: dict[str, Any], artifact: dict[str, Any]) -> bool:
    mode = _match_mode(artifact)
    if mode == "rule_id":
        return (finding.get("rule_id") or "") == artifact["expected_rule_id"]
    if mode == "asset_type":
        return (finding.get("asset_type") or "") == artifact["expected_asset_type"]
    return False


def _forbidden_hits(matched: list[dict[str, Any]], artifact: dict[str, Any]) -> list[dict]:
    forbidden_rules = set(artifact.get("forbidden_rule_ids") or [])
    forbidden_assets = set(artifact.get("forbidden_asset_types") or [])
    return [
        finding
        for finding in matched
        if (finding.get("rule_id") or "") in forbidden_rules
        or (finding.get("asset_type") or "") in forbidden_assets
    ]


def _evaluate_artifact(
    artifact: dict[str, Any], scan_root: Path, findings: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    relative_path = artifact.get("relative_path", "")
    location = str(scan_root / relative_path)
    is_directory = artifact.get("path_type") == "directory"
    matched = _findings_for(location, findings, is_directory)
    observed_labels = sorted({_finding_label(f) for f in matched})
    validation_class = _validation_class(artifact)

    base = {
        "artifact_id": artifact.get("artifact_id"),
        "relative_path": relative_path,
        "source_category": artifact.get("source_category"),
        "validation_class": validation_class,
        "negative_control": bool(artifact.get("negative_control")),
        "expected_rule_id": artifact.get("expected_rule_id") or None,
        "expected_asset_type": artifact.get("expected_asset_type") or None,
        "match_mode": _match_mode(artifact),
        "expected_finding_count": artifact.get("expected_finding_count", 0),
        "observed_finding_count": len(matched),
        "observed_findings": observed_labels,
    }
    results: list[dict[str, Any]] = []

    if validation_class == "blind_observation":
        results.append(
            {
                **base,
                "category": "blind_file_observation",
                "detail": (
                    "Blind input: no expectation was declared before the scan, so this "
                    "observation is neither correct nor incorrect. An operator must judge it."
                ),
            }
        )
        return results

    if artifact.get("path_type") == "missing":
        results.append(
            {
                **base,
                "category": "accounting_mismatch",
                "detail": "Manifest entry has no corresponding path in the frozen corpus.",
            }
        )
        return results

    expected_count = int(artifact.get("expected_finding_count") or 0)
    expectation = artifact.get("expected_rule_id") or artifact.get("expected_asset_type") or ""
    acknowledged = set(artifact.get("additional_expected") or [])

    if artifact.get("negative_control") or _match_mode(artifact) == "none":
        hits = _forbidden_hits(matched, artifact)
        if hits:
            results.append(
                {
                    **base,
                    "category": "false_positive",
                    "detail": (
                        "Negative control was reported under a forbidden rule or asset type: "
                        + ", ".join(sorted({_finding_label(h) for h in hits}))
                    ),
                }
            )
        else:
            results.append(
                {
                    **base,
                    "category": "expected_negative_remained_negative",
                    "detail": (
                        "No forbidden rule or asset type fired for this negative control."
                    ),
                }
            )
    else:
        on_target = [f for f in matched if _matches_expectation(f, artifact)]
        if expected_count > 0 and len(on_target) >= expected_count:
            results.append(
                {
                    **base,
                    "category": "expected_finding_observed",
                    "detail": (
                        f"{len(on_target)} finding(s) matched the expected {base['match_mode']} "
                        f"'{expectation}' (expected {expected_count})."
                    ),
                }
            )
            if len(on_target) > expected_count:
                results.append(
                    {
                        **base,
                        "category": "accounting_mismatch",
                        "detail": (
                            f"More findings than expected for '{expectation}': "
                            f"{len(on_target)} observed, {expected_count} expected."
                        ),
                    }
                )
        else:
            results.append(
                {
                    **base,
                    "category": "expected_finding_missing",
                    "detail": (
                        f"Expected {expected_count} finding(s) matching {base['match_mode']} "
                        f"'{expectation}', observed {len(on_target)}."
                    ),
                }
            )

    # Anything else reported at this location, that is neither the expectation,
    # an expectation the manifest already acknowledged, a forbidden hit already
    # reported above, nor a coverage limitation, is an observation the operator
    # should see.
    forbidden_ids = {id(f) for f in _forbidden_hits(matched, artifact)}
    others = sorted(
        {
            _finding_label(f)
            for f in matched
            if not _matches_expectation(f, artifact)
            and not _is_coverage_rule(f.get("rule_id") or "")
            and id(f) not in forbidden_ids
            and _finding_label(f) not in acknowledged
            and (f.get("asset_type") or "") not in acknowledged
        }
    )
    if others:
        results.append(
            {
                **base,
                "category": "unexpected_finding",
                "detail": "Additional finding(s) at this location: " + ", ".join(others),
            }
        )

    return results


def _privacy_check(marker: str, sources: dict[str, str]) -> list[dict[str, Any]]:
    violations: list[dict[str, Any]] = []
    needles = {
        "run secret marker": marker,
        "PEM private key block": "-----BEGIN PRIVATE KEY-----",
        "RSA private key block": "-----BEGIN RSA PRIVATE KEY-----",
        "EC private key block": "-----BEGIN EC PRIVATE KEY-----",
        "OpenSSH private key block": "-----BEGIN OPENSSH PRIVATE KEY-----",
    }
    for label, text in sources.items():
        if not text:
            continue
        for needle_label, needle in needles.items():
            if needle and needle in text:
                violations.append(
                    {
                        "category": "output_privacy_violation",
                        "validation_class": "generated_validation",
                        "detail": f"{needle_label} appears in {label}.",
                    }
                )
    return violations


def compare(args: argparse.Namespace) -> int:
    manifest = json.loads(_read_text(Path(args.manifest)))
    findings = json.loads(_read_text(Path(args.findings)) or "[]")
    scan_root = Path(manifest["scan_root"])

    results: list[dict[str, Any]] = []
    for artifact in manifest.get("artifacts", []):
        results.extend(_evaluate_artifact(artifact, scan_root, findings))

    for skipped in manifest.get("skipped_generators", []):
        outcome = skipped.get("outcome", "skipped")
        category = (
            "unsupported_generator" if outcome == "unsupported" else "skipped_generator"
        )
        results.append(
            {
                "category": category,
                "validation_class": category,
                "artifact_id": None,
                "relative_path": None,
                "detail": f"{skipped.get('generator')}: {skipped.get('reason')}",
            }
        )

    for path in manifest.get("unmanifested_corpus_files", []):
        results.append(
            {
                "category": "accounting_mismatch",
                "validation_class": "generated_validation",
                "artifact_id": None,
                "relative_path": path,
                "detail": "File was inside the frozen corpus but not represented in the manifest.",
            }
        )

    duplicate_ids = [
        finding_id
        for finding_id, count in Counter(f.get("finding_id") for f in findings).items()
        if count > 1
    ]
    for finding_id in duplicate_ids:
        results.append(
            {
                "category": "duplicate_finding",
                "validation_class": "generated_validation",
                "artifact_id": None,
                "relative_path": None,
                "detail": f"finding_id {finding_id} appears more than once in the JSON output.",
            }
        )

    # Artifacts whose manifest entry declared, before the scan, that a parse
    # attempt against them may record a scanner error (near-match negative
    # controls, and positives whose documented support is header-only). The
    # declaration is frozen with the manifest, so this never rewrites an
    # expectation after the fact.
    declared_error_locations = {
        str(scan_root / artifact.get("relative_path", ""))
        for artifact in manifest.get("artifacts", [])
        if artifact.get("expected_scanner_error")
    }

    for finding in findings:
        if finding.get("errors"):
            location = finding.get("location") or ""
            declared = any(
                location == declared or location.startswith(declared + "#")
                for declared in declared_error_locations
            )
            results.append(
                {
                    "category": "scanner_error",
                    "validation_class": "generated_validation",
                    "artifact_id": None,
                    "relative_path": location,
                    "declared_in_manifest": declared,
                    "detail": (
                        ("declared in advance for this artifact: " if declared else "")
                        + "; ".join(str(e) for e in finding["errors"])
                    ),
                }
            )
        if _is_coverage_rule(finding.get("rule_id") or ""):
            results.append(
                {
                    "category": "coverage_limitation",
                    "validation_class": "generated_validation",
                    "artifact_id": None,
                    "relative_path": finding.get("location"),
                    "detail": f"rule {finding.get('rule_id')} recorded a scope boundary.",
                }
            )

    commands = manifest.get("scan_commands", [])
    statuses = [
        ("console", args.console_exit_code),
        ("json", args.json_exit_code),
    ]
    if args.markdown_exit_code is not None:
        statuses.append(("markdown", args.markdown_exit_code))
    scan_invocations = [
        {
            "mode": mode,
            "argv": commands[index] if index < len(commands) else "",
            "exit_status": status,
        }
        for index, (mode, status) in enumerate(statuses)
    ]
    for invocation in scan_invocations:
        if invocation["exit_status"]:
            results.append(
                {
                    "category": "scanner_error",
                    "validation_class": "generated_validation",
                    "artifact_id": None,
                    "relative_path": None,
                    "detail": (
                        f"HarvestGuard {invocation['mode']} invocation exited with status "
                        f"{invocation['exit_status']}."
                    ),
                }
            )

    # The manifest legitimately records the marker itself (that is how a later
    # run can re-check an archived output), so the marker field is removed
    # before the manifest is searched for leaked secrets.
    manifest_without_marker = dict(manifest)
    manifest_without_marker.pop("secret_marker", None)

    results.extend(
        _privacy_check(
            manifest.get("secret_marker") or "",
            {
                "the console output": _read_text(Path(args.console) if args.console else None),
                "the JSON findings": _read_text(Path(args.findings)),
                "the Markdown report": _read_text(Path(args.markdown) if args.markdown else None),
                "the frozen manifest": json.dumps(manifest_without_marker),
            },
        )
    )

    counts = Counter(entry["category"] for entry in results)
    discrepancies = sum(
        1
        for entry in results
        if entry["category"] in DISCREPANCY_CATEGORIES and not entry.get("declared_in_manifest")
    )

    report = {
        "schema_version": RESULT_SCHEMA_VERSION,
        "run_id": manifest.get("run_id"),
        "harness_version": manifest.get("harness_version"),
        "harvestguard_version": manifest.get("harvestguard_version"),
        "scan_root": manifest.get("scan_root"),
        "scan_commands": manifest.get("scan_commands", []),
        "scan_invocations": scan_invocations,
        "manifest_path": str(args.manifest),
        "findings_path": str(args.findings),
        "operator_reviewed_raw_results": not args.non_interactive,
        "counts": dict(sorted(counts.items())),
        "discrepancy_count": discrepancies,
        "results": results,
        "caveat": (
            "Dry-run only: no cryptographic validation, scanner validation, or format "
            "support was exercised or established."
            if args.dry_run
            else "A passing generated fixture does not establish support for every valid "
            "form of a format. This harness validates the artifacts it actually generated "
            "on this host, nothing more."
        ),
    }

    Path(args.out_json).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    Path(args.out_markdown).write_text(_markdown_report(report), encoding="utf-8")

    print(f"Comparison report written: {args.out_json}")
    print(f"Human-readable report:     {args.out_markdown}")
    print("\nResult counts:")
    for category, count in sorted(counts.items()):
        print(f"  {count:4d}  {category}")
    print(f"\nEntries needing operator attention: {discrepancies}")
    return 1 if discrepancies else 0


_CLASS_TITLES = {
    "generated_validation": "Generated validation",
    "operator_declared_validation": "Operator-declared validation",
    "blind_observation": "Blind observations",
    "skipped_generator": "Skipped generators",
    "unsupported_generator": "Unsupported generators",
}


def _markdown_report(report: dict[str, Any]) -> str:
    lines = [
        "# HarvestGuard real-world validation report",
        "",
        f"- Run ID: `{report['run_id']}`",
        f"- Harness version: `{report['harness_version']}`",
        f"- HarvestGuard version: `{report['harvestguard_version']}`",
        f"- Scan root: `{report['scan_root']}`",
        f"- Raw results reviewed by an operator before comparison: "
        f"{'yes' if report['operator_reviewed_raw_results'] else 'NO (--non-interactive run)'}",
        f"- Entries needing operator attention: {report['discrepancy_count']}",
        "",
        "## Commands run against the frozen corpus",
        "",
    ]
    for command in report["scan_commands"]:
        lines.append(f"- `{command}`")
    lines += [
        "",
        "## Invocation exit statuses",
        "",
        "| Mode | Exit status |",
        "| --- | ---: |",
    ]
    for invocation in report["scan_invocations"]:
        lines.append(f"| {invocation['mode']} | {invocation['exit_status']} |")
    lines += ["", "## Result counts", "", "| Category | Count |", "| --- | --- |"]
    for category, count in report["counts"].items():
        lines.append(f"| {category} | {count} |")

    for class_key, title in _CLASS_TITLES.items():
        entries = [r for r in report["results"] if r.get("validation_class") == class_key]
        lines += ["", f"## {title}", ""]
        if not entries:
            lines.append("_None._")
            continue
        lines += ["| Category | Artifact | Path | Detail |", "| --- | --- | --- | --- |"]
        for entry in entries:
            lines.append(
                "| {} | {} | {} | {} |".format(
                    entry.get("category", ""),
                    entry.get("artifact_id") or "-",
                    entry.get("relative_path") or "-",
                    (entry.get("detail") or "").replace("|", "\\|"),
                )
            )

    lines += [
        "",
        "## Caveat",
        "",
        report["caveat"],
        "",
        "Blind-file observations are recorded, never scored: without an operator-provided",
        "expectation they are neither correct nor incorrect.",
        "",
    ]
    return "\n".join(lines)


# ----------------------------------------------------------------- entry ----


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    subparsers = parser.add_subparsers(dest="command", required=True)

    freeze_parser = subparsers.add_parser("freeze", help="Freeze the manifest before the scan")
    freeze_parser.add_argument("--corpus-root", required=True)
    freeze_parser.add_argument("--records", required=True)
    freeze_parser.add_argument("--out", required=True)
    freeze_parser.add_argument("--run-id", required=True)
    freeze_parser.add_argument("--harness-version", default="1")
    freeze_parser.add_argument("--frozen-at", default="")
    freeze_parser.add_argument("--host-os", default="")
    freeze_parser.add_argument("--harvestguard-version", default="")
    freeze_parser.add_argument("--secret-marker", default="")
    freeze_parser.add_argument("--scan-command", action="append", default=[])
    freeze_parser.add_argument("--skipped", default="")
    freeze_parser.add_argument("--operator-note", default="")
    freeze_parser.set_defaults(func=freeze)

    summarize_parser = subparsers.add_parser("summarize", help="Summarize raw findings JSON")
    summarize_parser.add_argument("--findings", required=True)
    summarize_parser.set_defaults(func=summarize)

    compare_parser = subparsers.add_parser("compare", help="Compare findings with the manifest")
    compare_parser.add_argument("--manifest", required=True)
    compare_parser.add_argument("--findings", required=True)
    compare_parser.add_argument("--console", default="")
    compare_parser.add_argument("--markdown", default="")
    compare_parser.add_argument("--console-exit-code", type=int, default=0)
    compare_parser.add_argument("--json-exit-code", type=int, default=0)
    compare_parser.add_argument("--markdown-exit-code", type=int, default=None)
    compare_parser.add_argument("--non-interactive", action="store_true")
    compare_parser.add_argument("--dry-run", action="store_true")
    compare_parser.add_argument("--out-json", required=True)
    compare_parser.add_argument("--out-markdown", required=True)
    compare_parser.set_defaults(func=compare)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
