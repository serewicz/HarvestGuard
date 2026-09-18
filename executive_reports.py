"""Markdown and executive-JSON serializers for the shared executive projection.

Both serializers are deliberately *thin*. Every status, count, reason,
reference, conclusion and exception they emit is read straight off the
`ExecutiveEvidenceView` built by `executive_evidence.py`: nothing here decides
what a stored run means, re-counts anything, re-verifies anything, or reads the
clock. The two formats carry the same assertions, outcomes, counts, references
and exceptions, and differ only in presentation -- so a reader comparing the
Markdown and the JSON for one stored run can never be told two different things.

Disclosure boundary (executive schema 0.1.0, see
docs/EXECUTIVE_EVIDENCE_VIEW.md). An executive export is a *disclosure view*,
not a copy of the evidence store:

- Recognized normalized-finding fields are disclosed with their exact stored
  values, taken from `FindingOccurrence.raw_snapshot` -- never from a
  reconstructed `NormalizedFinding`, whose defaults would invent a value for a
  field the stored snapshot never carried. A recognized field absent from the
  snapshot stays absent.
- Field *names* this release does not recognize are disclosed; their *values*
  are withheld, because an unrecognized field's content has no established
  privacy classification. Neither serializer ever falls back to emitting
  `raw_snapshot` wholesale.
- The exact raw snapshot, including withheld values, remains retained in the
  verified local evidence store and is covered unchanged by the existing
  evidence digest. The local store, not an export, is the technical-traceability
  source.

Markdown safety: every value read out of the projection is escaped, because a
filename, a scanner error or a stored identifier is untrusted text that must not
be able to inject a heading, a link, a table row or raw HTML into a document a
reader will trust. No escaped value is ever placed at the start of a line, so
list and heading constructs cannot be reopened, and nothing in a generated
document links to or fetches an external resource.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from types import MappingProxyType
from typing import Any

from executive_evidence import (
    CHECK_NOT_APPLICABLE,
    UNRECOGNIZED_FIELD_VALUE_DISCLOSURE,
    EvidenceReference,
    ExecutiveEvidenceView,
    FindingOccurrence,
)
from findings import NORMALIZED_FINDING_FIELD_ORDER, PROVENANCE_FIELD_ORDER

# The canonical recognized-field order, taken directly from findings.py's
# explicit field-order contract (shared with `NormalizedFinding.to_dict()` and
# `Provenance.to_dict()`) -- never discovered by constructing a probe
# NormalizedFinding, which would read the clock through __post_init__'s
# `observed_at` default the moment this module is imported. Re-exported under
# these names for existing callers.
RECOGNIZED_SNAPSHOT_FIELDS: tuple[str, ...] = NORMALIZED_FINDING_FIELD_ORDER
RECOGNIZED_PROVENANCE_FIELDS: tuple[str, ...] = PROVENANCE_FIELD_ORDER

# The one sentence that keeps withholding from being silent data loss. Owned by
# the shared executive projection (`executive_evidence`), not by this
# renderer; re-exported under this name for existing callers.
WITHHELD_VALUE_DISCLOSURE = UNRECOGNIZED_FIELD_VALUE_DISCLOSURE

_MARKDOWN_TITLE = "HarvestGuard Executive Evidence View"

# Exact headings required by the product contract: "Evidence checks and
# limitations", never an overall "Trust assessment"; "Supported conclusions and
# limits", never "Decision implication".
HEADING_OBSERVED = "What HarvestGuard observed"
HEADING_CHECKS = "Evidence checks and limitations"
HEADING_EXCEPTIONS = "Defined exceptions"
HEADING_CONCLUSIONS = "Supported conclusions and limits"
HEADING_TECHNICAL = "Technical evidence detail"

# Above this many exceptions the compact overview names them and links to their
# full statements instead of restating each one inline. It never drops one.
_OVERVIEW_EXCEPTION_DETAIL_LIMIT = 3


# --- Evidence-occurrence disclosure ----------------------------------------


def disclosed_snapshot(occurrence: FindingOccurrence) -> dict[str, Any]:
    """Recognized stored fields of one occurrence, in canonical field order.

    A thin read of `occurrence.disclosed_snapshot`: unknown-field
    classification is owned entirely by the shared executive projection
    (`executive_evidence._classify_snapshot`). This renderer does not decide
    what is recognized and does not reclassify `raw_snapshot` on its own.
    """
    return _json_ready(occurrence.disclosed_snapshot)


def unrecognized_field_names(occurrence: FindingOccurrence) -> list[str]:
    """Lexically sorted names of stored fields this release does not recognize.

    A thin read of `occurrence.unrecognized_field_names`, exactly as the
    shared executive projection classified them (including unrecognized
    direct `provenance` members, reported as `provenance.<member-name>`).
    Names only, never values.
    """
    return list(occurrence.unrecognized_field_names)


# --- Executive JSON --------------------------------------------------------


def executive_json_document(view: ExecutiveEvidenceView) -> dict[str, Any]:
    """The executive JSON document for one projected run, as a plain mapping.

    Field names and document order are the binding executive schema 0.1.0
    mapping documented in docs/EXECUTIVE_EVIDENCE_VIEW.md. This is *not* the
    existing `--json` shape: that option remains a bare normalized-finding
    array and is never reused for this envelope.
    """
    return {
        "executive_schema_version": view.schema_version,
        "executive_policy_version": view.policy_version,
        "scan_id": view.scan_id,
        "scan_time": view.scan_time,
        "scan_time_basis": view.scan_time_basis,
        "export_time": view.export_time,
        "producing_harvestguard_version": view.producing_harvestguard_version,
        "exporting_harvestguard_version": view.exporting_harvestguard_version,
        "finding_schema_version": view.finding_schema_version,
        "evidence_digest": view.evidence_digest,
        "scope": {
            "target_path": view.scope.target_path,
            "scan_type": view.scope.scan_type,
            "scanners": list(view.scope.scanners),
            "scanner_versions": dict(view.scope.scanner_versions),
            "excluded_paths": list(view.scope.excluded_paths),
            "scope_constraints": list(view.scope.scope_constraints),
            "crypto_files_inspected": view.scope.crypto_files_inspected,
        },
        "status": view.status,
        "status_statement": view.status_statement,
        "status_reasons": [
            {
                "reason_id": reason.reason_id,
                "statement": reason.statement,
                "check_ids": list(reason.check_ids),
                "exception_ids": list(reason.exception_ids),
            }
            for reason in view.status_reasons
        ],
        "checks": [
            {
                "check_id": check.check_id,
                "name": check.name,
                "title": check.title,
                "required": check.required,
                "applicable": check.applicable,
                "state": check.state,
                "method": check.method,
                "statement": check.statement,
                "references": [_reference_json(ref) for ref in check.references],
                "source_references": list(check.source_references),
                "limitations": list(check.limitations),
                "not_applicable_reason": check.not_applicable_reason,
            }
            for check in view.checks
        ],
        "exceptions": [
            {
                "exception_id": record.exception_id,
                "name": record.name,
                "statement": record.statement,
                "outcome_affecting": record.outcome_affecting,
                "references": [_reference_json(ref) for ref in record.references],
                "details": list(record.details),
            }
            for record in view.exceptions
        ],
        "observations": [_explanation_json(record) for record in view.observations],
        "conclusions": [_explanation_json(record) for record in view.conclusions],
        "unknowns": list(view.unknowns),
        "limits": list(view.limits),
        "counts": dict(view.counts),
        "scanner_errors": list(view.scanner_errors),
        "evidence": [
            {
                "ordinal": occurrence.ordinal,
                "finding_id": occurrence.finding.finding_id,
                "snapshot": disclosed_snapshot(occurrence),
                "unrecognized_field_names": unrecognized_field_names(occurrence),
            }
            for occurrence in view.occurrences
        ],
    }


def executive_json(view: ExecutiveEvidenceView) -> str:
    """Serialize the executive JSON document with a real JSON serializer."""
    return json.dumps(executive_json_document(view), indent=2)


def _reference_json(reference: EvidenceReference) -> dict[str, Any]:
    return {
        "scan_id": reference.scan_id,
        "ordinal": reference.ordinal,
        "finding_id": reference.finding_id,
    }


def _explanation_json(record: Any) -> dict[str, Any]:
    return {
        "explanation_id": record.explanation_id,
        "nature": record.nature,
        "statement": record.statement,
        "method": record.method,
        "references": [_reference_json(ref) for ref in record.references],
        "check_ids": list(record.check_ids),
        "limitations": list(record.limitations),
    }


def _json_ready(value: Any) -> Any:
    """A JSON-serializable copy of an exact stored value.

    The projection freezes stored payloads into `MappingProxyType`/tuples so a
    view cannot be mutated in place; this converts that back to plain
    dict/list without changing any value or any mapping's stored member order.
    """
    if isinstance(value, (Mapping, MappingProxyType)):
        return {str(key): _json_ready(item) for key, item in value.items()}
    if isinstance(value, (frozenset, set)):
        return sorted(_json_ready(item) for item in value)
    if isinstance(value, (list, tuple)) and not isinstance(value, (str, bytes)):
        return [_json_ready(item) for item in value]
    return value


# --- Executive Markdown ----------------------------------------------------


def format_executive_markdown(view: ExecutiveEvidenceView) -> str:
    """Render the executive Markdown document for one projected run.

    Same assertions, outcomes, counts, references and exceptions as
    `executive_json`; only the presentation differs.
    """
    lines: list[str] = [f"# {_MARKDOWN_TITLE}", ""]
    lines.extend(_overview_lines(view))
    lines.extend(_observation_lines(view))
    lines.extend(_check_lines(view))
    lines.extend(_exception_lines(view))
    lines.extend(_conclusion_lines(view))
    lines.extend(_technical_lines(view))
    return "\n".join(lines).rstrip("\n") + "\n"


def _overview_lines(view: ExecutiveEvidenceView) -> list[str]:
    """The compact overview: identity, qualified status, reasons, the three
    questions, and every defined exception.

    Nothing is truncated away here. When there are enough exceptions that
    restating each one inline would stop being an overview, they are named and
    linked to their full statements instead of dropped.
    """
    lines = [
        "## Overview",
        "",
        "| Field | Value |",
        "| --- | --- |",
        f"| Scan ID | {_escape(view.scan_id)} |",
        f"| Scan time | {_escape(view.scan_time if view.scan_time else 'not established')} |",
        f"| Scan-time basis | {_escape(view.scan_time_basis)} |",
        f"| Export time | {_escape(view.export_time)} |",
        f"| Scan type | {_escape(view.scope.scan_type or 'not recorded')} |",
        f"| Target | {_escape(view.scope.target_path)} |",
        f"| Produced by | HarvestGuard {_escape(view.producing_harvestguard_version)} |",
        f"| Exported by | HarvestGuard {_escape(view.exporting_harvestguard_version)} |",
        f"| Executive schema | {_escape(view.schema_version)} |",
        f"| Executive policy | {_escape(view.policy_version)} |",
        f"| Normalized finding schema | {_escape(view.finding_schema_version)} |",
        f"| Evidence digest | {_escape(view.evidence_digest or 'not recorded')} |",
        f"| Retained snapshot occurrences | {len(view.occurrences)} |",
        "",
        f"**Evidence evaluation: {_escape(view.status)}**",
        "",
        f"> {_escape(view.status_statement)}",
        "",
        "Why this evaluation:",
        "",
    ]
    for reason in view.status_reasons:
        lines.append(f"- {_escape(reason.reason_id)}: {_escape(reason.statement)}")
    lines.extend([
        "",
        "This view answers exactly three questions. It contains no risk score, "
        "no trust score, no remediation, no compliance verdict and no business "
        "judgment.",
        "",
        "1. **What did HarvestGuard observe?** "
        f"{view.counts.get('total_records', 0)} normalized record(s) were "
        f"retained, {view.counts.get('material_evidence', 0)} of them material "
        "evidence records -- see "
        f"[{HEADING_OBSERVED}]({_heading_anchor(HEADING_OBSERVED)}).",
        "2. **What evidence supports those observations?** "
        f"{len(view.occurrences)} retained snapshot occurrence(s) are listed "
        "individually under "
        f"[{HEADING_TECHNICAL}]({_heading_anchor(HEADING_TECHNICAL)}), and the "
        "identified checks over them under "
        f"[{HEADING_CHECKS}]({_heading_anchor(HEADING_CHECKS)}).",
        "3. **What can and cannot we conclude from that evidence?** See "
        f"[{HEADING_CONCLUSIONS}]({_heading_anchor(HEADING_CONCLUSIONS)}), "
        "which also lists what this view could not establish.",
        "",
    ])
    lines.extend(_overview_exception_lines(view))
    return lines


def _overview_exception_lines(view: ExecutiveEvidenceView) -> list[str]:
    anchor = _heading_anchor(HEADING_EXCEPTIONS)
    if not view.exceptions:
        return [
            "No defined exception was raised for this run. The closed set of "
            f"defined exceptions is listed under [{HEADING_EXCEPTIONS}]({anchor}).",
            "",
        ]
    named = ", ".join(
        f"{_escape(record.exception_id)} {_escape(record.name)}"
        for record in view.exceptions
    )
    lines = [
        f"Defined exception(s) needing attention ({len(view.exceptions)}): "
        f"{named}. Full statements, references and details are under "
        f"[{HEADING_EXCEPTIONS}]({anchor}).",
        "",
    ]
    if len(view.exceptions) <= _OVERVIEW_EXCEPTION_DETAIL_LIMIT:
        for record in view.exceptions:
            lines.append(
                f"- {_escape(record.exception_id)}: {_escape(record.statement)}"
            )
        lines.append("")
    return lines


def _observation_lines(view: ExecutiveEvidenceView) -> list[str]:
    lines = [f"## {HEADING_OBSERVED}", ""]
    for record in view.observations:
        lines.extend(_explanation_lines(view, record))
    lines.extend(["### Record counts", "", "| Count | Value |", "| --- | --- |"])
    for name, value in view.counts.items():
        lines.append(f"| {_escape(name)} | {value} |")
    lines.append("")
    lines.extend(["### Declared scope", "", "| Field | Value |", "| --- | --- |"])
    lines.extend([
        f"| Target path | {_escape(view.scope.target_path)} |",
        f"| Scan type | {_escape(view.scope.scan_type or 'not recorded')} |",
        f"| Scanners | {_join_or(view.scope.scanners, 'none recorded')} |",
        "| Scanner versions | "
        + (
            "; ".join(
                f"{_escape(name)} {_escape(version)}"
                for name, version in view.scope.scanner_versions.items()
            )
            or _escape("none recorded")
        )
        + " |",
        f"| Excluded paths | {_join_or(view.scope.excluded_paths, 'none')} |",
        f"| Scope constraints | {_join_or(view.scope.scope_constraints, 'none recorded')} |",
        "| Crypto files inspected | "
        + (
            str(view.scope.crypto_files_inspected)
            if view.scope.crypto_files_inspected is not None
            else _escape("not recorded")
        )
        + " |",
        "",
    ])
    lines.extend(["### Recorded scanner errors", ""])
    if view.scanner_errors:
        for error in view.scanner_errors:
            lines.append(f"- {_escape(error)}")
    else:
        lines.append(
            "- None recorded. An empty recorded-error list is interpreted only "
            "as far as the collection-contract check allows (EV-CHK-003, "
            "EV-CHK-004)."
        )
    lines.append("")
    return lines


def _check_lines(view: ExecutiveEvidenceView) -> list[str]:
    lines = [
        f"## {HEADING_CHECKS}",
        "",
        "Each row is an explicitly identified check. Required checks are "
        "selected by the executive policy version from the declared scope "
        "before any result is examined.",
        "",
        "| Check | Name | Required | Applicable | State |",
        "| --- | --- | --- | --- | --- |",
    ]
    for check in view.checks:
        lines.append(
            f"| {_escape(check.check_id)} | {_escape(check.name)} "
            f"| {_yes_no(check.required)} | {_yes_no(check.applicable)} "
            f"| {_escape(check.state)} |"
        )
    lines.append("")
    for check in view.checks:
        lines.extend([
            f"### {_escape(check.check_id)} {_escape(check.title)}",
            "",
            f"- State: {_escape(check.state)}",
            f"- Result: {_escape(check.statement)}",
            f"- Method: {_escape(check.method)}",
        ])
        if check.state == CHECK_NOT_APPLICABLE or check.not_applicable_reason:
            lines.append(
                "- Not applicable because: "
                f"{_escape(check.not_applicable_reason or 'no reason recorded')}"
            )
        for limitation in check.limitations:
            lines.append(f"- Limitation: {_escape(limitation)}")
        for source in check.source_references:
            lines.append(f"- Source: {_escape(source)}")
        lines.extend(_reference_lines(view, check.references))
        lines.append("")
    return lines


def _exception_lines(view: ExecutiveEvidenceView) -> list[str]:
    lines = [
        f"## {HEADING_EXCEPTIONS}",
        "",
        "Exceptions are a closed set defined by the executive policy version. "
        "An exception carries no severity, no priority and no recommendation.",
        "",
    ]
    if not view.exceptions:
        lines.extend(["No defined exception was raised for this run.", ""])
        return lines
    for record in view.exceptions:
        lines.extend([
            f"### {_escape(record.exception_id)} {_escape(record.name)}",
            "",
            f"- Statement: {_escape(record.statement)}",
            f"- Outcome-affecting: {_yes_no(record.outcome_affecting)}",
        ])
        for detail in record.details:
            lines.append(f"- Detail: {_escape(detail)}")
        lines.extend(_reference_lines(view, record.references))
        lines.append("")
    return lines


def _conclusion_lines(view: ExecutiveEvidenceView) -> list[str]:
    lines = [f"## {HEADING_CONCLUSIONS}", ""]
    for record in view.conclusions:
        lines.extend(_explanation_lines(view, record))
    lines.extend(["### What this view could not establish", ""])
    for unknown in view.unknowns:
        lines.append(f"- {_escape(unknown)}")
    lines.extend(["", "### Standing limits", ""])
    for limit in view.limits:
        lines.append(f"- {_escape(limit)}")
    lines.append("")
    return lines


def _explanation_lines(view: ExecutiveEvidenceView, record: Any) -> list[str]:
    lines = [
        f"### {_escape(record.explanation_id)} ({_escape(record.nature)})",
        "",
        f"- Statement: {_escape(record.statement)}",
        f"- Method: {_escape(record.method)}",
    ]
    for check_id in record.check_ids:
        lines.append(f"- Identified check: {_escape(check_id)}")
    for limitation in record.limitations:
        lines.append(f"- Limitation: {_escape(limitation)}")
    lines.extend(_reference_lines(view, record.references))
    lines.append("")
    return lines


def _technical_lines(view: ExecutiveEvidenceView) -> list[str]:
    lines = [
        f"## {HEADING_TECHNICAL}",
        "",
        "Every retained snapshot occurrence of this run, in canonical stored "
        "order. Occurrences that share a finding ID are separate occurrences "
        "and are listed separately; the complete reference to one occurrence is "
        "this run's scan ID plus its ordinal plus its finding ID. Recognized "
        "fields carry their exact stored values; a recognized field the stored "
        "snapshot did not carry is absent rather than defaulted.",
        "",
    ]
    if not view.occurrences:
        lines.extend([
            "This run retained no snapshot occurrence. Absence of a record is "
            "not evidence of absence.",
            "",
        ])
        return lines
    for occurrence in view.occurrences:
        lines.extend(_occurrence_lines(view, occurrence))
    return lines


def _occurrence_lines(
    view: ExecutiveEvidenceView, occurrence: FindingOccurrence
) -> list[str]:
    reference = occurrence.reference
    # An explicit anchor rather than a heading slug: the anchor has to be
    # derived from exact scan/snapshot identity and stay deterministic, and a
    # heading slug would depend on however the stored identifiers happen to be
    # punctuated.
    lines = [
        f'<a id="{_anchor_id(reference)}"></a>',
        "",
        f"### Occurrence {occurrence.ordinal}",
        "",
        f"- Complete reference: scan {_escape(reference.scan_id)}, ordinal "
        f"{reference.ordinal}, finding ID "
        f"{_escape(reference.finding_id if reference.finding_id else 'not recorded')}",
        "",
        "| Stored field | Value |",
        "| --- | --- |",
    ]
    for name, value in disclosed_snapshot(occurrence).items():
        if name == "provenance" and isinstance(value, dict):
            # Presentation only: the nested provenance object is flattened for
            # reading. The executive JSON keeps the documented nesting, and the
            # same recognized-member boundary applies in both formats.
            for member, member_value in value.items():
                lines.append(
                    f"| provenance.{_escape(member)} | {_value_cell(member_value)} |"
                )
            continue
        lines.append(f"| {_escape(name)} | {_value_cell(value)} |")
    lines.append("")
    withheld = unrecognized_field_names(occurrence)
    if withheld:
        lines.extend([
            "- Unrecognized stored field name(s), values withheld: "
            + ", ".join(f"`{_inline_code(name)}`" for name in withheld),
            f"- {_escape(WITHHELD_VALUE_DISCLOSURE)}",
            "",
        ])
    else:
        lines.extend([
            "- Unrecognized stored field name(s): none. Every stored field of "
            "this snapshot is recognized by the exporting version.",
            "",
        ])
    return lines


def _reference_lines(
    view: ExecutiveEvidenceView, references: Sequence[EvidenceReference]
) -> list[str]:
    """One line per evidence reference, linking to that occurrence's detail.

    Every reference resolves through the projection first, so a rendered link
    can never point at a technical-detail section this document does not
    contain.
    """
    lines = []
    for reference in references:
        view.resolve(reference)
        label = (
            f"{_escape(reference.scan_id)} ordinal {reference.ordinal} "
            f"(finding ID {_escape(reference.finding_id or 'not recorded')})"
        )
        lines.append(f"- Evidence: [{label}](#{_anchor_id(reference)})")
    return lines


# --- Small helpers ---------------------------------------------------------


def _anchor_id(reference: EvidenceReference) -> str:
    """A deterministic anchor for one occurrence's exact identity."""
    scan = "".join(
        char if char.isalnum() else "-" for char in str(reference.scan_id).lower()
    )
    return f"evidence-{scan}-{reference.ordinal}"


def _heading_anchor(heading: str) -> str:
    slug = "".join(char if char.isalnum() or char == " " else "" for char in heading)
    return "#" + slug.lower().replace(" ", "-")


# Backslash-escaped rather than stripped: the reader must still see exactly
# what was stored. Every ASCII character below is Markdown- or HTML-active,
# and a backslash escape is defined for all of them in CommonMark/GFM.
_MARKDOWN_ACTIVE = frozenset("\\`*_{}[]()#+-!|<>~&$")

# Nothing generated here ever links stored text to an external resource, so the
# two GFM extended-autolink triggers are neutralized as well. The inserted
# backslash escapes render as the original characters, so the disclosed value
# stays exactly what was stored.
_AUTOLINK_TRIGGERS = (("://", ":\\/\\/"), ("www.", "www\\."))


def _escape(value: Any) -> str:
    """Escape untrusted projection text for safe Markdown presentation.

    Every Markdown- and HTML-active character is backslash-escaped rather than
    removed, so a stored filename, scanner error or identifier cannot open a
    heading, a link, a table row or raw HTML, and is still shown exactly as it
    was stored. Line breaks become spaces, and no escaped value is ever placed
    at the start of a line, so block constructs cannot be reopened either.

    Presentation safety only -- never a substitute for the privacy boundary
    that decides what may be emitted at all.
    """
    text = str(value if value is not None else "")
    text = text.replace("\r\n", " ").replace("\r", " ").replace("\n", " ")
    text = text.replace("\t", " ")
    escaped = "".join(
        f"\\{char}" if char in _MARKDOWN_ACTIVE else char for char in text
    )
    for trigger, replacement in _AUTOLINK_TRIGGERS:
        escaped = escaped.replace(trigger, replacement)
    return escaped


def _inline_code(value: Any) -> str:
    """A value rendered inside inline code, with backticks neutralized."""
    return str(value if value is not None else "").replace("`", "'").replace("\n", " ")


def _value_cell(value: Any) -> str:
    """One exact stored value, rendered safely inside a table cell."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return _escape(value)
    if isinstance(value, str):
        return _escape(value)
    # Nested structures keep their stored member order and their exact values;
    # only the presentation is compacted.
    return _escape(json.dumps(_json_ready(value), sort_keys=False))


def _yes_no(value: bool) -> str:
    return "yes" if value else "no"


def _join_or(values: Sequence[str], empty: str) -> str:
    return "; ".join(_escape(value) for value in values) or _escape(empty)
