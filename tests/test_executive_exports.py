"""Regression coverage for the executive Markdown and JSON exports (#152).

Every scenario goes through the *real* path a user gets: a run written with
`store_scan_run`, read back through `evidence_store`'s verifying loader, one
shared `executive_evidence` projection, then a serializer -- usually driven
through the actual CLI. Nothing here mocks integrity verification, introduces a
second digest, or fabricates a projection, because the behaviour under test is
exactly what a *verified* stored run is allowed to disclose.

The canaries below are synthetic. They exist so a test can prove a withheld
value is absent from every generated artifact, and they match no real
credential shape.
"""

from __future__ import annotations

import json
import re
import socket
import sqlite3
from datetime import datetime, timezone

import pytest

import evidence_store
import executive_reports
import harvestguard
from evidence_store import compute_evidence_digest, load_scan_run, store_scan_run
from executive_evidence import (
    EvidenceReference,
    build_executive_evidence_view,
    load_executive_evidence_view,
)
from executive_reports import (
    RECOGNIZED_PROVENANCE_FIELDS,
    RECOGNIZED_SNAPSHOT_FIELDS,
    executive_json,
    executive_json_document,
    format_executive_markdown,
)
from findings import NormalizedFinding
from reports import make_report_context

SCAN_TIME = datetime(2024, 3, 4, 5, 6, 7, tzinfo=timezone.utc)
EXPORT_TIME = "2026-09-10T00:00:00+00:00"

# Synthetic secret-like values, only ever stored in *unrecognized* snapshot
# fields, so a disclosure view must never reproduce them.
CANARY = "SYNTHETIC-CANARY-VALUE-0000-NOT-A-REAL-SECRET"
NESTED_CANARY = "SYNTHETIC-NESTED-CANARY-0000-NOT-A-REAL-SECRET"


# --- fixtures --------------------------------------------------------------


def code_finding(scan_id="run-1", location="app.py:3", full_provenance=True, **kwargs):
    provenance = {}
    if full_provenance:
        provenance = {
            "collection_method": "static source-text match",
            "collection_source": "vendored semgrep rule set",
            "repeatable": True,
            "verification_rationale": "re-running the same rule set reproduces the match",
        }
    provenance.update(kwargs)
    return NormalizedFinding(
        scan_id=scan_id,
        source_type="code_analysis",
        asset_type="source_code",
        location=location,
        scanner_name="semgrep_crypto_rules",
        scanner_version="0.2.0",
        observed_at=SCAN_TIME,
        evidence="Semgrep rule matched: weak-hash-md5",
        confidence="High",
        rule_id="weak-hash-md5",
        technical_metadata={"Rule": "weak-hash-md5"},
        **provenance,
    )


def filesystem_finding(scan_id="run-1", rule_id="directory_traversal_error", **kwargs):
    return NormalizedFinding(
        scan_id=scan_id,
        source_type="local_filesystem",
        asset_type="directory",
        location=f"/target/{rule_id}",
        scanner_name="filesystem",
        scanner_version="0.1.0",
        observed_at=SCAN_TIME,
        evidence="Directory could not be traversed",
        confidence="High",
        rule_id=rule_id,
        collection_method="directory walk",
        collection_source="local filesystem",
        repeatable=True,
        verification_rationale="re-walking the same tree reproduces the record",
        **kwargs,
    )


def code_context(scan_id="run-1", versions=None, errors=None, **kwargs):
    return make_report_context(
        target_path="/target",
        started_at=SCAN_TIME,
        duration_seconds=1.5,
        scanner_errors=list(errors or []),
        scan_type="code",
        scanners=["code analysis"],
        scanner_versions=(
            {"semgrep_crypto_rules": "0.2.0"} if versions is None else dict(versions)
        ),
        scan_id=scan_id,
        **kwargs,
    )


def store(tmp_path, context=None, findings=(), scan_id="run-1"):
    """Write one run through the real store and return the database path."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    db = tmp_path / "evidence.sqlite"
    store_scan_run(
        db,
        scan_id=scan_id,
        context=context if context is not None else code_context(scan_id),
        findings=list(findings),
    )
    return db


def stored_view(tmp_path, context=None, findings=(), scan_id="run-1", export_time=EXPORT_TIME):
    db = store(tmp_path, context, findings, scan_id)
    return load_executive_evidence_view(db, scan_id, export_time=export_time)


def rewrite_snapshots(db, scan_id, mutate, keep_digest_valid=True):
    """Rewrite stored snapshots, optionally re-digesting the run.

    With `keep_digest_valid=True` the stored run stays genuinely consistent, as
    a different writer version would have written it, so the real loader
    accepts it. With `keep_digest_valid=False` the run is corrupt and the real
    loader must reject it.
    """
    connection = sqlite3.connect(str(db))
    connection.row_factory = sqlite3.Row
    row = connection.execute("SELECT * FROM scan_runs WHERE scan_id = ?", (scan_id,)).fetchone()
    run = {key: row[key] for key in evidence_store._RUN_KEYS}
    for key in evidence_store._STRUCTURED_RUN_KEYS:
        run[key] = json.loads(row[key])
    snapshots = [
        mutate(json.loads(record["finding_json"]))
        for record in connection.execute(
            "SELECT finding_json FROM scan_findings WHERE scan_id = ? ORDER BY ordinal",
            (scan_id,),
        )
    ]
    for ordinal, snapshot in enumerate(snapshots):
        connection.execute(
            "UPDATE scan_findings SET finding_json = ?, finding_id = ? "
            "WHERE scan_id = ? AND ordinal = ?",
            (
                json.dumps(snapshot, separators=(",", ":")),
                snapshot.get("finding_id"),
                scan_id,
                ordinal,
            ),
        )
    if keep_digest_valid:
        connection.execute(
            "UPDATE scan_runs SET evidence_digest = ? WHERE scan_id = ?",
            (compute_evidence_digest(run, snapshots), scan_id),
        )
    connection.commit()
    connection.close()


def run_cli(capsys, *args):
    """Run the CLI in-process and return (exit code, stdout, stderr)."""
    code = harvestguard.main(list(args))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def export_cli(capsys, db, *args, scan_id="run-1"):
    return run_cli(capsys, "evidence", "export", scan_id, "--evidence-db", str(db), *args)


# --- cross-format parity ---------------------------------------------------


def _markdown_ids(markdown: str) -> set[str]:
    """Every policy identifier the Markdown document mentions."""
    return set(re.findall(r"EV-(?:CHK|EXC|OBS|CON|RSN)\\?-\d+", markdown.replace("\\", "")))


def _json_ids(document: dict) -> set[str]:
    ids = {check["check_id"] for check in document["checks"]}
    ids |= {record["exception_id"] for record in document["exceptions"]}
    ids |= {record["reason_id"] for record in document["status_reasons"]}
    ids |= {
        record["explanation_id"]
        for record in document["observations"] + document["conclusions"]
    }
    return ids


def test_markdown_and_json_carry_the_same_assertions(tmp_path):
    view = stored_view(
        tmp_path,
        code_context(errors=["code analysis: exited nonzero"]),
        [code_finding(), filesystem_finding()],
    )
    document = executive_json_document(view)
    markdown = format_executive_markdown(view)

    assert _json_ids(document) == _markdown_ids(markdown)
    # Status, reasons, counts, exceptions and conclusions all appear in both.
    assert f"Evidence evaluation: {document['status']}" in markdown
    assert document["status_statement"].replace("\\", "") in _unescape(markdown)
    for reason in document["status_reasons"]:
        assert reason["statement"] in _unescape(markdown)
    for record in document["exceptions"] + document["observations"]:
        assert record["statement"] in _unescape(markdown)
    for record in document["conclusions"]:
        assert record["statement"] in _unescape(markdown)
    for unknown in document["unknowns"]:
        assert unknown in _unescape(markdown)
    for limit in document["limits"]:
        assert limit in _unescape(markdown)
    for name, value in document["counts"].items():
        assert f"| {name} | {value} |" in _unescape(markdown)
    for error in document["scanner_errors"]:
        assert error in _unescape(markdown)
    # Every occurrence, and every reference, is present in both.
    assert len(document["evidence"]) == 2
    for item in document["evidence"]:
        assert f"### Occurrence {item['ordinal']}" in markdown
        assert item["finding_id"] in markdown


def _unescape(markdown: str) -> str:
    """The rendered text of an escaped document, for substring comparison."""
    return re.sub(r"\\(.)", r"\1", markdown)


def test_headings_use_the_contract_wording(tmp_path):
    markdown = format_executive_markdown(stored_view(tmp_path, findings=[code_finding()]))
    assert "## Evidence checks and limitations" in markdown
    assert "## Supported conclusions and limits" in markdown
    assert "Trust assessment" not in markdown
    assert "Decision implication" not in markdown


def test_overview_answers_the_three_questions_and_names_the_sections(tmp_path):
    markdown = format_executive_markdown(stored_view(tmp_path, findings=[code_finding()]))
    overview = markdown.split("## What HarvestGuard observed")[0]
    assert "What did HarvestGuard observe?" in overview
    assert "What evidence supports those observations?" in overview
    assert "What can and cannot we conclude from that evidence?" in overview
    assert "Evidence checks and limitations" in overview
    assert "Supported conclusions and limits" in overview
    # Qualified status plus reason, never a bare word.
    assert "**Evidence evaluation: VERIFIED**" in overview
    assert "EV\\-RSN\\-004" in overview
    assert "required check" in overview


def test_overview_keeps_every_exception_and_links_to_full_detail(tmp_path):
    db = store(tmp_path, findings=[code_finding(full_provenance=False)])
    rewrite_snapshots(db, "run-1", lambda snapshot: {**snapshot, "future_field": CANARY})
    view = load_executive_evidence_view(db, "run-1", export_time=EXPORT_TIME)
    markdown = format_executive_markdown(view)
    overview = markdown.split("## What HarvestGuard observed")[0]
    for record in view.exceptions:
        assert record.exception_id.replace("-", "\\-") in overview
    assert "#defined-exceptions" in overview
    assert "## Defined exceptions" in markdown


# --- all four outcomes, empty and partial runs -----------------------------


@pytest.mark.parametrize(
    "context, findings, expected",
    [
        (code_context(), [], "VERIFIED"),
        (code_context(), [code_finding(full_provenance=False)], "WARNING"),
        (code_context(errors=["code analysis: exited nonzero"]), [], "INCOMPLETE"),
        (code_context(versions={"semgrep_crypto_rules": "0.1.0"}), [], "INCOMPLETE"),
    ],
)
def test_every_outcome_renders_truthfully(tmp_path, context, findings, expected):
    view = stored_view(tmp_path, context, findings)
    assert view.status == expected
    document = executive_json_document(view)
    markdown = format_executive_markdown(view)
    assert document["status"] == expected
    assert f"**Evidence evaluation: {expected}**" in markdown
    assert document["status_statement"] in _unescape(markdown)


def test_failed_outcome_renders_truthfully(tmp_path):
    db = store(tmp_path, findings=[code_finding()])
    # A stored snapshot recording a different run identity: EV-CHK-005 is the
    # check that can complete and fail.
    rewrite_snapshots(db, "run-1", lambda snapshot: {**snapshot, "scan_id": "other-run"})
    view = load_executive_evidence_view(db, "run-1", export_time=EXPORT_TIME)
    assert view.status == "FAILED"
    assert "**Evidence evaluation: FAILED**" in format_executive_markdown(view)
    assert executive_json_document(view)["status"] == "FAILED"


def test_valid_empty_run_never_claims_absence_is_proof(tmp_path):
    view = stored_view(tmp_path, code_context(), [])
    markdown = format_executive_markdown(view)
    document = executive_json_document(view)
    assert document["evidence"] == []
    assert "Absence of a record is not evidence of absence" in _unescape(markdown)
    assert any("valid empty result" in record["statement"] for record in document["conclusions"])


def test_partial_run_keeps_findings_collected_before_the_failure(tmp_path):
    view = stored_view(
        tmp_path, code_context(errors=["code analysis: exited nonzero"]), [code_finding()]
    )
    document = executive_json_document(view)
    assert view.status == "INCOMPLETE"
    assert len(document["evidence"]) == 1
    assert document["scanner_errors"] == ["code analysis: exited nonzero"]
    assert "code analysis: exited nonzero" in _unescape(format_executive_markdown(view))


def test_no_fail_on_error_history_still_reports_the_recorded_failure(tmp_path, capsys):
    db = store(tmp_path, code_context(errors=["code analysis: exited nonzero"]), [code_finding()])
    code, out, err = export_cli(capsys, db, "--executive-json")
    # Export-process success; the stored evaluation stays INCOMPLETE.
    assert code == 0
    document = json.loads(out)
    assert document["status"] == "INCOMPLETE"
    assert document["scanner_errors"] == ["code analysis: exited nonzero"]


# --- evidence-occurrence contract (schema 0.1.0) ---------------------------


def test_evidence_items_have_exactly_the_contracted_members_in_order(tmp_path):
    document = executive_json_document(
        stored_view(tmp_path, findings=[code_finding(), filesystem_finding()])
    )
    for item in document["evidence"]:
        assert list(item) == ["ordinal", "finding_id", "snapshot", "unrecognized_field_names"]
        assert isinstance(item["snapshot"], dict)
        assert isinstance(item["unrecognized_field_names"], list)


def test_snapshot_members_follow_canonical_normalized_finding_order(tmp_path):
    document = executive_json_document(stored_view(tmp_path, findings=[code_finding()]))
    snapshot = document["evidence"][0]["snapshot"]
    assert list(snapshot) == [
        name for name in RECOGNIZED_SNAPSHOT_FIELDS if name in snapshot
    ]
    assert list(snapshot["provenance"]) == [
        name for name in RECOGNIZED_PROVENANCE_FIELDS if name in snapshot["provenance"]
    ]


def test_shuffled_stored_member_order_still_serializes_canonically(tmp_path):
    db = store(tmp_path, findings=[code_finding()])
    rewrite_snapshots(
        db,
        "run-1",
        lambda snapshot: dict(reversed(list(snapshot.items()))),
    )
    view = load_executive_evidence_view(db, "run-1", export_time=EXPORT_TIME)
    snapshot = executive_json_document(view)["evidence"][0]["snapshot"]
    assert list(snapshot) == [
        name for name in RECOGNIZED_SNAPSHOT_FIELDS if name in snapshot
    ]


def test_absent_historical_fields_are_not_backfilled_from_reconstruction(tmp_path):
    db = store(tmp_path, findings=[code_finding()])
    rewrite_snapshots(
        db,
        "run-1",
        lambda snapshot: {
            key: value
            for key, value in snapshot.items()
            if key not in ("observed_at", "confidence_rationale", "identity_key")
        },
    )
    view = load_executive_evidence_view(db, "run-1", export_time=EXPORT_TIME)
    snapshot = executive_json_document(view)["evidence"][0]["snapshot"]
    assert "observed_at" not in snapshot
    assert "confidence_rationale" not in snapshot
    assert "identity_key" not in snapshot
    # Reconstruction would have supplied a current-clock observed_at.
    assert view.occurrences[0].finding.observed_at is None
    assert "observed\\_at" not in format_executive_markdown(view).split("### Occurrence 0")[1]


def test_recognized_values_come_from_the_stored_snapshot(tmp_path):
    db = store(tmp_path, findings=[code_finding()])
    rewrite_snapshots(
        db, "run-1", lambda snapshot: {**snapshot, "confidence": "Medium (as stored)"}
    )
    view = load_executive_evidence_view(db, "run-1", export_time=EXPORT_TIME)
    snapshot = executive_json_document(view)["evidence"][0]["snapshot"]
    assert snapshot["confidence"] == "Medium (as stored)"
    assert "Medium \\(as stored\\)" in format_executive_markdown(view)


def test_unrecognized_field_names_are_sorted_and_present_when_empty(tmp_path):
    document = executive_json_document(stored_view(tmp_path, findings=[code_finding()]))
    assert document["evidence"][0]["unrecognized_field_names"] == []

    db = store(tmp_path / "second", findings=[code_finding()])
    rewrite_snapshots(
        db,
        "run-1",
        lambda snapshot: {**snapshot, "zeta_field": CANARY, "alpha_field": CANARY},
    )
    view = load_executive_evidence_view(db, "run-1", export_time=EXPORT_TIME)
    names = executive_json_document(view)["evidence"][0]["unrecognized_field_names"]
    assert names == ["alpha_field", "zeta_field"]


def test_duplicate_finding_ids_stay_separate_occurrences_with_resolvable_references(tmp_path):
    view = stored_view(
        tmp_path,
        findings=[
            code_finding(location="app.py:3", finding_id="shared-id"),
            code_finding(location="app.py:9", finding_id="shared-id"),
        ],
    )
    document = executive_json_document(view)
    assert [item["ordinal"] for item in document["evidence"]] == [0, 1]
    assert {item["finding_id"] for item in document["evidence"]} == {"shared-id"}
    assert document["evidence"][0]["snapshot"]["location"] == "app.py:3"
    assert document["evidence"][1]["snapshot"]["location"] == "app.py:9"
    # Each complete reference resolves to its own exact local snapshot.
    for ordinal, location in ((0, "app.py:3"), (1, "app.py:9")):
        occurrence = view.resolve(
            EvidenceReference(scan_id=view.scan_id, ordinal=ordinal, finding_id="shared-id")
        )
        assert occurrence.raw_snapshot["location"] == location
    markdown = format_executive_markdown(view)
    assert "### Occurrence 0" in markdown and "### Occurrence 1" in markdown


def test_every_markdown_reference_anchor_resolves(tmp_path):
    view = stored_view(
        tmp_path,
        code_context(errors=["code analysis: exited nonzero"]),
        [
            code_finding(finding_id="shared-id", full_provenance=False),
            code_finding(location="app.py:9", finding_id="shared-id"),
            filesystem_finding(),
        ],
    )
    markdown = format_executive_markdown(view)
    anchors = set(re.findall(r'<a id="([^"]+)"></a>', markdown))
    targets = set(re.findall(r"\]\(#(evidence-[^)]+-\d+)\)", markdown))
    assert targets
    assert targets <= anchors
    assert len(anchors) == len(view.occurrences)


def test_markdown_and_json_disclose_the_same_boundary(tmp_path):
    db = store(tmp_path, findings=[code_finding()])
    rewrite_snapshots(
        db,
        "run-1",
        lambda snapshot: {
            **snapshot,
            "future_field": CANARY,
            "provenance": {**snapshot["provenance"], "future_provenance": NESTED_CANARY},
        },
    )
    view = load_executive_evidence_view(db, "run-1", export_time=EXPORT_TIME)
    document = executive_json_document(view)
    markdown = format_executive_markdown(view)
    names = document["evidence"][0]["unrecognized_field_names"]
    assert names == ["future_field", "provenance.future_provenance"]
    for name in names:
        assert name in markdown
    assert "values withheld" in markdown
    assert executive_reports.WITHHELD_VALUE_DISCLOSURE in _unescape(markdown)
    # Both formats state the withholding and the continued local retention.
    assert any(
        "withheld" in record["statement"] and "evidence store" in record["statement"]
        for record in document["exceptions"]
    )


# --- privacy ---------------------------------------------------------------


def test_canary_values_are_absent_from_every_generated_artifact(tmp_path, capsys):
    db = store(tmp_path, findings=[code_finding()])
    rewrite_snapshots(
        db,
        "run-1",
        lambda snapshot: {
            **snapshot,
            "future_field": CANARY,
            "provenance": {**snapshot["provenance"], "future_provenance": NESTED_CANARY},
        },
    )
    json_path = tmp_path / "executive.json"
    markdown_path = tmp_path / "executive.md"
    for option, destination in (
        ("--executive-json", json_path),
        ("--executive-markdown", markdown_path),
    ):
        code, out, err = export_cli(capsys, db, option, str(destination))
        assert code == 0
        for stream in (out, err, destination.read_text(encoding="utf-8")):
            assert CANARY not in stream
            assert NESTED_CANARY not in stream
    # The withheld values are still retained, unchanged, in the store itself.
    stored = load_scan_run(db, "run-1")
    assert stored.raw_finding_snapshots[0]["future_field"] == CANARY
    assert stored.raw_finding_snapshots[0]["provenance"]["future_provenance"] == NESTED_CANARY


def test_changing_only_an_unrecognized_value_fails_closed(tmp_path, capsys):
    db = store(tmp_path, findings=[code_finding()])
    rewrite_snapshots(db, "run-1", lambda snapshot: {**snapshot, "future_field": "original"})
    destination = tmp_path / "executive.json"
    assert export_cli(capsys, db, "--executive-json", str(destination))[0] == 0
    previous = destination.read_text(encoding="utf-8")

    # Only the unrecognized value changes, and the digest is not updated: the
    # existing digest covers the complete raw snapshot, so the run is rejected.
    rewrite_snapshots(
        db,
        "run-1",
        lambda snapshot: {**snapshot, "future_field": CANARY},
        keep_digest_valid=False,
    )
    code, out, err = export_cli(capsys, db, "--executive-json", str(destination))
    assert code == 1
    assert out == ""
    assert "run-1" in err
    assert CANARY not in err
    assert destination.read_text(encoding="utf-8") == previous


def test_no_raw_snapshot_wholesale_fallback(tmp_path):
    db = store(tmp_path, findings=[code_finding()])
    rewrite_snapshots(db, "run-1", lambda snapshot: {**snapshot, "future_field": CANARY})
    view = load_executive_evidence_view(db, "run-1", export_time=EXPORT_TIME)
    serialized = executive_json(view)
    assert "future_field" in serialized  # the name is disclosed
    assert CANARY not in serialized  # the value is not
    assert json.loads(serialized)["evidence"][0]["snapshot"].get("future_field") is None


# --- failing closed -------------------------------------------------------


def test_digest_mismatch_emits_no_normal_report_and_preserves_the_destination(
    tmp_path, capsys
):
    db = store(tmp_path, findings=[code_finding()])
    destination = tmp_path / "executive.md"
    destination.write_text("PREVIOUS VALID ARTIFACT\n", encoding="utf-8")
    rewrite_snapshots(
        db, "run-1", lambda snapshot: {**snapshot, "evidence": "edited"}, keep_digest_valid=False
    )
    code, out, err = export_cli(capsys, db, "--executive-markdown", str(destination))
    assert code == 1
    assert out == ""
    assert "Evidence evaluation" not in err
    assert "edited" not in err
    assert destination.read_text(encoding="utf-8") == "PREVIOUS VALID ARTIFACT\n"
    assert not list(tmp_path.glob(".executive.md.*"))


def test_deleted_snapshots_fail_closed(tmp_path, capsys):
    db = store(tmp_path, findings=[code_finding(), filesystem_finding()])
    connection = sqlite3.connect(str(db))
    connection.execute("DELETE FROM scan_findings WHERE ordinal = 1")
    connection.commit()
    connection.close()
    code, out, err = export_cli(capsys, db, "--executive-json")
    assert code == 1
    assert out == ""
    assert "Error:" in err


def test_corrupt_database_fails_closed(tmp_path, capsys):
    db = tmp_path / "evidence.sqlite"
    db.write_bytes(b"this is not a SQLite database")
    code, out, err = export_cli(capsys, db, "--executive-markdown")
    assert code == 1
    assert out == ""
    assert "Error:" in err


def test_unsupported_store_schema_version_fails_closed(tmp_path, capsys):
    db = store(tmp_path, findings=[code_finding()])
    connection = sqlite3.connect(str(db))
    connection.execute("PRAGMA user_version = 99")
    connection.commit()
    connection.close()
    code, out, err = export_cli(capsys, db, "--executive-json")
    assert code == 1
    assert out == ""
    assert "99" in err


def test_missing_run_and_missing_database_fail_closed(tmp_path, capsys):
    db = store(tmp_path, findings=[code_finding()])
    code, out, err = export_cli(capsys, db, "--executive-json", scan_id="absent-run")
    assert code == 1 and out == "" and "absent-run" in err
    code, out, err = export_cli(capsys, tmp_path / "missing.sqlite", "--executive-json")
    assert code == 1 and out == ""


# --- atomic output --------------------------------------------------------


def test_write_failure_preserves_an_existing_valid_destination(tmp_path, capsys):
    db = store(tmp_path, findings=[code_finding()])
    destination = tmp_path / "exports"
    destination.mkdir()  # a directory cannot be replaced by a file
    code, out, err = export_cli(capsys, db, "--executive-json", str(destination))
    assert code == 1
    assert "could not write" in err
    assert destination.is_dir()
    assert list(destination.iterdir()) == []
    assert not list(tmp_path.glob(".exports.*"))


def test_write_failure_into_a_missing_directory_leaves_nothing_behind(tmp_path, capsys):
    db = store(tmp_path, findings=[code_finding()])
    target = tmp_path / "absent" / "executive.json"
    code, out, err = export_cli(capsys, db, "--executive-json", str(target))
    assert code == 1
    assert "could not write" in err
    assert not target.exists()
    assert not (tmp_path / "absent").exists()


def test_successful_export_replaces_an_existing_destination_atomically(tmp_path, capsys):
    db = store(tmp_path, findings=[code_finding()])
    destination = tmp_path / "executive.json"
    destination.write_text("PREVIOUS\n", encoding="utf-8")
    code, out, err = export_cli(capsys, db, "--executive-json", str(destination))
    assert code == 0
    assert out == ""
    assert f"Wrote executive evidence JSON: {destination}" in err
    assert json.loads(destination.read_text(encoding="utf-8"))["scan_id"] == "run-1"
    assert not list(tmp_path.glob(".executive.json.*"))


def test_quiet_suppresses_progress_but_not_output(tmp_path, capsys):
    db = store(tmp_path, findings=[code_finding()])
    destination = tmp_path / "executive.md"
    code, out, err = export_cli(capsys, db, "--executive-markdown", str(destination), "--quiet")
    assert code == 0
    assert err == ""
    assert destination.read_text(encoding="utf-8").startswith("# HarvestGuard Executive")


def test_stdout_is_the_default_destination(tmp_path, capsys):
    db = store(tmp_path, findings=[code_finding()])
    for args in (("--executive-json",), ("--executive-json", "-")):
        code, out, err = export_cli(capsys, db, *args)
        assert code == 0
        assert json.loads(out)["scan_id"] == "run-1"
    for args in (("--executive-markdown",), ("--executive-markdown", "-")):
        code, out, err = export_cli(capsys, db, *args)
        assert code == 0
        assert out.startswith("# HarvestGuard Executive Evidence View")


# --- CLI surface and compatibility ----------------------------------------


@pytest.mark.parametrize(
    "conflicting",
    [
        ("--executive-json", "--executive-markdown"),
        ("--executive-json", "--json"),
        ("--executive-markdown", "--markdown"),
        ("--executive-markdown", "--summary"),
    ],
)
def test_executive_options_are_mutually_exclusive(tmp_path, conflicting):
    db = store(tmp_path, findings=[code_finding()])
    with pytest.raises(SystemExit) as excinfo:
        harvestguard.main(
            ["evidence", "export", "run-1", "--evidence-db", str(db), *conflicting]
        )
    assert excinfo.value.code == harvestguard.EXIT_USAGE


def test_no_public_export_time_option_exists(tmp_path):
    db = store(tmp_path, findings=[code_finding()])
    with pytest.raises(SystemExit) as excinfo:
        harvestguard.main(
            [
                "evidence",
                "export",
                "run-1",
                "--evidence-db",
                str(db),
                "--executive-json",
                "--export-time",
                EXPORT_TIME,
            ]
        )
    assert excinfo.value.code == harvestguard.EXIT_USAGE


def test_scan_command_has_no_executive_options(tmp_path):
    with pytest.raises(SystemExit):
        harvestguard.main(["scan", str(tmp_path), "--executive-json"])


def test_existing_export_modes_are_unchanged(tmp_path, capsys):
    findings = [code_finding(), filesystem_finding()]
    db = store(tmp_path, findings=findings)
    stored = load_scan_run(db, "run-1")

    code, out, err = export_cli(capsys, db, "--json")
    assert code == 0
    payload = json.loads(out)
    assert isinstance(payload, list)
    assert [item["finding_id"] for item in payload] == [
        item["finding_id"] for item in json.loads(harvestguard.findings_json(stored.findings))
    ]
    assert out.rstrip("\n") == harvestguard.findings_json(stored.findings)

    code, out, err = export_cli(capsys, db, "--markdown")
    assert code == 0
    assert out.rstrip("\n") == harvestguard.format_markdown_report(
        stored.findings, stored.context, stored.harvestguard_version
    ).rstrip("\n")

    code, out, err = export_cli(capsys, db, "--summary")
    assert code == 0
    assert out.rstrip("\n") == harvestguard.format_console_summary(
        stored.findings, stored.context
    ).rstrip("\n")


# --- explicit export time and determinism ---------------------------------


def test_cli_captures_exactly_one_utc_export_time(tmp_path, capsys, monkeypatch):
    db = store(tmp_path, findings=[code_finding()])
    calls: list[object] = []
    fixed = datetime(2026, 9, 11, 12, 30, 45, tzinfo=timezone.utc)

    class OneShotClock(datetime):
        @classmethod
        def now(cls, tz=None):
            calls.append(tz)
            return fixed

    monkeypatch.setattr(harvestguard, "datetime", OneShotClock)
    code, out, err = export_cli(capsys, db, "--executive-json")
    assert code == 0
    assert calls == [timezone.utc]
    assert json.loads(out)["export_time"] == fixed.isoformat()


def test_serializers_never_read_the_clock(tmp_path, monkeypatch):
    view = stored_view(tmp_path, findings=[code_finding()])

    class ForbiddenClock(datetime):
        @classmethod
        def now(cls, tz=None):  # pragma: no cover - must never be called
            raise AssertionError("a serializer must not read the clock")

    monkeypatch.setattr("executive_evidence.datetime", ForbiddenClock)
    monkeypatch.setattr("harvestguard.datetime", ForbiddenClock)
    first_json, first_markdown = executive_json(view), format_executive_markdown(view)
    second_json, second_markdown = executive_json(view), format_executive_markdown(view)
    assert first_json == second_json
    assert first_markdown == second_markdown
    assert EXPORT_TIME in first_json


def test_fixed_inputs_and_export_time_are_deterministic(tmp_path):
    findings = [code_finding(), code_finding(location="app.py:9"), filesystem_finding()]
    first = stored_view(tmp_path / "a", findings=findings)
    second = stored_view(tmp_path / "b", findings=findings)
    assert executive_json(first) == executive_json(second)
    assert format_executive_markdown(first) == format_executive_markdown(second)


def test_local_export_needs_no_networking(tmp_path, monkeypatch):
    view = stored_view(tmp_path, findings=[code_finding()])

    def forbidden(*args, **kwargs):  # pragma: no cover - must never be called
        raise AssertionError("executive export must not open a socket")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    assert executive_json(view)
    assert format_executive_markdown(view)


# --- escaping, Unicode and scale ------------------------------------------


def test_markdown_metacharacters_and_unicode_cannot_inject_markup(tmp_path):
    hostile = (
        "/target/# Heading\n[link](http://example.test) "
        "<script>alert(1)</script> | ✅ ünïcode"
    )
    view = stored_view(
        tmp_path,
        code_context(errors=[f"code analysis: failed on {hostile}"]),
        [code_finding(location=hostile)],
    )
    markdown = format_executive_markdown(view)
    body = markdown.split("## Overview", 1)[1]
    for line in body.splitlines():
        assert not line.startswith("# ")
        assert not line.startswith("## Heading")
    assert "<script>" not in markdown
    assert "\\<script\\>" in markdown
    assert "[link](http" not in markdown
    assert "✅ ünïcode" in markdown
    # The exact stored value survives in the machine-readable form.
    assert executive_json_document(view)["evidence"][0]["snapshot"]["location"] == hostile


def test_large_record_sets_keep_every_occurrence(tmp_path):
    findings = [code_finding(location=f"app.py:{index}") for index in range(250)]
    view = stored_view(tmp_path, findings=findings)
    document = executive_json_document(view)
    markdown = format_executive_markdown(view)
    assert [item["ordinal"] for item in document["evidence"]] == list(range(250))
    assert markdown.count("<a id=\"evidence-") == 250
    assert "### Occurrence 249" in markdown


def test_exported_view_matches_a_directly_built_projection(tmp_path, capsys):
    db = store(tmp_path, findings=[code_finding()])
    code, out, err = export_cli(capsys, db, "--executive-json")
    assert code == 0
    exported = json.loads(out)
    direct = executive_json_document(
        build_executive_evidence_view(load_scan_run(db, "run-1"), export_time=EXPORT_TIME)
    )
    exported.pop("export_time")
    direct.pop("export_time")
    assert exported == direct


def test_non_object_provenance_keeps_its_exact_stored_value(tmp_path):
    # A payload whose `provenance` is not the documented nested object: the
    # field is still recognized, so its exact stored value is disclosed and
    # nothing is reconstructed in its place.
    db = store(tmp_path, findings=[code_finding()])
    rewrite_snapshots(db, "run-1", lambda snapshot: {**snapshot, "provenance": "as stored"})
    view = load_executive_evidence_view(db, "run-1", export_time=EXPORT_TIME)
    snapshot = executive_json_document(view)["evidence"][0]["snapshot"]
    assert snapshot["provenance"] == "as stored"
    assert "as stored" in format_executive_markdown(view)
