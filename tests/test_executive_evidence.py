"""Regression coverage for the shared executive evidence projection (#151).

Every scenario here goes through the *real* evidence store and its verifying
load path: runs are written with `store_scan_run` and read back with
`load_executive_evidence_view`. Nothing mocks integrity verification, because
the behaviour under test is exactly what a verified stored run is allowed to
mean.
"""

from __future__ import annotations

import dataclasses
import json
import sqlite3
from datetime import datetime, timezone

import pytest

import evidence_store
from evidence_store import (
    EvidenceIntegrityError,
    EvidenceStoreError,
    ScanRunNotFoundError,
    compute_evidence_digest,
    load_scan_run,
    store_scan_run,
)
from executive_evidence import (
    CHECK_FAILED,
    CHECK_NOT_APPLICABLE,
    CHECK_PASSED,
    CHECK_UNKNOWN,
    EXECUTIVE_POLICY_VERSION,
    EXECUTIVE_SCHEMA_VERSION,
    EXPLANATION_BOUNDED_DERIVATION,
    EXPLANATION_CHECK_RESULT,
    EXPLANATION_OBSERVATION,
    STATUS_FAILED,
    STATUS_INCOMPLETE,
    STATUS_PRECEDENCE,
    STATUS_VERIFIED,
    STATUS_WARNING,
    EvidenceReference,
    ExecutiveEvidenceError,
    build_executive_evidence_view,
    load_executive_evidence_view,
)
from findings import NormalizedFinding
from reports import ScanReportContext, make_report_context, summarize_findings

SCAN_TIME = datetime(2024, 3, 4, 5, 6, 7, tzinfo=timezone.utc)
EXPORT_TIME = "2026-09-10T00:00:00+00:00"
LATER_EXPORT_TIME = "2030-01-01T00:00:00+00:00"


# --- fixtures --------------------------------------------------------------


def code_finding(scan_id="run-1", location="app.py:3", full_provenance=True, **kwargs):
    """A code-analysis record from the supported 0.2.0 collection contract."""
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


def certificate_finding(scan_id="run-1", expiration="2024-01-01T00:00:00+00:00", **kwargs):
    return NormalizedFinding(
        scan_id=scan_id,
        source_type="crypto_inventory",
        asset_type="X.509 Certificate",
        location="/target/server.pem",
        scanner_name="crypto_inventory",
        scanner_version="0.1.0",
        observed_at=SCAN_TIME,
        evidence="Parsed X.509 certificate",
        confidence="High",
        technical_metadata={"Expiration": expiration},
        collection_method="file_read",
        collection_source="local filesystem",
        repeatable=True,
        verification_rationale="re-parsing the same file reproduces the record",
        **kwargs,
    )


def filesystem_finding(scan_id="run-1", rule_id="max_depth_boundary", **kwargs):
    return NormalizedFinding(
        scan_id=scan_id,
        source_type="local_filesystem",
        asset_type="directory",
        location=f"/target/{rule_id}",
        scanner_name="filesystem",
        scanner_version="0.1.0",
        observed_at=SCAN_TIME,
        evidence="Directory not traversed",
        confidence="High",
        rule_id=rule_id,
        limitations=["subtree not traversed"],
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


def stored_view(tmp_path, context, findings, scan_id="run-1", export_time=EXPORT_TIME):
    tmp_path.mkdir(parents=True, exist_ok=True)
    db = tmp_path / "evidence.sqlite"
    store_scan_run(db, scan_id=scan_id, context=context, findings=list(findings))
    return load_executive_evidence_view(db, scan_id, export_time=export_time)


def rewrite_snapshots(db, scan_id, mutate, keep_digest_valid=True):
    """Rewrite stored snapshots, optionally re-digesting the run.

    With `keep_digest_valid=True` this produces a genuinely consistent stored
    run (as a different writer version would have written it), so the real
    loader accepts it. With `keep_digest_valid=False` it produces a corrupted
    run, which the real loader must reject.
    """
    connection = sqlite3.connect(str(db))
    connection.row_factory = sqlite3.Row
    row = connection.execute(
        "SELECT * FROM scan_runs WHERE scan_id = ?", (scan_id,)
    ).fetchone()
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


# --- status outcomes and precedence ---------------------------------------


def test_valid_empty_supported_execution_is_verified(tmp_path):
    view = stored_view(tmp_path, code_context(), [])
    assert view.status == STATUS_VERIFIED
    assert "VERIFIED" in view.status_statement
    assert view.status_reasons
    assert view.status_reasons[0].check_ids
    assert view.check("EV-CHK-004").state == CHECK_PASSED
    valid_empty = [record for record in view.conclusions if record.explanation_id == "EV-CON-003"]
    assert len(valid_empty) == 1
    assert "valid empty result" in valid_empty[0].statement
    assert valid_empty[0].nature == EXPLANATION_BOUNDED_DERIVATION


def test_empty_run_with_scanner_error_is_incomplete_not_valid_empty(tmp_path):
    view = stored_view(tmp_path, code_context(errors=["code analysis: exited nonzero"]), [])
    assert view.status == STATUS_INCOMPLETE
    assert view.check("EV-CHK-004").state == CHECK_UNKNOWN
    assert view.check("EV-CHK-001").state == CHECK_PASSED
    empty = view.conclusions[-1]
    assert "cannot be distinguished from output that was never produced" in empty.statement
    assert any("EV-CHK-004" in unknown for unknown in view.unknowns)


def test_unsupported_collection_contract_is_incomplete_not_absent_output(tmp_path):
    view = stored_view(tmp_path, code_context(versions={"semgrep_crypto_rules": "0.1.0"}), [])
    assert view.status == STATUS_INCOMPLETE
    assert view.check("EV-CHK-003").state == CHECK_UNKNOWN
    assert "0.1.0" in view.check("EV-CHK-003").statement
    # An empty error list must not be read as success for an unknown contract.
    assert view.check("EV-CHK-004").state == CHECK_UNKNOWN


def test_missing_scanner_provenance_is_incomplete(tmp_path):
    view = stored_view(tmp_path, code_context(versions={}), [])
    assert view.status == STATUS_INCOMPLETE
    assert view.check("EV-CHK-003").state == CHECK_UNKNOWN
    assert "no scanner/version pair" in view.check("EV-CHK-003").statement


def test_optional_provenance_omission_is_a_named_warning(tmp_path):
    view = stored_view(
        tmp_path, code_context(), [code_finding(full_provenance=False)]
    )
    assert view.status == STATUS_WARNING
    assert [record.exception_id for record in view.exceptions] == ["EV-EXC-001"]
    assert view.exceptions[0].references[0].ordinal == 0
    assert all(check.state == CHECK_PASSED for check in view.checks if check.applicable)


def test_reference_inconsistency_is_a_completed_failed_check(tmp_path):
    view = stored_view(
        tmp_path, code_context(), [code_finding(scan_id="a-different-run")]
    )
    assert view.status == STATUS_FAILED
    assert view.check("EV-CHK-005").state == CHECK_FAILED
    assert view.check("EV-CHK-005").references[0].ordinal == 0
    assert view.status_reasons[0].check_ids == ("EV-CHK-005",)


def test_failed_takes_precedence_but_other_results_are_retained(tmp_path):
    view = stored_view(
        tmp_path,
        code_context(errors=["code analysis: exited nonzero"]),
        [code_finding(scan_id="a-different-run", full_provenance=False)],
    )
    assert view.status == STATUS_FAILED
    reasons = {reason.reason_id for reason in view.status_reasons}
    assert {"EV-RSN-001", "EV-RSN-005", "EV-RSN-006"} <= reasons
    assert view.check("EV-CHK-004").state == CHECK_UNKNOWN
    assert [record.exception_id for record in view.exceptions] == ["EV-EXC-001"]
    assert view.unknowns


def test_status_precedence_order_is_declared():
    assert STATUS_PRECEDENCE == (
        STATUS_FAILED,
        STATUS_INCOMPLETE,
        STATUS_WARNING,
        STATUS_VERIFIED,
    )


def test_every_outcome_references_checks_or_exceptions(tmp_path):
    cases = [
        (code_context(), [], STATUS_VERIFIED),
        (code_context(), [code_finding(full_provenance=False)], STATUS_WARNING),
        (code_context(errors=["boom"]), [], STATUS_INCOMPLETE),
        (code_context(), [code_finding(scan_id="other")], STATUS_FAILED),
    ]
    seen = set()
    for index, (context, findings, expected) in enumerate(cases):
        view = stored_view(
            tmp_path / f"case-{index}", context, findings, scan_id=f"run-{index}"
        )
        assert view.status == expected
        seen.add(view.status)
        for reason in view.status_reasons:
            assert reason.check_ids or reason.exception_ids
    assert seen == set(STATUS_PRECEDENCE)


# --- partial findings, integrity and errors -------------------------------


def test_partial_findings_survive_a_recorded_failure_with_matching_digest(tmp_path):
    view = stored_view(
        tmp_path, code_context(errors=["code analysis: exited nonzero"]), [code_finding()]
    )
    assert view.status == STATUS_INCOMPLETE
    assert view.check("EV-CHK-001").state == CHECK_PASSED
    assert len(view.occurrences) == 1
    assert view.counts["code_analysis"] == 1
    assert view.scanner_errors == ("code analysis: exited nonzero",)
    assert any(
        record.explanation_id == "EV-OBS-004" and record.nature == EXPLANATION_OBSERVATION
        for record in view.observations
    )


def test_integrity_check_never_claims_authenticity(tmp_path):
    view = stored_view(tmp_path, code_context(), [code_finding()])
    integrity = view.check("EV-CHK-001")
    assert "not a signature" in " ".join(integrity.limitations)
    assert any("not a signature" in limit for limit in view.limits)


def test_finding_level_errors_are_a_named_exception(tmp_path):
    view = stored_view(
        tmp_path, code_context(), [code_finding(errors=["metadata unavailable"])]
    )
    assert view.status == STATUS_WARNING
    assert [record.exception_id for record in view.exceptions] == ["EV-EXC-002"]
    assert view.exceptions[0].details == ("metadata unavailable",)


@pytest.mark.parametrize(
    "statement", ["corrupt", "delete", "context"]
)
def test_rejected_runs_produce_no_view(tmp_path, statement):
    db = tmp_path / "evidence.sqlite"
    store_scan_run(db, scan_id="run-1", context=code_context(), findings=[code_finding()])
    if statement == "corrupt":
        rewrite_snapshots(
            db, "run-1", lambda snapshot: {**snapshot, "location": "tampered"},
            keep_digest_valid=False,
        )
    else:
        connection = sqlite3.connect(str(db))
        if statement == "delete":
            connection.execute("DELETE FROM scan_findings WHERE scan_id = 'run-1'")
        else:
            connection.execute("UPDATE scan_runs SET target_path = '/elsewhere'")
        connection.commit()
        connection.close()
    with pytest.raises(EvidenceIntegrityError):
        load_executive_evidence_view(db, "run-1", export_time=EXPORT_TIME)


def test_missing_run_and_missing_database_propagate_bounded_failures(tmp_path):
    db = tmp_path / "evidence.sqlite"
    store_scan_run(db, scan_id="run-1", context=code_context(), findings=[])
    with pytest.raises(ScanRunNotFoundError):
        load_executive_evidence_view(db, "absent", export_time=EXPORT_TIME)
    with pytest.raises(EvidenceStoreError):
        load_executive_evidence_view(tmp_path / "nope.sqlite", "run-1", export_time=EXPORT_TIME)


# --- schema, unknown fields, references ------------------------------------


def test_unknown_finding_schema_version_cannot_pass(tmp_path):
    view = stored_view(
        tmp_path, code_context(), [code_finding(schema_version="9.9.9")]
    )
    assert view.status == STATUS_INCOMPLETE
    assert view.check("EV-CHK-002").state == CHECK_UNKNOWN
    assert "9.9.9" in view.check("EV-CHK-002").statement
    assert view.check("EV-CHK-002").references[0].ordinal == 0
    # The record itself is still retained, unchanged.
    assert view.occurrences[0].finding.schema_version == "9.9.9"


def test_unrecognized_stored_fields_are_retained_and_named(tmp_path):
    db = tmp_path / "evidence.sqlite"
    store_scan_run(db, scan_id="run-1", context=code_context(), findings=[code_finding()])
    rewrite_snapshots(db, "run-1", lambda snapshot: {**snapshot, "future_field": "kept"})
    view = load_executive_evidence_view(db, "run-1", export_time=EXPORT_TIME)
    assert view.status == STATUS_WARNING
    assert [record.exception_id for record in view.exceptions] == ["EV-EXC-003"]
    assert view.exceptions[0].details == ("future_field",)
    assert view.occurrences[0].raw_snapshot["future_field"] == "kept"


def test_duplicate_finding_ids_resolve_to_separate_occurrences(tmp_path):
    duplicate = [
        code_finding(location="app.py:3", finding_id="shared-id"),
        code_finding(location="app.py:9", finding_id="shared-id"),
    ]
    view = stored_view(tmp_path, code_context(), duplicate)
    assert len(view.occurrences) == 2
    assert {occurrence.finding.finding_id for occurrence in view.occurrences} == {"shared-id"}
    first = view.resolve(EvidenceReference("run-1", 0, "shared-id"))
    second = view.resolve(EvidenceReference("run-1", 1, "shared-id"))
    assert first.finding.location != second.finding.location
    assert view.check("EV-CHK-005").state == CHECK_PASSED
    assert any(record.explanation_id == "EV-OBS-005" for record in view.observations)


def test_equal_sort_keys_keep_every_occurrence(tmp_path):
    identical = [code_finding(finding_id="same"), code_finding(finding_id="same")]
    view = stored_view(tmp_path, code_context(), identical)
    assert [occurrence.ordinal for occurrence in view.occurrences] == [0, 1]
    assert view.counts["total_records"] == 2


def test_reference_to_another_run_does_not_resolve(tmp_path):
    view = stored_view(tmp_path, code_context(), [code_finding()])
    with pytest.raises(KeyError):
        view.resolve(EvidenceReference("another-run", 0, None))
    with pytest.raises(KeyError):
        view.resolve(EvidenceReference("run-1", 7, None))


def test_the_same_finding_id_on_two_runs_stays_two_occurrences(tmp_path):
    """The same logical finding, observed twice, is two separate snapshots."""
    db = tmp_path / "evidence.sqlite"
    views = []
    for scan_id in ("run-1", "run-2"):
        store_scan_run(
            db,
            scan_id=scan_id,
            context=code_context(scan_id=scan_id),
            findings=[code_finding(scan_id=scan_id, finding_id="shared-id")],
        )
        views.append(load_executive_evidence_view(db, scan_id, export_time=EXPORT_TIME))
    first, second = views
    assert first.scan_id != second.scan_id
    assert (
        first.occurrences[0].finding.finding_id
        == second.occurrences[0].finding.finding_id
        == "shared-id"
    )
    assert first.occurrences[0].reference != second.occurrences[0].reference
    # Each run resolves its own occurrence, and neither resolves the other's.
    assert first.resolve(first.occurrences[0].reference).finding.scan_id == "run-1"
    with pytest.raises(KeyError):
        first.resolve(second.occurrences[0].reference)
    assert first.check("EV-CHK-005").state == CHECK_PASSED
    assert second.check("EV-CHK-005").state == CHECK_PASSED


# --- scope -----------------------------------------------------------------


def test_configured_scope_limits_are_disclosures_not_observability_failures(tmp_path):
    context = make_report_context(
        target_path="/target",
        started_at=SCAN_TIME,
        excluded_paths=["*.tmp"],
        scan_type="crypto",
        scanners=["crypto inventory"],
        scanner_versions={"filesystem": "0.1.0"},
        scope_constraints=["Maximum traversal depth: 2"],
        scan_id="run-1",
    )
    view = stored_view(tmp_path, context, [filesystem_finding(rule_id="max_depth_boundary")])
    assert view.check("EV-CHK-007").state == CHECK_PASSED
    scope_observation = next(
        record for record in view.observations if record.explanation_id == "EV-OBS-003"
    )
    assert "Maximum traversal depth: 2" in scope_observation.statement
    assert "*.tmp" in scope_observation.statement


def test_unexpected_inaccessible_scope_stays_visible(tmp_path):
    context = make_report_context(
        target_path="/target",
        started_at=SCAN_TIME,
        scan_type="crypto",
        scanners=["crypto inventory"],
        scanner_versions={"filesystem": "0.1.0"},
        scan_id="run-1",
    )
    view = stored_view(
        tmp_path, context, [filesystem_finding(rule_id="directory_traversal_error")]
    )
    check = view.check("EV-CHK-007")
    assert check.state == CHECK_UNKNOWN
    assert "directory_traversal_error" in check.statement
    assert check.references[0].ordinal == 0
    assert view.status == STATUS_INCOMPLETE


def test_not_applicable_check_states_a_scope_based_reason(tmp_path):
    view = stored_view(tmp_path, code_context(), [code_finding()])
    check = view.check("EV-CHK-008")
    assert check.state == CHECK_NOT_APPLICABLE
    assert check.applicable is False
    assert "declared scope includes no scanner" in check.not_applicable_reason
    assert any(reason.reason_id == "EV-RSN-007" for reason in view.status_reasons)


# --- time semantics --------------------------------------------------------


def test_certificate_expiration_is_dated_against_the_recorded_scan_time(tmp_path):
    # Expires after the scan but long before either export: the derivation must
    # describe the scan, not the export.
    view = stored_view(
        tmp_path,
        code_context(versions={"crypto_inventory": "0.1.0"}),
        [certificate_finding(expiration="2025-01-01T00:00:00+00:00")],
    )
    derivation = next(
        record for record in view.conclusions if record.explanation_id == "EV-CON-004"
    )
    assert derivation.nature == EXPLANATION_BOUNDED_DERIVATION
    assert "0 of 1" in derivation.statement
    assert view.counts["expired_certificates"] == 0
    assert view.check("EV-CHK-008").state == CHECK_PASSED


def test_export_date_does_not_change_a_historical_derivation(tmp_path):
    db = tmp_path / "evidence.sqlite"
    context = code_context(versions={"crypto_inventory": "0.1.0"})
    store_scan_run(
        db,
        scan_id="run-1",
        context=context,
        findings=[certificate_finding(expiration="2025-01-01T00:00:00+00:00")],
    )
    early = load_executive_evidence_view(db, "run-1", export_time=EXPORT_TIME)
    late = load_executive_evidence_view(db, "run-1", export_time=LATER_EXPORT_TIME)
    assert early.export_time != late.export_time
    assert early.conclusions == late.conclusions
    assert early.counts["expired_certificates"] == late.counts["expired_certificates"] == 0
    assert dataclasses.replace(early, export_time=late.export_time) == late


def test_absent_or_invalid_scan_time_yields_unknown_derivations(tmp_path):
    context = ScanReportContext(
        target_path="/target",
        scan_time="not-a-timestamp",
        scanners=["crypto inventory"],
        scanner_versions={"crypto_inventory": "0.1.0"},
        scan_id="run-1",
    )
    view = stored_view(tmp_path, context, [certificate_finding()])
    assert view.scan_time is None
    assert "unknown" in view.scan_time_basis
    assert view.check("EV-CHK-006").state == CHECK_UNKNOWN
    assert view.check("EV-CHK-008").state == CHECK_UNKNOWN
    assert "expired_certificates" not in view.counts
    assert any("Time-based derivations" in unknown for unknown in view.unknowns)
    assert view.status == STATUS_INCOMPLETE


def test_export_time_must_be_explicit(tmp_path):
    db = tmp_path / "evidence.sqlite"
    store_scan_run(db, scan_id="run-1", context=code_context(), findings=[])
    run = load_scan_run(db, "run-1")
    for bad in (None, "", "   "):
        with pytest.raises(ExecutiveEvidenceError):
            build_executive_evidence_view(run, export_time=bad)
    assert build_executive_evidence_view(
        run, export_time=datetime(2026, 9, 10, tzinfo=timezone.utc)
    ).export_time == "2026-09-10T00:00:00+00:00"


def test_fixed_evidence_and_export_time_produce_an_identical_projection(tmp_path):
    db = tmp_path / "evidence.sqlite"
    store_scan_run(
        db,
        scan_id="run-1",
        context=code_context(errors=["code analysis: exited nonzero"]),
        findings=[code_finding(), certificate_finding()],
    )
    first = load_executive_evidence_view(db, "run-1", export_time=EXPORT_TIME)
    second = load_executive_evidence_view(db, "run-1", export_time=EXPORT_TIME)
    assert first == second
    assert first.checks == second.checks
    assert [check.check_id for check in first.checks] == sorted(
        check.check_id for check in first.checks
    )
    assert [record.exception_id for record in first.exceptions] == sorted(
        record.exception_id for record in first.exceptions
    )


# --- versions, immutability and non-interference ---------------------------


def test_projection_versions_are_separate_from_producing_versions(tmp_path):
    db = tmp_path / "evidence.sqlite"
    store_scan_run(
        db,
        scan_id="run-1",
        context=code_context(),
        findings=[code_finding()],
        harvestguard_version="0.0.1-historical",
    )
    view = load_executive_evidence_view(
        db, "run-1", export_time=EXPORT_TIME, exporting_harvestguard_version="9.9.9"
    )
    assert view.producing_harvestguard_version == "0.0.1-historical"
    assert view.exporting_harvestguard_version == "9.9.9"
    assert view.schema_version == EXECUTIVE_SCHEMA_VERSION
    assert view.policy_version == EXECUTIVE_POLICY_VERSION
    assert view.finding_schema_version == "1.0.0"


def test_view_and_its_nested_records_are_immutable(tmp_path):
    view = stored_view(tmp_path, code_context(), [code_finding()])
    for target, attribute in (
        (view, "status"),
        (view.checks[0], "state"),
        (view.scope, "target_path"),
        (view.occurrences[0], "ordinal"),
    ):
        with pytest.raises(dataclasses.FrozenInstanceError):
            setattr(target, attribute, "changed")
    with pytest.raises(TypeError):
        view.counts["total_records"] = 99
    with pytest.raises(TypeError):
        view.occurrences[0].raw_snapshot["location"] = "changed"
    with pytest.raises(TypeError):
        view.occurrences[0].raw_snapshot["technical_metadata"]["Rule"] = "changed"


def test_projection_does_not_write_or_alter_stored_evidence(tmp_path):
    db = tmp_path / "evidence.sqlite"
    findings = [code_finding(), certificate_finding()]
    store_scan_run(db, scan_id="run-1", context=code_context(), findings=findings)
    before = db.read_bytes()
    stored = load_scan_run(db, "run-1")
    view = load_executive_evidence_view(db, "run-1", export_time=EXPORT_TIME)
    assert db.read_bytes() == before
    assert [occurrence.finding for occurrence in view.occurrences] == stored.findings
    assert [occurrence.finding.finding_id for occurrence in view.occurrences] == [
        finding.finding_id for finding in stored.findings
    ]
    assert view.scope.excluded_paths == tuple(stored.context.excluded_paths)
    assert view.scanner_errors == tuple(stored.context.scanner_errors)


def test_counts_reuse_the_existing_report_helpers(tmp_path):
    findings = [code_finding(), certificate_finding(), filesystem_finding()]
    view = stored_view(tmp_path, code_context(), findings)
    expected = summarize_findings(load_scan_run(
        tmp_path / "evidence.sqlite", "run-1"
    ).findings, reference_time=SCAN_TIME)
    assert dict(view.counts) == expected


def test_explanations_are_labelled_by_nature(tmp_path):
    view = stored_view(tmp_path, code_context(), [code_finding(), certificate_finding()])
    assert {record.nature for record in view.observations} == {EXPLANATION_OBSERVATION}
    assert {record.nature for record in view.conclusions} <= {
        EXPLANATION_CHECK_RESULT,
        EXPLANATION_BOUNDED_DERIVATION,
    }
    assert all(record.method for record in view.observations + view.conclusions)
    assert any("not assessed" in unknown for unknown in view.unknowns)


def test_a_non_stored_input_cannot_produce_a_view():
    with pytest.raises(ExecutiveEvidenceError):
        build_executive_evidence_view({"scan_id": "run-1"}, export_time=EXPORT_TIME)


# --- extended reporting helper: legacy defaults preserved ------------------


def test_expired_certificate_helper_keeps_its_legacy_default():
    expired = certificate_finding(expiration="2000-01-01T00:00:00+00:00")
    # No reference time: the historical current-clock behaviour, unchanged.
    assert summarize_findings([expired])["expired_certificates"] == 1
    # Explicit reference time before the expiration: dated, not clock-based.
    assert (
        summarize_findings([expired], reference_time=datetime(1999, 1, 1, tzinfo=timezone.utc))[
            "expired_certificates"
        ]
        == 0
    )
