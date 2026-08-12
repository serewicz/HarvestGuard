"""Durable local evidence chain: scan identity, persistence, integrity, export.

Covers the HG-046 regression matrix: one CLI scan can be given a run identity,
stored locally, verified, and re-exported through the existing report
formatters without rescanning the target -- and a stored run that has become
internally inconsistent is refused rather than presented as evidence.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from dataclasses import replace
from pathlib import Path

import pytest

import evidence_store
import harvestguard
from evidence_store import (
    DuplicateScanRunError,
    EvidenceIntegrityError,
    EvidenceStoreError,
    ScanRunNotFoundError,
    list_scan_runs,
    load_scan_run,
    store_scan_run,
)
from findings import NormalizedFinding, finding_from_dict
from harvestguard_version import __version__ as HARVESTGUARD_VERSION
from reports import findings_json, make_report_context

ROOT = Path(__file__).parent.parent


def _finding(
    location: str,
    source_type: str = "crypto_inventory",
    asset_type: str = "PEM Certificate",
    **overrides,
) -> NormalizedFinding:
    payload = {
        "source_type": source_type,
        "asset_type": asset_type,
        "location": location,
        "scanner_name": "test",
        "scanner_version": "0.1.0",
        "evidence": "observed",
        "confidence": "High",
        "observed_at": "2026-07-20T00:00:00+00:00",
    }
    payload.update(overrides)
    return NormalizedFinding(**payload)


def _context(**overrides):
    defaults = {
        "target_path": "/scan/target",
        "scan_type": "crypto",
        "scanners": ["crypto inventory"],
        "scanner_versions": {"crypto_inventory": "0.1.0"},
    }
    defaults.update(overrides)
    return make_report_context(**defaults)


def _patch_local_scanners(monkeypatch, findings_by_scanner):
    monkeypatch.setattr(
        harvestguard,
        "scan_filesystem_findings",
        lambda path, max_depth=3, scan_id=None: findings_by_scanner.get("filesystem", []),
    )
    monkeypatch.setattr(
        harvestguard,
        "scan_crypto_inventory_findings",
        lambda path, exclude_patterns=None, stats=None: findings_by_scanner.get("crypto", []),
    )
    monkeypatch.setattr(
        harvestguard,
        "scan_filesystem_for_sensitive_data_findings",
        lambda path, max_depth=3, scan_id=None: findings_by_scanner.get("sensitive", []),
    )
    monkeypatch.setattr(
        harvestguard,
        "scan_source_for_crypto_usage_findings",
        lambda path: findings_by_scanner.get("code", []),
    )


# --- Scan identity ----------------------------------------------------------


def test_local_scan_generates_a_uuid_scan_id_shared_by_every_finding(
    tmp_path, capsys, monkeypatch
):
    _patch_local_scanners(
        monkeypatch,
        {
            "crypto": [_finding("/a/cert.pem"), _finding("/a/key.pem", asset_type="PEM Key")],
            "sensitive": [_finding("/a/secret.txt", source_type="local_sensitive_data")],
        },
    )

    exit_code = harvestguard.main(["scan", str(tmp_path), "--json", "--quiet"])

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    scan_ids = {record["scan_id"] for record in payload}
    assert len(payload) == 3
    assert len(scan_ids) == 1
    # A real UUID, not an arbitrary string.
    assert uuid.UUID(scan_ids.pop())


def test_cloud_scan_generates_a_uuid_scan_id(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(
        harvestguard,
        "scan_s3_bucket_findings",
        lambda bucket, prefix="": [_finding("s3://bucket/object", source_type="aws_s3")],
    )

    exit_code = harvestguard.main(["scan", "bucket", "--type", "s3", "--json", "--quiet"])

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert uuid.UUID(payload[0]["scan_id"])


def test_separate_runs_receive_separate_scan_ids(tmp_path, capsys, monkeypatch):
    _patch_local_scanners(monkeypatch, {"crypto": [_finding("/a/cert.pem")]})

    harvestguard.main(["scan", str(tmp_path), "--json", "--quiet"])
    first = json.loads(capsys.readouterr().out)[0]["scan_id"]
    harvestguard.main(["scan", str(tmp_path), "--json", "--quiet"])
    second = json.loads(capsys.readouterr().out)[0]["scan_id"]

    assert first != second


def test_assigning_a_scan_id_does_not_change_stable_finding_ids(tmp_path, capsys, monkeypatch):
    finding = _finding("/a/cert.pem")
    original_id = finding.finding_id
    _patch_local_scanners(monkeypatch, {"crypto": [finding]})

    harvestguard.main(["scan", str(tmp_path), "--json", "--quiet"])

    payload = json.loads(capsys.readouterr().out)
    assert payload[0]["finding_id"] == original_id
    # And the identity algorithm itself still ignores scan_id.
    assert replace(finding, scan_id="other").finding_id == original_id


def test_markdown_scan_information_includes_the_scan_id(tmp_path, capsys, monkeypatch):
    _patch_local_scanners(monkeypatch, {"crypto": [_finding("/a/cert.pem")]})

    harvestguard.main(["scan", str(tmp_path), "--markdown", "--quiet"])

    output = capsys.readouterr().out
    scan_id_rows = [line for line in output.splitlines() if line.startswith("| Scan ID |")]
    assert len(scan_id_rows) == 1
    assert uuid.UUID(scan_id_rows[0].split("|")[2].strip())


def test_json_output_remains_a_bare_array(tmp_path, capsys, monkeypatch):
    _patch_local_scanners(monkeypatch, {"crypto": [_finding("/a/cert.pem")]})

    harvestguard.main(["scan", str(tmp_path), "--json", "--quiet"])

    assert isinstance(json.loads(capsys.readouterr().out), list)


def test_zero_finding_run_still_has_a_stored_scan_identity(tmp_path, capsys, monkeypatch):
    _patch_local_scanners(monkeypatch, {})
    db = tmp_path / "evidence.db"

    harvestguard.main(
        ["scan", str(tmp_path), "--json", "--quiet", "--evidence-db", str(db)]
    )

    assert json.loads(capsys.readouterr().out) == []
    runs = list_scan_runs(db)
    assert len(runs) == 1
    assert uuid.UUID(runs[0].scan_id)
    assert runs[0].finding_count == 0


# --- Persistence ------------------------------------------------------------


def test_scan_without_evidence_db_creates_no_database(tmp_path, capsys, monkeypatch):
    _patch_local_scanners(monkeypatch, {"crypto": [_finding("/a/cert.pem")]})

    harvestguard.main(["scan", str(tmp_path), "--json", "--quiet"])
    capsys.readouterr()

    assert list(tmp_path.iterdir()) == []


def test_fresh_database_is_created_with_schema_version_one(tmp_path):
    db = tmp_path / "evidence.db"

    store_scan_run(db, scan_id="run-1", context=_context(), findings=[_finding("/a/cert.pem")])

    connection = sqlite3.connect(db)
    try:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 1
    finally:
        connection.close()


def test_existing_database_is_reopened_and_appended_to(tmp_path):
    db = tmp_path / "evidence.db"
    store_scan_run(db, scan_id="run-1", context=_context(), findings=[])

    store_scan_run(db, scan_id="run-2", context=_context(), findings=[_finding("/a/cert.pem")])

    assert [run.scan_id for run in list_scan_runs(db)] == ["run-1", "run-2"]


def test_multiple_runs_are_stored_independently(tmp_path):
    db = tmp_path / "evidence.db"
    store_scan_run(
        db,
        scan_id="run-1",
        context=_context(target_path="/first"),
        findings=[_finding("/a/cert.pem")],
    )
    store_scan_run(
        db,
        scan_id="run-2",
        context=_context(target_path="/second"),
        findings=[_finding("/b/cert.pem"), _finding("/b/key.pem")],
    )

    first = load_scan_run(db, "run-1")
    second = load_scan_run(db, "run-2")
    assert first.context.target_path == "/first"
    assert [f.location for f in first.findings] == ["/a/cert.pem"]
    assert second.context.target_path == "/second"
    assert [f.location for f in second.findings] == ["/b/cert.pem", "/b/key.pem"]


def test_same_finding_id_in_two_runs_keeps_two_snapshots(tmp_path):
    db = tmp_path / "evidence.db"
    first = _finding("/a/cert.pem", observed_at="2026-07-20T00:00:00+00:00")
    # The same logical finding, observed again later with different volatile
    # facts: same stable finding_id, distinct per-scan observation.
    second = _finding("/a/cert.pem", observed_at="2026-07-21T00:00:00+00:00", confidence="Low")
    assert first.finding_id == second.finding_id

    store_scan_run(db, scan_id="run-1", context=_context(), findings=[first])
    store_scan_run(db, scan_id="run-2", context=_context(), findings=[second])

    stored_first = load_scan_run(db, "run-1").findings[0]
    stored_second = load_scan_run(db, "run-2").findings[0]
    assert stored_first.finding_id == stored_second.finding_id
    assert stored_first.observed_at == "2026-07-20T00:00:00+00:00"
    assert stored_second.observed_at == "2026-07-21T00:00:00+00:00"
    assert stored_second.confidence == "Low"


def test_colliding_finding_ids_within_one_run_are_preserved_by_ordinal(tmp_path):
    db = tmp_path / "evidence.db"
    # Two records the identity algorithm cannot tell apart (the documented
    # residual collision case for malformed blocks without a fingerprint).
    first = _finding("/a/bundle.pem", evidence="first block")
    second = _finding("/a/bundle.pem", evidence="second block")
    assert first.finding_id == second.finding_id

    store_scan_run(db, scan_id="run-1", context=_context(), findings=[first, second])

    stored = load_scan_run(db, "run-1").findings
    assert len(stored) == 2
    assert {f.evidence for f in stored} == {"first block", "second block"}


def test_reusing_a_scan_id_fails_without_overwriting_prior_evidence(tmp_path):
    db = tmp_path / "evidence.db"
    store_scan_run(db, scan_id="run-1", context=_context(), findings=[_finding("/a/cert.pem")])

    with pytest.raises(DuplicateScanRunError):
        store_scan_run(
            db,
            scan_id="run-1",
            context=_context(target_path="/replacement"),
            findings=[_finding("/b/other.pem")],
        )

    stored = load_scan_run(db, "run-1")
    assert stored.context.target_path == "/scan/target"
    assert [f.location for f in stored.findings] == ["/a/cert.pem"]


def test_scanner_errors_and_partial_findings_are_stored_together(tmp_path):
    db = tmp_path / "evidence.db"
    context = _context(scanner_errors=["s3: connection reset after 2 objects"])

    store_scan_run(
        db, scan_id="run-1", context=context, findings=[_finding("s3://b/o", "aws_s3", "object")]
    )

    stored = load_scan_run(db, "run-1")
    assert stored.context.scanner_errors == ["s3: connection reset after 2 objects"]
    assert len(stored.findings) == 1
    assert list_scan_runs(db)[0].has_scanner_errors is True


def test_scope_constraints_and_exclusions_are_stored(tmp_path):
    db = tmp_path / "evidence.db"
    context = _context(
        scope_constraints=["Maximum directory depth: 1"], excluded_paths=["*.tmp"]
    )

    store_scan_run(db, scan_id="run-1", context=context, findings=[])

    stored = load_scan_run(db, "run-1")
    assert stored.context.scope_constraints == ["Maximum directory depth: 1"]
    assert stored.context.excluded_paths == ["*.tmp"]


def test_scanner_versions_and_crypto_accounting_survive_a_zero_finding_run(tmp_path):
    db = tmp_path / "evidence.db"
    context = _context(
        scanner_versions={"crypto_inventory": "0.1.0", "sensitive_data": "0.2.0"},
        crypto_files_inspected=17,
    )

    store_scan_run(db, scan_id="run-1", context=context, findings=[])

    stored = load_scan_run(db, "run-1")
    assert stored.context.scanner_versions == {
        "crypto_inventory": "0.1.0",
        "sensitive_data": "0.2.0",
    }
    assert stored.context.crypto_files_inspected == 17


def test_stored_run_records_the_harvestguard_version_that_executed_it(tmp_path):
    db = tmp_path / "evidence.db"

    store_scan_run(db, scan_id="run-1", context=_context(), findings=[])

    assert load_scan_run(db, "run-1").harvestguard_version == HARVESTGUARD_VERSION


def test_unsupported_schema_version_fails_safely(tmp_path):
    db = tmp_path / "evidence.db"
    store_scan_run(db, scan_id="run-1", context=_context(), findings=[])
    connection = sqlite3.connect(db)
    try:
        connection.execute("PRAGMA user_version = 99")
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(EvidenceStoreError, match="unsupported evidence-store schema version"):
        list_scan_runs(db)


def test_corrupt_database_file_fails_safely(tmp_path):
    db = tmp_path / "evidence.db"
    db.write_bytes(b"this is not a sqlite database" * 8)

    with pytest.raises(EvidenceStoreError, match="not a readable evidence database"):
        list_scan_runs(db)


def test_missing_database_is_not_created_by_a_read(tmp_path):
    db = tmp_path / "absent.db"

    with pytest.raises(EvidenceStoreError, match="does not exist"):
        list_scan_runs(db)
    assert not db.exists()


def test_persistence_failure_leaves_no_partial_run(tmp_path):
    db = tmp_path / "evidence.db"
    store_scan_run(db, scan_id="run-1", context=_context(), findings=[])
    # Fail for real at the database level, after the run row of the next
    # transaction has already been inserted and before its snapshots are.
    connection = sqlite3.connect(db)
    try:
        connection.execute(
            "CREATE TRIGGER fail_snapshots BEFORE INSERT ON scan_findings "
            "BEGIN SELECT RAISE(ABORT, 'simulated snapshot write failure'); END"
        )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(EvidenceStoreError):
        store_scan_run(
            db, scan_id="run-2", context=_context(), findings=[_finding("/a/cert.pem")]
        )

    # The run row inserted before the failure was rolled back with it.
    assert [run.scan_id for run in list_scan_runs(db)] == ["run-1"]
    with pytest.raises(ScanRunNotFoundError):
        load_scan_run(db, "run-2")


# --- Integrity --------------------------------------------------------------


def test_fresh_stored_run_verifies(tmp_path):
    db = tmp_path / "evidence.db"
    digest = store_scan_run(
        db, scan_id="run-1", context=_context(), findings=[_finding("/a/cert.pem")]
    )

    assert evidence_store.verify_scan_run(db, "run-1").evidence_digest == digest


def test_finding_payload_mutation_fails_verification(tmp_path):
    db = tmp_path / "evidence.db"
    store_scan_run(db, scan_id="run-1", context=_context(), findings=[_finding("/a/cert.pem")])
    connection = sqlite3.connect(db)
    try:
        connection.execute(
            "UPDATE scan_findings SET finding_json = "
            "replace(finding_json, '/a/cert.pem', '/a/tampered.pem')"
        )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(EvidenceIntegrityError):
        load_scan_run(db, "run-1")


def test_scan_context_mutation_fails_verification(tmp_path):
    db = tmp_path / "evidence.db"
    store_scan_run(db, scan_id="run-1", context=_context(), findings=[_finding("/a/cert.pem")])
    connection = sqlite3.connect(db)
    try:
        connection.execute("UPDATE scan_runs SET target_path = '/elsewhere'")
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(EvidenceIntegrityError):
        load_scan_run(db, "run-1")


def test_removing_a_finding_snapshot_fails_verification(tmp_path):
    db = tmp_path / "evidence.db"
    store_scan_run(
        db,
        scan_id="run-1",
        context=_context(),
        findings=[_finding("/a/cert.pem"), _finding("/a/key.pem", asset_type="PEM Key")],
    )
    connection = sqlite3.connect(db)
    try:
        connection.execute("DELETE FROM scan_findings WHERE ordinal = 1")
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(EvidenceIntegrityError):
        load_scan_run(db, "run-1")


def test_integrity_failure_returns_execution_error_and_emits_no_payload(tmp_path, capsys):
    db = tmp_path / "evidence.db"
    store_scan_run(db, scan_id="run-1", context=_context(), findings=[_finding("/a/cert.pem")])
    connection = sqlite3.connect(db)
    try:
        connection.execute(
            "UPDATE scan_findings SET finding_json = "
            "replace(finding_json, '/a/cert.pem', '/a/tampered.pem')"
        )
        connection.commit()
    finally:
        connection.close()

    verify_code = harvestguard.main(["evidence", "verify", "run-1", "--evidence-db", str(db)])
    verify_output = capsys.readouterr()
    json_code = harvestguard.main(
        ["evidence", "export", "run-1", "--evidence-db", str(db), "--json"]
    )
    json_output = capsys.readouterr()
    markdown_code = harvestguard.main(
        ["evidence", "export", "run-1", "--evidence-db", str(db), "--markdown"]
    )
    markdown_output = capsys.readouterr()

    assert verify_code == harvestguard.EXIT_SCAN_ERROR
    assert json_code == harvestguard.EXIT_SCAN_ERROR
    assert markdown_code == harvestguard.EXIT_SCAN_ERROR
    assert "integrity verification" in verify_output.err
    # The corrupt payload is never emitted as if it had been verified.
    assert json_output.out == ""
    assert markdown_output.out == ""
    assert "tampered.pem" not in json_output.err + markdown_output.err


def test_verify_output_does_not_claim_tamper_proof_or_signed_evidence(tmp_path, capsys):
    db = tmp_path / "evidence.db"
    store_scan_run(db, scan_id="run-1", context=_context(), findings=[])

    exit_code = harvestguard.main(["evidence", "verify", "run-1", "--evidence-db", str(db)])

    output = capsys.readouterr().out
    assert exit_code == 0
    assert "not a signature, attestation, or chain-of-custody proof" in output
    lowered = output.lower()
    assert "tamper-proof" not in lowered
    assert "tamper proof" not in lowered


# --- Export -----------------------------------------------------------------


def test_stored_json_export_is_a_bare_array_matching_live_json(tmp_path, capsys, monkeypatch):
    db = tmp_path / "evidence.db"
    _patch_local_scanners(
        monkeypatch,
        {
            "crypto": [_finding("/a/cert.pem"), _finding("/a/key.pem", asset_type="PEM Key")],
            "sensitive": [_finding("/a/secret.txt", source_type="local_sensitive_data")],
        },
    )

    harvestguard.main(
        ["scan", str(tmp_path), "--json", "--quiet", "--evidence-db", str(db)]
    )
    live = capsys.readouterr().out
    scan_id = json.loads(live)[0]["scan_id"]

    exit_code = harvestguard.main(
        ["evidence", "export", scan_id, "--evidence-db", str(db), "--json", "--quiet"]
    )
    stored = capsys.readouterr().out

    assert exit_code == 0
    assert isinstance(json.loads(stored), list)
    # Byte-equivalent aside from the final newline both paths append.
    assert stored == live


def test_stored_export_routes_through_the_existing_formatters(tmp_path, monkeypatch, capsys):
    db = tmp_path / "evidence.db"
    store_scan_run(db, scan_id="run-1", context=_context(), findings=[_finding("/a/cert.pem")])
    calls: list[str] = []

    def _record(name, result):
        def wrapper(*args, **kwargs):
            calls.append(name)
            return result

        return wrapper

    monkeypatch.setattr(harvestguard, "findings_json", _record("json", "[]"))
    monkeypatch.setattr(harvestguard, "format_markdown_report", _record("markdown", "# report"))
    monkeypatch.setattr(harvestguard, "format_console_summary", _record("summary", "summary"))

    for flag in ("--json", "--markdown", "--summary"):
        assert (
            harvestguard.main(
                ["evidence", "export", "run-1", "--evidence-db", str(db), flag, "--quiet"]
            )
            == 0
        )
    capsys.readouterr()

    assert calls == ["json", "markdown", "summary"]


def test_stored_markdown_preserves_the_original_scan_context(tmp_path, capsys):
    db = tmp_path / "evidence.db"
    context = _context(
        target_path="/original/target",
        duration_seconds=1.5,
        scanner_errors=["crypto inventory: permission denied"],
        scope_constraints=["Maximum directory depth: 2"],
        scanner_versions={"crypto_inventory": "0.1.0"},
        crypto_files_inspected=9,
    )
    store_scan_run(db, scan_id="run-1", context=context, findings=[_finding("/a/cert.pem")])

    exit_code = harvestguard.main(
        ["evidence", "export", "run-1", "--evidence-db", str(db), "--markdown", "--quiet"]
    )

    output = capsys.readouterr().out
    assert exit_code == 0
    assert "| Scan ID | run-1 |" in output
    assert "| Target Path | /original/target |" in output
    assert "| Duration | 1.50 seconds |" in output
    assert "| Crypto Files Inspected | 9 |" in output
    assert "Maximum directory depth: 2" in output
    assert "crypto inventory: permission denied" in output
    # The declared scanner version is preserved even though this run's stored
    # finding was produced by a different scanner identity.
    assert "| crypto_inventory | 0.1.0 | 0 |" in output
    assert "| test | 0.1.0 | 1 |" in output


def test_stored_markdown_export_names_the_release_that_executed_the_scan(tmp_path, capsys):
    # A run stored by an older release and exported by a newer one: the report
    # must not reattribute the evidence to the release doing the export.
    db = tmp_path / "evidence.db"
    store_scan_run(
        db,
        scan_id="run-1",
        context=_context(),
        findings=[_finding("/a/cert.pem")],
        harvestguard_version="0.0.9-earlier",
    )

    exit_code = harvestguard.main(
        ["evidence", "export", "run-1", "--evidence-db", str(db), "--markdown", "--quiet"]
    )

    output = capsys.readouterr().out
    assert exit_code == 0
    assert "| HarvestGuard Version | 0.0.9-earlier |" in output
    # The exporting release is reported separately, not merged into the row
    # above and not silently dropped.
    assert f"| Exported By | HarvestGuard {HARVESTGUARD_VERSION} |" in output
    assert "| Report Generator | harvestguard-report" in output


def test_same_version_stored_markdown_export_adds_no_exported_by_row(tmp_path, capsys):
    db = tmp_path / "evidence.db"
    store_scan_run(db, scan_id="run-1", context=_context(), findings=[_finding("/a/cert.pem")])

    exit_code = harvestguard.main(
        ["evidence", "export", "run-1", "--evidence-db", str(db), "--markdown", "--quiet"]
    )

    output = capsys.readouterr().out
    assert exit_code == 0
    assert f"| HarvestGuard Version | {HARVESTGUARD_VERSION} |" in output
    assert "Exported By" not in output


def test_stored_summary_export_uses_the_console_formatter(tmp_path, capsys):
    db = tmp_path / "evidence.db"
    store_scan_run(
        db,
        scan_id="run-1",
        context=_context(crypto_files_inspected=4),
        findings=[_finding("/a/cert.pem")],
    )

    exit_code = harvestguard.main(
        ["evidence", "export", "run-1", "--evidence-db", str(db), "--summary"]
    )

    output = capsys.readouterr().out
    assert exit_code == 0
    assert "HarvestGuard Scan Complete" in output
    assert "Crypto files inspected: 4" in output
    assert "Certificates: 1" in output


def test_every_finding_field_survives_the_round_trip(tmp_path):
    db = tmp_path / "evidence.db"
    finding = _finding(
        "/a/cert.pem",
        confidence_rationale="parsed with cryptography",
        collection_method="file_read",
        collection_source="local_filesystem",
        rule_id="pem_certificate",
        repeatable=True,
        verification_rationale="re-reading the file reproduces this",
        identity_key="fingerprint:abc123",
        ownership_signals={"uid": 1000, "mode": "0600"},
        unknowns=["business owner"],
        limitations=["volume-level fallback used"],
        errors=["trailing block ignored"],
        technical_metadata={"Subject": "CN=example", "Key Size": 2048, "Nested": {"a": [1, 2]}},
        scan_id="run-1",
    )
    store_scan_run(db, scan_id="run-1", context=_context(), findings=[finding])

    stored = load_scan_run(db, "run-1").findings[0]

    assert stored.to_dict() == finding.to_dict()
    assert stored.finding_id == finding.finding_id
    assert stored.scan_id == "run-1"
    assert stored.provenance.to_dict() == finding.provenance.to_dict()
    assert stored.schema_version == finding.schema_version


def test_stored_finding_identity_is_preserved_not_regenerated():
    payload = _finding("/a/cert.pem").to_dict()
    payload["finding_id"] = "historical-identity-value"

    assert finding_from_dict(payload).finding_id == "historical-identity-value"


def test_deterministic_ordering_survives_stored_export(tmp_path, capsys):
    db = tmp_path / "evidence.db"
    unordered = [
        _finding("/z/cert.pem"),
        _finding("/a/key.pem", asset_type="PEM Key"),
        _finding("/a/cert.pem"),
    ]
    store_scan_run(db, scan_id="run-1", context=_context(), findings=unordered)

    harvestguard.main(
        ["evidence", "export", "run-1", "--evidence-db", str(db), "--json", "--quiet"]
    )

    stored = capsys.readouterr().out
    assert stored == findings_json(unordered) + "\n"
    assert [record["location"] for record in json.loads(stored)] == [
        "/a/cert.pem",
        "/z/cert.pem",
        "/a/key.pem",
    ]


def test_evidence_list_shows_the_documented_columns(tmp_path, capsys):
    db = tmp_path / "evidence.db"
    store_scan_run(
        db,
        scan_id="run-1",
        context=_context(target_path="/first", scan_type="crypto"),
        findings=[_finding("/a/cert.pem")],
    )
    store_scan_run(
        db,
        scan_id="run-2",
        context=_context(target_path="/second", scanner_errors=["code analysis: failed"]),
        findings=[],
    )

    exit_code = harvestguard.main(["evidence", "list", "--evidence-db", str(db)])

    output = capsys.readouterr().out
    assert exit_code == 0
    assert "SCAN ID" in output and "FINDINGS" in output and "SCANNER ERRORS" in output
    run_one = next(line for line in output.splitlines() if line.startswith("run-1"))
    run_two = next(line for line in output.splitlines() if line.startswith("run-2"))
    assert "crypto" in run_one and "/first" in run_one and run_one.endswith("no")
    assert "/second" in run_two and run_two.endswith("yes")


def test_missing_scan_id_fails_safely(tmp_path, capsys):
    db = tmp_path / "evidence.db"
    store_scan_run(db, scan_id="run-1", context=_context(), findings=[])

    exit_code = harvestguard.main(
        ["evidence", "export", "absent-run", "--evidence-db", str(db), "--json"]
    )

    captured = capsys.readouterr()
    assert exit_code == harvestguard.EXIT_SCAN_ERROR
    assert captured.out == ""
    assert "no stored scan run with scan ID absent-run" in captured.err


def test_output_write_failure_after_persistence_leaves_the_run_retrievable(
    tmp_path, capsys, monkeypatch
):
    db = tmp_path / "evidence.db"
    _patch_local_scanners(monkeypatch, {"crypto": [_finding("/a/cert.pem")]})
    unwritable = tmp_path / "missing-directory" / "report.json"

    exit_code = harvestguard.main(
        [
            "scan",
            str(tmp_path),
            "--json",
            str(unwritable),
            "--quiet",
            "--evidence-db",
            str(db),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == harvestguard.EXIT_SCAN_ERROR
    assert "could not write JSON findings" in captured.err
    runs = list_scan_runs(db)
    assert len(runs) == 1
    assert len(load_scan_run(db, runs[0].scan_id).findings) == 1


def test_persistence_failure_reports_an_error_without_corrupting_json_stdout(
    tmp_path, capsys, monkeypatch
):
    _patch_local_scanners(monkeypatch, {"crypto": [_finding("/a/cert.pem")]})
    # A directory is not a writable SQLite database.
    unusable_db = tmp_path / "as-a-directory"
    unusable_db.mkdir()

    exit_code = harvestguard.main(
        ["scan", str(tmp_path), "--json", "--quiet", "--evidence-db", str(unusable_db)]
    )

    captured = capsys.readouterr()
    assert exit_code == harvestguard.EXIT_SCAN_ERROR
    # stdout is still parseable evidence; the failure went to stderr only.
    assert len(json.loads(captured.out)) == 1
    assert "could not store scan evidence" in captured.err
    assert "Stored scan" not in captured.err


# --- Privacy and security ---------------------------------------------------


def test_forbidden_raw_values_are_absent_from_the_database_bytes(tmp_path):
    """The store persists only what a normalized finding already emits.

    Synthetic secrets are placed in fields the scanners never populate from raw
    target content, so anything appearing in the file bytes would mean the
    store widened what HarvestGuard retains.
    """
    db = tmp_path / "evidence.db"
    context = _context(scanner_errors=["sensitive data: 1 file unreadable"])
    store_scan_run(
        db,
        scan_id="run-1",
        context=context,
        findings=[
            _finding(
                "/a/secret.txt",
                source_type="local_sensitive_data",
                asset_type="file",
                evidence="1 credit card pattern match",
                technical_metadata={"Categories": ["credit_card"], "Match Count": 1},
            )
        ],
    )

    raw = db.read_bytes()
    for forbidden in (
        b"4111111111111111",
        b"-----BEGIN RSA PRIVATE KEY-----",
        b"AKIAIOSFODNN7EXAMPLE",
        b"hunter2",
        b"AWS_SECRET_ACCESS_KEY",
        b"Traceback (most recent call last)",
    ):
        assert forbidden not in raw
    # The safe, already-reported category count is retained.
    assert b"credit_card" in raw


def test_scanner_error_text_is_stored_verbatim_without_exception_objects(tmp_path):
    db = tmp_path / "evidence.db"
    context = _context(scanner_errors=["s3: An error occurred (AccessDenied)"])

    store_scan_run(db, scan_id="run-1", context=context, findings=[])

    stored = load_scan_run(db, "run-1")
    assert stored.context.scanner_errors == ["s3: An error occurred (AccessDenied)"]
    assert all(isinstance(error, str) for error in stored.context.scanner_errors)


def test_stored_run_record_contains_no_host_environment_columns(tmp_path):
    db = tmp_path / "evidence.db"
    store_scan_run(db, scan_id="run-1", context=_context(), findings=[])

    connection = sqlite3.connect(db)
    try:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(scan_runs)")}
    finally:
        connection.close()
    forbidden = {"hostname", "environment", "process_id", "pid", "credentials", "user"}
    assert columns & forbidden == set()


# --- Documentation claims ---------------------------------------------------


_EVIDENCE_DOCS = ("README.md", "docs/CLI.md", "docs/ARCHITECTURE.md")


def _documentation_text() -> str:
    return "\n".join(
        (ROOT / name).read_text(encoding="utf-8").lower() for name in _EVIDENCE_DOCS
    )


def test_documentation_states_the_digest_detects_corruption_not_tampering():
    text = _documentation_text()
    assert "corruption" in text
    # The claim must be scoped every time it appears: a reader must never come
    # away believing the digest proves the evidence was not altered.
    for phrase in ("tamper-proof", "chain of custody", "signed"):
        for occurrence in _sentences_containing(text, phrase):
            assert "not" in occurrence, f"unscoped '{phrase}' claim: {occurrence!r}"


def test_documentation_identifies_the_database_as_a_sensitive_artifact():
    assert "sensitive evidence artifact" in _documentation_text()


def test_documentation_does_not_claim_the_database_is_encrypted_at_rest():
    text = _documentation_text()
    assert "not encrypted at rest" in text
    for occurrence in _sentences_containing(text, "encrypted at rest"):
        assert "not encrypted at rest" in occurrence, occurrence


def _sentences_containing(text: str, phrase: str) -> list[str]:
    return [
        sentence.strip()
        for sentence in text.replace("\n", " ").split(". ")
        if phrase in sentence
    ]
