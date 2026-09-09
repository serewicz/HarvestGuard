"""Exercise the actual wrapper -> CLI -> store -> verified export path."""
import json
import subprocess

import pytest

import harvestguard
from code_analysis.scanner import scan_source_for_crypto_usage_findings
from evidence_store import list_scan_runs, load_scan_run, store_scan_run
from reports import make_report_context
from scanner.errors import LocalScanError


def match():
    return {"path": "app.py", "check_id": "weak-hash-md5", "start": {"line": 3},
            "extra": {"message": "MD5 pattern", "severity": "ERROR"}}


def response(results=None, errors=None):
    return json.dumps({"results": results or [], "errors": errors or []})


def analyzer(monkeypatch, stdout, code=0):
    monkeypatch.setattr("code_analysis.scanner.subprocess.run", lambda *a, **k:
                        subprocess.CompletedProcess([], code, stdout, "PRIVATE-CANARY" * 1000))


@pytest.mark.parametrize("stdout", ["", " ", "not-json", "{}", "[]", "null",
                                   '{"results": []}', '{"results": {}, "errors": []}',
                                   '{"results": [], "errors": null}',
                                   response(errors=[{"message": "PRIVATE-CANARY"}]),
                                   response(results=[{}])])
def test_invalid_execution_never_becomes_success(monkeypatch, tmp_path, stdout):
    analyzer(monkeypatch, stdout)
    with pytest.raises(LocalScanError) as caught:
        scan_source_for_crypto_usage_findings(str(tmp_path))
    assert "PRIVATE-CANARY" not in str(caught.value)
    assert len(str(caught.value)) < 400


@pytest.mark.parametrize("results", [[], [match()]])
def test_positive_execution_contract(monkeypatch, tmp_path, results):
    analyzer(monkeypatch, response(results))
    findings = scan_source_for_crypto_usage_findings(str(tmp_path))
    assert len(findings) == len(results)
    assert all(f.scanner_version == "0.2.0" for f in findings)


@pytest.mark.parametrize("failure", [FileNotFoundError("PRIVATE-CANARY"),
    subprocess.TimeoutExpired("PRIVATE-CANARY", 120, output=response([match()])),
    PermissionError("PRIVATE-CANARY"), UnicodeError("PRIVATE-CANARY")])
def test_launch_and_timeout_failures(monkeypatch, tmp_path, failure):
    def fail(*a, **k):
        raise failure
    monkeypatch.setattr("code_analysis.scanner.subprocess.run", fail)
    with pytest.raises(LocalScanError) as caught:
        scan_source_for_crypto_usage_findings(str(tmp_path))
    assert "PRIVATE-CANARY" not in str(caught.value)
    assert not caught.value.partial_findings


@pytest.mark.parametrize("stdout,code", [
    (response([match()]), 2),
    (response([match()], [{"message": "PRIVATE-CANARY"}]), 0),
    (response([match(), {}, match()]), 0),
    (json.dumps({"results": [match()]}), 0),
])
def test_partial_findings_survive(monkeypatch, tmp_path, stdout, code):
    analyzer(monkeypatch, stdout, code)
    with pytest.raises(LocalScanError) as caught:
        scan_source_for_crypto_usage_findings(str(tmp_path))
    expected = sum(item == match() for item in json.loads(stdout)["results"])
    assert len(caught.value.partial_findings) == expected
    assert "PRIVATE-CANARY" not in str(caught.value)


@pytest.mark.parametrize("no_fail", [False, True])
@pytest.mark.parametrize("partial", [False, True])
def test_failure_survives_cli_store_integrity_and_exports(monkeypatch, tmp_path, capsys,
                                                         no_fail, partial):
    analyzer(monkeypatch, response([match()] if partial else []), 2)
    db = tmp_path / "evidence.sqlite"
    args = ["scan", str(tmp_path), "--type", "code", "--json", "-",
            "--evidence-db", str(db), "--quiet"]
    if no_fail:
        args.append("--no-fail-on-error")
    assert harvestguard.main(args) == (0 if no_fail else 1)
    captured = capsys.readouterr()
    live = json.loads(captured.out)
    assert len(live) == int(partial)
    scan_id = list_scan_runs(db)[0].scan_id
    stored = load_scan_run(db, scan_id)
    assert stored.context.scanner_errors
    assert stored.context.scanner_versions["semgrep_crypto_rules"] == "0.2.0"
    assert "PRIVATE-CANARY" not in db.read_bytes().decode("latin1")
    base = ["evidence"]
    assert harvestguard.main(base + ["verify", scan_id, "--evidence-db", str(db)]) == 0
    assert "internally consistent" in capsys.readouterr().out
    for output in ["--markdown", "--summary", "--json"]:
        assert harvestguard.main(base + ["export", scan_id, "--evidence-db", str(db), output]) == 0
        text = capsys.readouterr().out
        if output == "--json":
            assert json.loads(text) == live
        else:
            assert "exited nonzero" in text
        assert "PRIVATE-CANARY" not in text
    assert load_scan_run(db, scan_id).context.scanner_errors == stored.context.scanner_errors


@pytest.mark.parametrize("versions", [{"semgrep_crypto_rules": "0.1.0"}, {}])
def test_historical_empty_run_is_not_upgraded(tmp_path, capsys, versions):
    db = tmp_path / "old.sqlite"
    context = make_report_context("old", scanners=["code analysis"],
        scanner_versions=versions, scan_id="old")
    store_scan_run(db, "old", context, [])
    before = db.read_bytes()
    assert harvestguard.main(["evidence", "export", "old", "--evidence-db", str(db),
                              "--markdown"]) == 0
    text = capsys.readouterr().out
    assert "cannot establish execution" in text
    assert load_scan_run(db, "old").context.scanner_versions == context.scanner_versions
    assert db.read_bytes() == before


@pytest.mark.parametrize("results", [[], [match()]])
def test_successful_execution_survives_storage(monkeypatch, tmp_path, capsys, results):
    analyzer(monkeypatch, response(results))
    db = tmp_path / "success.sqlite"
    assert harvestguard.main(["scan", str(tmp_path), "--type", "code", "--json", "-",
                              "--evidence-db", str(db), "--quiet"]) == 0
    live = json.loads(capsys.readouterr().out)
    run = load_scan_run(db, list_scan_runs(db)[0].scan_id)
    assert len(run.findings) == len(results) == len(live)
    assert not run.context.scanner_errors
    assert run.context.scanner_versions["semgrep_crypto_rules"] == "0.2.0"
