"""Tests for scripts/check_builder_result.py, the gate between the Claude
builder step and commit/push/PR in .github/workflows/agent-orchestrator.yml.
"""

from __future__ import annotations

import json

from scripts.check_builder_result import check, load_result, main


def _valid_result(**overrides) -> dict:
    result = {
        "status": "COMPLETE",
        "issue_number": 123,
        "branch": "agent/claude/issue-123",
        "commit_sha": None,
        "files_changed": ["scanner/filesystem.py"],
        "validation": {"ruff": "pass", "pytest": "pass"},
        "known_limitations": [],
        "scope_expansion_requested": False,
        "summary": "Implemented the requested change.",
    }
    result.update(overrides)
    return result


def test_complete_clean_result_proceeds():
    assert check(_valid_result(), ["scanner/filesystem.py"]) == []


def test_needs_human_stops():
    result = _valid_result(status="NEEDS_HUMAN", summary="Requires an architecture decision.")
    reasons = check(result, [])
    assert reasons
    assert any("NEEDS_HUMAN" in r for r in reasons)
    assert any("architecture decision" in r for r in reasons)


def test_failed_stops():
    result = _valid_result(status="FAILED", summary="Could not make tests pass.")
    reasons = check(result, [])
    assert reasons
    assert any("FAILED" in r for r in reasons)


def test_unrecognized_status_stops():
    reasons = check(_valid_result(status="DONE"), [])
    assert reasons
    assert any("status" in r for r in reasons)


def test_scope_expansion_requested_overrides_complete():
    result = _valid_result(scope_expansion_requested=True)
    reasons = check(result, ["scanner/filesystem.py"])
    assert reasons
    assert any("scope_expansion_requested" in r for r in reasons)


def test_protected_workflow_path_stops():
    reasons = check(_valid_result(), [".github/workflows/agent-orchestrator.yml"])
    assert reasons
    assert any("SECURITY" in r for r in reasons)
    assert any(".github/workflows/agent-orchestrator.yml" in r for r in reasons)


def test_protected_agent_policy_path_stops():
    reasons = check(_valid_result(), [".agent-policy.yml"])
    assert any("SECURITY" in r for r in reasons)


def test_protected_agent_contract_path_stops():
    reasons = check(_valid_result(), ["docs/AGENT_CONTRACT.md"])
    assert any("SECURITY" in r for r in reasons)


def test_unrelated_docs_file_does_not_trigger_protected_path_check():
    assert check(_valid_result(), ["docs/ARCHITECTURE.md"]) == []


def test_sibling_github_actions_path_is_not_protected():
    # Only .github/workflows/** is protected per docs/AGENT_CONTRACT.md;
    # .github/actions/** is a different, non-protected directory.
    assert check(_valid_result(), [".github/actions/container-validate/action.yml"]) == []


def test_mixed_changed_files_with_one_protected_still_stops():
    reasons = check(
        _valid_result(),
        ["scanner/filesystem.py", "tests/test_filesystem.py", ".agent-policy.yml"],
    )
    assert any("SECURITY" in r for r in reasons)


def test_missing_result_file_fails_via_main(tmp_path, capsys):
    rc = main([str(tmp_path / "does-not-exist.json")])
    assert rc == 1
    assert "::error::" in capsys.readouterr().out


def test_malformed_json_fails_via_main(tmp_path, capsys):
    bad = tmp_path / "result.json"
    bad.write_text("{not valid json")
    rc = main([str(bad)])
    assert rc == 1
    assert "not valid JSON" in capsys.readouterr().out


def test_main_proceeds_for_valid_result_and_prints_summary(tmp_path, capsys, monkeypatch):
    result_path = tmp_path / "result.json"
    result_path.write_text(json.dumps(_valid_result(known_limitations=["Only covers case X."])))
    monkeypatch.setattr("sys.stdin", __import__("io").StringIO("scanner/filesystem.py\n"))

    rc = main([str(result_path)])

    out = capsys.readouterr().out
    assert rc == 0
    assert "Builder result OK" in out
    assert "Only covers case X." in out


def test_main_stops_for_protected_path_via_stdin(tmp_path, capsys, monkeypatch):
    result_path = tmp_path / "result.json"
    result_path.write_text(json.dumps(_valid_result()))
    monkeypatch.setattr(
        "sys.stdin", __import__("io").StringIO(".github/workflows/agent-orchestrator.yml\n")
    )

    rc = main([str(result_path)])

    out = capsys.readouterr().out
    assert rc == 1
    assert "SECURITY" in out


def test_load_result_missing_file_raises():
    import pytest

    from scripts.check_builder_result import ResultError

    with pytest.raises(ResultError, match="not found"):
        load_result("/nonexistent/path/result.json")


def test_load_result_non_mapping_raises(tmp_path):
    import pytest

    from scripts.check_builder_result import ResultError

    bad = tmp_path / "result.json"
    bad.write_text("[1, 2, 3]")
    with pytest.raises(ResultError, match="JSON object"):
        load_result(bad)
