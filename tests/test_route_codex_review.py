"""Tests for scripts/route_codex_review.py, the cycle-0 routing gate that
decides between: APPROVED (exit 0, no correction), BLOCKERS (exit 0, the
single correction cycle may trigger), and everything else (exit 1, stop).
"""

from __future__ import annotations

import json

from scripts.route_codex_review import main

SHA = "deadbeefcafefeed0000000000000000000000"
MARKER = "LEAKED_MODEL_TEXT_MARKER_deadbeef"


def _valid_review(**overrides) -> dict:
    review = {
        "status": "APPROVED",
        "reviewed_sha": SHA,
        "blockers": [],
        "important": [],
        "follow_up": [],
        "summary": "No blocking issues found.",
    }
    review.update(overrides)
    return review


def _run(tmp_path, capsys, review: dict, github_output=None, monkeypatch=None):
    path = tmp_path / "review.json"
    path.write_text(json.dumps(review))
    if monkeypatch is not None:
        if github_output is not None:
            monkeypatch.setenv("GITHUB_OUTPUT", str(github_output))
        else:
            monkeypatch.delenv("GITHUB_OUTPUT", raising=False)
    rc = main([str(path), SHA])
    captured = capsys.readouterr()
    return rc, captured.out + captured.err


# --- Routing outcomes --------------------------------------------------------


def test_clean_approved_routes_to_success(tmp_path, capsys, monkeypatch):
    rc, out = _run(tmp_path, capsys, _valid_review(), monkeypatch=monkeypatch)
    assert rc == 0
    assert "no correction cycle needed" in out


def test_well_formed_blockers_routes_to_correction(tmp_path, capsys, monkeypatch):
    review = _valid_review(status="BLOCKERS", blockers=["Missing validation."])
    rc, out = _run(tmp_path, capsys, review, monkeypatch=monkeypatch)
    assert rc == 0
    assert "eligible for" in out


def test_needs_human_fails(tmp_path, capsys, monkeypatch):
    review = _valid_review(status="NEEDS_HUMAN")
    rc, out = _run(tmp_path, capsys, review, monkeypatch=monkeypatch)
    assert rc == 1
    assert "::error::" in out


def test_approved_with_blockers_fails(tmp_path, capsys, monkeypatch):
    # An APPROVED verdict contradicted by non-empty blockers is not a clean
    # approval and not a BLOCKERS route -- it's an inconsistency for a human.
    review = _valid_review(blockers=["Should have been BLOCKERS."])
    rc, out = _run(tmp_path, capsys, review, monkeypatch=monkeypatch)
    assert rc == 1


def test_approved_with_important_fails(tmp_path, capsys, monkeypatch):
    review = _valid_review(important=["Fix before merge."])
    rc, out = _run(tmp_path, capsys, review, monkeypatch=monkeypatch)
    assert rc == 1


def test_blockers_status_with_empty_blocker_list_fails(tmp_path, capsys, monkeypatch):
    # A BLOCKERS verdict with nothing to fix is inconsistent -- there is no
    # meaningful correction to run, so it must not trigger one.
    review = _valid_review(status="BLOCKERS", blockers=[])
    rc, out = _run(tmp_path, capsys, review, monkeypatch=monkeypatch)
    assert rc == 1


def test_sha_mismatch_fails_even_for_blockers(tmp_path, capsys, monkeypatch):
    review = _valid_review(status="BLOCKERS", blockers=["x"], reviewed_sha="0" * 40)
    rc, out = _run(tmp_path, capsys, review, monkeypatch=monkeypatch)
    assert rc == 1
    assert "reviewed_sha mismatch" in out


def test_malformed_review_fails(tmp_path, capsys, monkeypatch):
    review = _valid_review()
    del review["summary"]
    rc, out = _run(tmp_path, capsys, review, monkeypatch=monkeypatch)
    assert rc == 1


def test_missing_file_fails(tmp_path, capsys):
    rc = main([str(tmp_path / "does-not-exist.json"), SHA])
    assert rc == 1
    assert "::error::" in capsys.readouterr().out


def test_requires_two_arguments(capsys):
    rc = main([])
    assert rc == 2
    assert "usage" in capsys.readouterr().out


# --- GITHUB_OUTPUT wiring ----------------------------------------------------


def test_blockers_route_writes_status_output(tmp_path, capsys, monkeypatch):
    gh_out = tmp_path / "github_output"
    review = _valid_review(status="BLOCKERS", blockers=["a", "b"])
    rc, _ = _run(tmp_path, capsys, review, github_output=gh_out, monkeypatch=monkeypatch)
    assert rc == 0
    content = gh_out.read_text()
    assert "status=BLOCKERS" in content
    assert "blockers_count=2" in content


def test_approved_route_writes_status_output(tmp_path, capsys, monkeypatch):
    gh_out = tmp_path / "github_output"
    rc, _ = _run(tmp_path, capsys, _valid_review(), github_output=gh_out, monkeypatch=monkeypatch)
    assert rc == 0
    assert "status=APPROVED" in gh_out.read_text()


def test_no_github_output_env_is_not_an_error(tmp_path, capsys, monkeypatch):
    rc, _ = _run(tmp_path, capsys, _valid_review(), monkeypatch=monkeypatch)
    assert rc == 0


# --- Log redaction -----------------------------------------------------------


def test_blocker_text_never_reaches_the_log_on_the_correction_route(tmp_path, capsys, monkeypatch):
    review = _valid_review(status="BLOCKERS", blockers=[MARKER], summary=MARKER)
    rc, out = _run(tmp_path, capsys, review, monkeypatch=monkeypatch)
    assert rc == 0
    assert MARKER not in out
    assert "Blockers: 1" in out


def test_model_text_never_reaches_the_log_on_the_stop_route(tmp_path, capsys, monkeypatch):
    review = _valid_review(status="NEEDS_HUMAN", follow_up=[MARKER], summary=MARKER)
    rc, out = _run(tmp_path, capsys, review, monkeypatch=monkeypatch)
    assert rc == 1
    assert MARKER not in out


def test_malformed_field_values_never_reach_the_log(tmp_path, capsys, monkeypatch):
    review = _valid_review(blockers=MARKER, summary={"text": MARKER})
    rc, out = _run(tmp_path, capsys, review, monkeypatch=monkeypatch)
    assert rc == 1
    assert MARKER not in out


def test_mismatched_reviewed_sha_never_reaches_the_log(tmp_path, capsys, monkeypatch):
    review = _valid_review(reviewed_sha=MARKER)
    rc, out = _run(tmp_path, capsys, review, monkeypatch=monkeypatch)
    assert rc == 1
    assert MARKER not in out
