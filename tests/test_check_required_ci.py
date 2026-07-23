"""Tests for scripts/check_required_ci.py, the fail-closed gate the Codex
Principal Reviewer's `review` job waits on before running Codex at all.
"""

from __future__ import annotations

import json

from scripts.check_required_ci import REQUIRED_CHECKS, check, main

SHA = "deadbeefcafefeed0000000000000000000000"
OTHER_SHA = "0000000000000000000000000000000000dead"


def _run(name: str, status: str, conclusion: str | None, *, sha: str = SHA) -> dict:
    return {"name": name, "head_sha": sha, "status": status, "conclusion": conclusion}


def _passing_run(name: str, *, sha: str = SHA) -> dict:
    return _run(name, "completed", "success", sha=sha)


def _all_passing(sha: str = SHA) -> list[dict]:
    return [_passing_run(name, sha=sha) for name in REQUIRED_CHECKS]


def test_all_required_checks_present_and_passing_succeeds():
    assert check(_all_passing(), SHA) == []


def test_one_required_check_missing_fails():
    runs = [_passing_run(name) for name in REQUIRED_CHECKS[1:]]
    reasons = check(runs, SHA)
    assert reasons
    assert any(REQUIRED_CHECKS[0] in r for r in reasons)


def test_one_check_pending_in_progress_fails():
    runs = _all_passing()
    runs[0] = _run(REQUIRED_CHECKS[0], "in_progress", None)
    reasons = check(runs, SHA)
    assert reasons
    assert any("not complete yet" in r for r in reasons)


def test_one_check_queued_fails():
    runs = _all_passing()
    runs[0] = _run(REQUIRED_CHECKS[0], "queued", None)
    reasons = check(runs, SHA)
    assert reasons
    assert any("not complete yet" in r for r in reasons)


def test_one_check_failed_fails():
    runs = _all_passing()
    runs[0] = _run(REQUIRED_CHECKS[0], "completed", "failure")
    reasons = check(runs, SHA)
    assert reasons
    assert any("did not succeed" in r and "failure" in r for r in reasons)


def test_one_check_skipped_fails():
    runs = _all_passing()
    runs[0] = _run(REQUIRED_CHECKS[0], "completed", "skipped")
    reasons = check(runs, SHA)
    assert reasons
    assert any("skipped" in r for r in reasons)


def test_one_check_cancelled_fails():
    runs = _all_passing()
    runs[0] = _run(REQUIRED_CHECKS[0], "completed", "cancelled")
    reasons = check(runs, SHA)
    assert reasons
    assert any("cancelled" in r for r in reasons)


def test_one_check_neutral_fails():
    runs = _all_passing()
    runs[0] = _run(REQUIRED_CHECKS[0], "completed", "neutral")
    reasons = check(runs, SHA)
    assert reasons


def test_one_check_timed_out_fails():
    runs = _all_passing()
    runs[0] = _run(REQUIRED_CHECKS[0], "completed", "timed_out")
    reasons = check(runs, SHA)
    assert reasons


def test_one_check_action_required_fails():
    runs = _all_passing()
    runs[0] = _run(REQUIRED_CHECKS[0], "completed", "action_required")
    reasons = check(runs, SHA)
    assert reasons


def test_one_check_stale_fails():
    runs = _all_passing()
    runs[0] = _run(REQUIRED_CHECKS[0], "completed", "stale")
    reasons = check(runs, SHA)
    assert reasons


def test_wrong_sha_fails():
    # Every required check passed, but only for a different commit -- e.g.
    # a stale run from before the PR's most recent push. Must not be
    # mistaken for the exact head SHA being green.
    reasons = check(_all_passing(sha=OTHER_SHA), SHA)
    assert reasons
    assert len(reasons) == len(REQUIRED_CHECKS)


def test_a_check_passing_on_the_wrong_sha_does_not_mask_a_missing_check_on_the_right_sha():
    runs = _all_passing() + [_passing_run(REQUIRED_CHECKS[0], sha=OTHER_SHA)]
    # Duplicate a passing entry under a different SHA for the same check --
    # the real (matching-SHA) entry is still present and passing, so this
    # should still succeed; the extra stale-SHA entry must be ignored, not
    # treated as evidence of failure or success.
    assert check(runs, SHA) == []


def test_extra_non_required_check_runs_are_ignored():
    runs = _all_passing() + [_run("Some Other Check", "completed", "failure")]
    assert check(runs, SHA) == []


def test_empty_check_runs_list_fails_for_every_required_check():
    reasons = check([], SHA)
    assert len(reasons) == len(REQUIRED_CHECKS)


def test_main_succeeds_for_a_ready_check_runs_file(tmp_path, capsys):
    path = tmp_path / "check_runs.json"
    path.write_text(json.dumps(_all_passing()))

    rc = main([str(path), SHA])

    out = capsys.readouterr().out
    assert rc == 0
    assert "All required CI checks passed" in out


def test_main_fails_for_a_not_ready_check_runs_file(tmp_path, capsys):
    path = tmp_path / "check_runs.json"
    path.write_text(json.dumps([]))

    rc = main([str(path), SHA])

    out = capsys.readouterr().out
    assert rc == 1
    assert "not ready" in out


def test_main_treats_missing_file_as_a_hard_error(tmp_path, capsys):
    rc = main([str(tmp_path / "does-not-exist.json"), SHA])
    assert rc == 1
    assert "::error::" in capsys.readouterr().out


def test_main_treats_malformed_json_as_a_hard_error(tmp_path, capsys):
    path = tmp_path / "bad.json"
    path.write_text("{not valid json")
    rc = main([str(path), SHA])
    assert rc == 1
    assert "::error::" in capsys.readouterr().out


def test_main_treats_non_list_json_as_a_hard_error(tmp_path, capsys):
    path = tmp_path / "bad.json"
    path.write_text(json.dumps({"not": "a list"}))
    rc = main([str(path), SHA])
    assert rc == 1
    assert "::error::" in capsys.readouterr().out


def test_main_requires_two_arguments(capsys):
    rc = main([])
    assert rc == 2
    assert "usage" in capsys.readouterr().out
