"""Tests for scripts/check_codex_review.py, the gate between the Codex
Principal Reviewer step and the rest of the `review` job in
.github/workflows/agent-orchestrator.yml.

check_schema() covers shape/well-formedness only. check_ready_to_merge()
covers the fail-closed merge-readiness decision on top of an already
schema-valid review. main() wires both together and never prints the
arbitrary model-generated text (blockers/important/follow_up/summary) to
the run log -- only counts and status/SHA.
"""

from __future__ import annotations

import json

from scripts.check_codex_review import check_ready_to_merge, check_schema, load_review, main

SHA = "deadbeefcafefeed0000000000000000000000"


def _valid_review(**overrides) -> dict:
    review = {
        "status": "APPROVED",
        "reviewed_sha": SHA,
        "blockers": [],
        "important": [],
        "follow_up": ["Consider adding a benchmark for large repos."],
        "summary": "No blocking issues found.",
    }
    review.update(overrides)
    return review


# --- check_schema(): shape/well-formedness only -----------------------------


def test_schema_valid_for_approved_blockers_and_needs_human_alike():
    # Schema validity is orthogonal to the verdict -- all three statuses are
    # well-formed reviews.
    assert check_schema(_valid_review(status="APPROVED")) == []
    assert check_schema(_valid_review(status="BLOCKERS", blockers=["x"])) == []
    assert check_schema(_valid_review(status="NEEDS_HUMAN")) == []


def test_schema_unrecognized_status_fails():
    reasons = check_schema(_valid_review(status="LGTM"))
    assert reasons
    assert any("status" in r for r in reasons)


def test_schema_missing_reviewed_sha_fails():
    review = _valid_review()
    del review["reviewed_sha"]
    reasons = check_schema(review)
    assert reasons
    assert any("Missing required field" in r and "reviewed_sha" in r for r in reasons)


def test_schema_empty_reviewed_sha_fails():
    reasons = check_schema(_valid_review(reviewed_sha=""))
    assert reasons
    assert any("reviewed_sha" in r for r in reasons)


def test_schema_missing_top_level_field_fails():
    review = _valid_review()
    del review["summary"]
    reasons = check_schema(review)
    assert reasons
    assert any("summary" in r for r in reasons)


def test_schema_blockers_not_a_list_of_strings_fails():
    reasons = check_schema(_valid_review(blockers="not a list"))
    assert reasons
    assert any("blockers" in r for r in reasons)


def test_schema_blockers_with_non_string_items_fails():
    reasons = check_schema(_valid_review(blockers=[{"nested": "object"}]))
    assert reasons
    assert any("blockers" in r for r in reasons)


def test_schema_empty_summary_fails():
    reasons = check_schema(_valid_review(summary=""))
    assert reasons
    assert any("summary" in r for r in reasons)


# --- check_ready_to_merge(): fail-closed merge-readiness decision ----------


def test_approved_with_empty_blockers_and_important_is_ready():
    assert check_ready_to_merge(_valid_review(), SHA) == []


def test_approved_with_follow_up_only_is_still_ready():
    review = _valid_review(follow_up=["a", "b", "c"])
    assert check_ready_to_merge(review, SHA) == []


def test_blockers_status_is_not_ready():
    review = _valid_review(status="BLOCKERS", blockers=["Missing input validation on X."])
    reasons = check_ready_to_merge(review, SHA)
    assert reasons
    assert any("not APPROVED" in r for r in reasons)


def test_needs_human_status_is_not_ready():
    review = _valid_review(status="NEEDS_HUMAN")
    reasons = check_ready_to_merge(review, SHA)
    assert reasons
    assert any("not APPROVED" in r for r in reasons)


def test_approved_with_a_blocker_is_not_ready():
    # A malformed self-report where status says APPROVED but blockers is
    # non-empty must still fail closed, not be trusted at face value.
    review = _valid_review(status="APPROVED", blockers=["Should have been BLOCKERS."])
    reasons = check_ready_to_merge(review, SHA)
    assert reasons
    assert any("blockers is non-empty" in r for r in reasons)


def test_approved_with_an_important_finding_is_not_ready():
    review = _valid_review(status="APPROVED", important=["Should be fixed before merge."])
    reasons = check_ready_to_merge(review, SHA)
    assert reasons
    assert any("important is non-empty" in r for r in reasons)


def test_reviewed_sha_mismatch_is_not_ready():
    reasons = check_ready_to_merge(_valid_review(reviewed_sha="0" * 40), SHA)
    assert reasons
    assert any("reviewed_sha mismatch" in r for r in reasons)


def test_wrong_sha_and_approved_status_both_reported():
    review = _valid_review(status="BLOCKERS", blockers=["x"], reviewed_sha="0" * 40)
    reasons = check_ready_to_merge(review, SHA)
    assert len(reasons) >= 2


# --- load_review(): file-loading edge cases ---------------------------------


def test_load_review_missing_file_raises():
    import pytest

    from scripts.check_codex_review import ReviewError

    with pytest.raises(ReviewError, match="not found"):
        load_review("/nonexistent/path/review.json")


def test_load_review_non_mapping_raises(tmp_path):
    import pytest

    from scripts.check_codex_review import ReviewError

    bad = tmp_path / "review.json"
    bad.write_text('"just a string"')
    with pytest.raises(ReviewError, match="JSON object"):
        load_review(bad)


# --- main(): end-to-end exit codes and log-redaction ------------------------


def test_main_approved_empty_blockers_and_important_exits_zero(tmp_path, capsys):
    path = tmp_path / "review.json"
    path.write_text(json.dumps(_valid_review()))

    rc = main([str(path), SHA])

    assert rc == 0
    assert "APPROVED" in capsys.readouterr().out


def test_main_blockers_status_exits_nonzero(tmp_path, capsys):
    path = tmp_path / "review.json"
    path.write_text(json.dumps(_valid_review(status="BLOCKERS", blockers=["Real issue."])))

    rc = main([str(path), SHA])

    assert rc != 0
    assert "::error::" in capsys.readouterr().out


def test_main_needs_human_status_exits_nonzero(tmp_path, capsys):
    path = tmp_path / "review.json"
    path.write_text(json.dumps(_valid_review(status="NEEDS_HUMAN")))

    rc = main([str(path), SHA])

    assert rc != 0
    assert "::error::" in capsys.readouterr().out


def test_main_approved_with_blocker_exits_nonzero(tmp_path, capsys):
    path = tmp_path / "review.json"
    path.write_text(json.dumps(_valid_review(status="APPROVED", blockers=["Shouldn't be here."])))

    rc = main([str(path), SHA])

    assert rc != 0


def test_main_approved_with_important_exits_nonzero(tmp_path, capsys):
    path = tmp_path / "review.json"
    path.write_text(json.dumps(_valid_review(status="APPROVED", important=["Shouldn't be here."])))

    rc = main([str(path), SHA])

    assert rc != 0


def test_main_approved_with_follow_up_only_exits_zero(tmp_path, capsys):
    path = tmp_path / "review.json"
    path.write_text(json.dumps(_valid_review(follow_up=["Nice to have."])))

    rc = main([str(path), SHA])

    assert rc == 0


def test_main_does_not_print_blocker_important_or_summary_text(tmp_path, capsys):
    # The whole point of the log-redaction requirement: arbitrary
    # Codex-generated prose must never land in the Actions run log, even on
    # a failing (BLOCKERS) run -- only counts/status/SHA.
    secret_blocker_text = "UNIQUE_BLOCKER_TEXT_MARKER_1234"
    secret_summary_text = "UNIQUE_SUMMARY_TEXT_MARKER_5678"
    path = tmp_path / "review.json"
    path.write_text(
        json.dumps(
            _valid_review(
                status="BLOCKERS",
                blockers=[secret_blocker_text],
                summary=secret_summary_text,
            )
        )
    )

    main([str(path), SHA])

    out = capsys.readouterr().out
    assert secret_blocker_text not in out
    assert secret_summary_text not in out
    assert "Blockers: 1" in out


def test_main_missing_result_file_fails_via_main(tmp_path, capsys):
    rc = main([str(tmp_path / "does-not-exist.json"), SHA])
    assert rc == 1
    assert "::error::" in capsys.readouterr().out


def test_main_empty_result_file_fails_via_main(tmp_path, capsys):
    empty = tmp_path / "empty.json"
    empty.write_text("")
    rc = main([str(empty), SHA])
    assert rc == 1
    assert "empty" in capsys.readouterr().out


def test_main_malformed_json_fails_via_main(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text("{not valid json")
    rc = main([str(bad), SHA])
    assert rc == 1
    assert "not valid JSON" in capsys.readouterr().out


def test_main_non_object_json_fails_via_main(tmp_path, capsys):
    bad = tmp_path / "list.json"
    bad.write_text("[1, 2, 3]")
    rc = main([str(bad), SHA])
    assert rc == 1
    assert "JSON object" in capsys.readouterr().out


def test_main_fails_for_sha_mismatch_without_traceback(tmp_path, capsys):
    review_path = tmp_path / "review.json"
    review_path.write_text(json.dumps(_valid_review(reviewed_sha="0" * 40)))

    rc = main([str(review_path), SHA])

    out = capsys.readouterr().out
    assert rc == 1
    assert "::error::" in out
    assert "reviewed_sha mismatch" in out


def test_main_requires_two_arguments(capsys):
    rc = main([])
    assert rc == 2
    assert "usage" in capsys.readouterr().out


# --- Malformed model-controlled values must never reach the run log ---------
#
# Validation error messages may name the field, the expected constraint, and
# the actual Python *type* -- never the value itself. A malformed field is
# still model-controlled text, and an error message is still a log line.

MARKER = "LEAKED_MODEL_TEXT_MARKER_deadbeef"


def _run_main_and_capture(tmp_path, capsys, review: dict) -> tuple[int, str]:
    path = tmp_path / "review.json"
    path.write_text(json.dumps(review))
    rc = main([str(path), SHA])
    captured = capsys.readouterr()
    return rc, captured.out + captured.err


def test_malformed_blockers_value_is_not_echoed(tmp_path, capsys):
    rc, out = _run_main_and_capture(tmp_path, capsys, _valid_review(blockers=MARKER))
    assert rc != 0
    assert MARKER not in out
    assert "blockers" in out


def test_non_string_blocker_items_are_not_echoed(tmp_path, capsys):
    rc, out = _run_main_and_capture(
        tmp_path, capsys, _valid_review(blockers=[{"text": MARKER}, 42])
    )
    assert rc != 0
    assert MARKER not in out
    assert "non-string type" in out


def test_malformed_important_value_is_not_echoed(tmp_path, capsys):
    rc, out = _run_main_and_capture(tmp_path, capsys, _valid_review(important=MARKER))
    assert rc != 0
    assert MARKER not in out
    assert "important" in out


def test_malformed_follow_up_value_is_not_echoed(tmp_path, capsys):
    rc, out = _run_main_and_capture(tmp_path, capsys, _valid_review(follow_up={"note": MARKER}))
    assert rc != 0
    assert MARKER not in out
    assert "follow_up" in out


def test_malformed_summary_value_is_not_echoed(tmp_path, capsys):
    rc, out = _run_main_and_capture(tmp_path, capsys, _valid_review(summary=[MARKER]))
    assert rc != 0
    assert MARKER not in out
    assert "summary" in out


def test_malformed_status_value_is_not_echoed(tmp_path, capsys):
    rc, out = _run_main_and_capture(tmp_path, capsys, _valid_review(status=MARKER))
    assert rc != 0
    assert MARKER not in out
    assert "status" in out


def test_malformed_reviewed_sha_value_is_not_echoed(tmp_path, capsys):
    rc, out = _run_main_and_capture(tmp_path, capsys, _valid_review(reviewed_sha=[MARKER]))
    assert rc != 0
    assert MARKER not in out
    assert "reviewed_sha" in out


def test_mismatched_reviewed_sha_string_is_not_echoed(tmp_path, capsys):
    # Schema-valid (a non-empty string) but wrong -- both the mismatch error
    # and the "Reviewed SHA:" metadata line must not echo the model's value;
    # only the workflow-controlled expected SHA may appear.
    rc, out = _run_main_and_capture(tmp_path, capsys, _valid_review(reviewed_sha=MARKER))
    assert rc != 0
    assert MARKER not in out
    assert "reviewed_sha mismatch" in out
    assert SHA in out  # the expected (workflow-controlled) SHA is fine to print
