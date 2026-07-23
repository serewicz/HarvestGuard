"""Tests for scripts/check_codex_review.py, the gate between the Codex
Principal Reviewer step and the rest of the `review` job in
.github/workflows/agent-orchestrator.yml.
"""

from __future__ import annotations

import json

from scripts.check_codex_review import check, load_review, main

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


def test_approved_review_of_expected_sha_passes():
    assert check(_valid_review(), SHA) == []


def test_blockers_status_still_passes_validation_when_sha_matches():
    # Validation here is about well-formedness + exact-SHA match, not about
    # whether the verdict itself was APPROVED -- BLOCKERS is a legitimate,
    # valid outcome the workflow log/artifact should still faithfully record.
    review = _valid_review(status="BLOCKERS", blockers=["Missing input validation on X."])
    assert check(review, SHA) == []


def test_needs_human_status_still_passes_validation_when_sha_matches():
    review = _valid_review(status="NEEDS_HUMAN", summary="Ambiguous product-boundary question.")
    assert check(review, SHA) == []


def test_unrecognized_status_fails():
    reasons = check(_valid_review(status="LGTM"), SHA)
    assert reasons
    assert any("status" in r for r in reasons)


def test_reviewed_sha_mismatch_fails():
    reasons = check(_valid_review(reviewed_sha="0" * 40), SHA)
    assert reasons
    assert any("reviewed_sha mismatch" in r for r in reasons)


def test_reviewed_sha_missing_fails():
    review = _valid_review()
    del review["reviewed_sha"]
    reasons = check(review, SHA)
    assert reasons
    assert any("Missing required field" in r and "reviewed_sha" in r for r in reasons)


def test_missing_top_level_field_fails():
    review = _valid_review()
    del review["summary"]
    reasons = check(review, SHA)
    assert reasons
    assert any("summary" in r for r in reasons)


def test_blockers_not_a_list_of_strings_fails():
    reasons = check(_valid_review(blockers="not a list"), SHA)
    assert reasons
    assert any("blockers" in r for r in reasons)


def test_blockers_with_non_string_items_fails():
    reasons = check(_valid_review(blockers=[{"nested": "object"}]), SHA)
    assert reasons
    assert any("blockers" in r for r in reasons)


def test_empty_summary_fails():
    reasons = check(_valid_review(summary=""), SHA)
    assert reasons
    assert any("summary" in r for r in reasons)


def test_missing_result_file_fails_via_main(tmp_path, capsys):
    rc = main([str(tmp_path / "does-not-exist.json"), SHA])
    assert rc == 1
    assert "::error::" in capsys.readouterr().out


def test_empty_result_file_fails_via_main(tmp_path, capsys):
    empty = tmp_path / "empty.json"
    empty.write_text("")
    rc = main([str(empty), SHA])
    assert rc == 1
    assert "empty" in capsys.readouterr().out


def test_malformed_json_fails_via_main(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text("{not valid json")
    rc = main([str(bad), SHA])
    assert rc == 1
    assert "not valid JSON" in capsys.readouterr().out


def test_non_object_json_fails_via_main(tmp_path, capsys):
    bad = tmp_path / "list.json"
    bad.write_text("[1, 2, 3]")
    rc = main([str(bad), SHA])
    assert rc == 1
    assert "JSON object" in capsys.readouterr().out


def test_main_proceeds_for_valid_review_and_prints_summary(tmp_path, capsys):
    review_path = tmp_path / "review.json"
    review_path.write_text(json.dumps(_valid_review()))

    rc = main([str(review_path), SHA])

    out = capsys.readouterr().out
    assert rc == 0
    assert "Codex review valid" in out
    assert SHA in out


def test_main_fails_for_sha_mismatch_without_traceback(tmp_path, capsys):
    review_path = tmp_path / "review.json"
    review_path.write_text(json.dumps(_valid_review(reviewed_sha="wrongsha")))

    rc = main([str(review_path), SHA])

    out = capsys.readouterr().out
    assert rc == 1
    assert "::error::" in out
    assert "reviewed_sha mismatch" in out


def test_main_requires_two_arguments(capsys):
    rc = main([])
    assert rc == 2
    assert "usage" in capsys.readouterr().out


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
