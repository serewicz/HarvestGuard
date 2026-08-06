import json

from scripts.classify_builder_segment import should_continue


def test_turn_exhaustion_continues(tmp_path):
    execution = tmp_path / "execution.json"
    execution.write_text('{"result":"Error: Reached max turns (40)"}')
    assert should_continue("failure", tmp_path / "missing.json", execution)


def test_complete_and_needs_human_skip_continuation(tmp_path):
    execution = tmp_path / "execution.json"
    execution.write_text('{"result":"Reached max turns"}')
    for status in ("COMPLETE", "NEEDS_HUMAN", "FAILED"):
        result = tmp_path / "result.json"
        result.write_text(json.dumps({"status": status}))
        assert not should_continue("failure", result, execution)


def test_non_turn_failure_does_not_continue(tmp_path):
    execution = tmp_path / "execution.json"
    execution.write_text('{"result":"authentication failed"}')
    assert not should_continue("failure", tmp_path / "missing.json", execution)
