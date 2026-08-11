import json

from scripts.classify_builder_segment import should_continue, terminal_event


def write_execution(path, event, transcript=""):
    path.write_text(json.dumps([{"type": "assistant", "message": transcript}, event]))


def test_structured_turn_exhaustion_continues(tmp_path):
    execution = tmp_path / "execution.json"
    write_execution(execution, {"type": "result", "subtype": "error_max_turns"})
    assert should_continue("failure", tmp_path / "missing.json", execution)


def test_success_transcript_mentioning_max_turns_does_not_continue(tmp_path):
    execution = tmp_path / "execution.json"
    write_execution(
        execution,
        {"type": "result", "subtype": "success"},
        "The issue discusses max_turns but work is complete.",
    )
    assert not should_continue("success", tmp_path / "missing.json", execution)


def test_unrelated_failure_transcript_mentioning_turn_limit_does_not_continue(tmp_path):
    execution = tmp_path / "execution.json"
    write_execution(
        execution,
        {"type": "result", "subtype": "error_during_execution"},
        "The issue contains the words turn limit.",
    )
    assert not should_continue("failure", tmp_path / "missing.json", execution)


def test_missing_structured_terminal_status_does_not_continue(tmp_path):
    execution = tmp_path / "execution.json"
    execution.write_text('{"message":"max_turns"}\nnot-json\n')
    assert terminal_event(execution) is None
    assert not should_continue("failure", tmp_path / "missing.json", execution)


def test_complete_needs_human_and_failed_results_skip_continuation(tmp_path):
    execution = tmp_path / "execution.json"
    write_execution(execution, {"type": "result", "subtype": "error_max_turns"})
    for status in ("COMPLETE", "NEEDS_HUMAN", "FAILED"):
        result = tmp_path / "result.json"
        result.write_text(json.dumps({"status": status}))
        assert not should_continue("failure", result, execution)


def test_json_lines_terminal_event_is_supported(tmp_path):
    execution = tmp_path / "execution.jsonl"
    execution.write_text(
        '{"type":"assistant","message":"max_turns"}\n'
        '{"type":"result","subtype":"error_max_turns","num_turns":40}\n'
    )
    assert terminal_event(execution)["num_turns"] == 40
