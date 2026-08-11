import json

from scripts.resolve_session_id import main, resolve


def write_execution(path, event):
    path.write_text(json.dumps([{"type": "assistant", "message": "work"}, event]))


def test_prefers_the_action_session_id_output_when_present(tmp_path):
    execution = tmp_path / "execution.json"
    write_execution(
        execution,
        {"type": "result", "subtype": "success", "session_id": "from-execution-file"},
    )
    assert resolve("from-action-output", execution) == "from-action-output"


def test_max_turns_result_with_session_id_falls_back_when_action_output_absent(tmp_path):
    execution = tmp_path / "execution.json"
    write_execution(
        execution,
        {
            "type": "result",
            "subtype": "error_max_turns",
            "session_id": "1d43ee66-a2c0-4ba9-baf6-c388f9ac2723",
        },
    )
    assert resolve("", execution) == "1d43ee66-a2c0-4ba9-baf6-c388f9ac2723"


def test_whitespace_only_action_output_also_falls_back(tmp_path):
    execution = tmp_path / "execution.json"
    write_execution(
        execution,
        {"type": "result", "subtype": "error_max_turns", "session_id": "real-session-id"},
    )
    assert resolve("   ", execution) == "real-session-id"


def test_missing_execution_file_fails_closed_to_none():
    assert resolve("", None) is None


def test_nonexistent_execution_file_path_fails_closed_to_none(tmp_path):
    assert resolve("", tmp_path / "does-not-exist.json") is None


def test_execution_file_without_a_terminal_result_event_fails_closed(tmp_path):
    execution = tmp_path / "execution.json"
    execution.write_text(json.dumps([{"type": "assistant", "message": "no terminal event"}]))
    assert resolve("", execution) is None


def test_terminal_result_event_missing_session_id_fails_closed(tmp_path):
    execution = tmp_path / "execution.json"
    write_execution(execution, {"type": "result", "subtype": "error_max_turns"})
    assert resolve("", execution) is None


def test_terminal_result_event_with_blank_session_id_fails_closed(tmp_path):
    execution = tmp_path / "execution.json"
    write_execution(execution, {"type": "result", "subtype": "error_max_turns", "session_id": ""})
    assert resolve("", execution) is None


def test_malformed_execution_file_fails_closed(tmp_path):
    execution = tmp_path / "execution.json"
    execution.write_text("{not valid json")
    assert resolve("", execution) is None


def test_cli_prints_resolved_session_id(tmp_path, capsys):
    execution = tmp_path / "execution.json"
    write_execution(
        execution,
        {"type": "result", "subtype": "error_max_turns", "session_id": "resolved-id"},
    )
    assert main(["", str(execution)]) == 0
    assert capsys.readouterr().out == "resolved-id\n"


def test_cli_prints_nothing_when_unresolvable(tmp_path, capsys):
    assert main(["", str(tmp_path / "missing.json")]) == 0
    assert capsys.readouterr().out == ""


def test_cli_requires_exact_arguments(capsys):
    assert main([]) == 2
    assert "usage" in capsys.readouterr().err
