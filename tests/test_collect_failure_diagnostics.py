"""Tests for scripts/collect_failure_diagnostics.py, which preserves safe
diagnostics after a Claude Code action step fails (most commonly: the
max-turns limit was reached) in the `build`/`correct_1`/`correct_2`/
`correct_3` jobs of .github/workflows/agent-orchestrator.yml.
"""

from __future__ import annotations

import json

import scripts.collect_failure_diagnostics as diag


def _fake_aws_key() -> str:
    """AWS-access-key-shaped value built at runtime, not a literal in
    source -- same technique as tests/test_classifier.py, so this test
    exercises the real production detector without committing a matchable
    secret shape."""
    return "AKIA" + "FAKE0000FAKE0000"


def _fake_openai_key() -> str:
    """Legacy/bare OpenAI-key-shaped value (`sk-<20+ alnum>`), built at
    runtime for the same reason as _fake_aws_key(): OpenAI keys are a
    supported GitHub push-protection pattern, so no single literal in this
    file's source may match the shape."""
    return "sk-" + "1234567890abcdefghijklmnop"


def _fake_google_api_key() -> str:
    """Google-API-key-shaped value (`AIza` + 20+ chars), built at runtime
    for the same reason as _fake_aws_key()."""
    return "AIza" + "SyAabcdefghijklmnopqrstuvwxyz1234"


def _fake_azure_account_key() -> str:
    """Azure-Storage-account-key-shaped value (base64-ish, 20+ chars),
    built at runtime for the same reason as _fake_aws_key()."""
    return "".join(["abcd1234EFGH5678", "ijkl9012MNOP3456", "ab=="])


def test_safe_working_tree_is_written_verbatim(tmp_path, monkeypatch):
    monkeypatch.setattr(
        diag,
        "_run_git",
        lambda args: "diff --git a/foo.py b/foo.py\n+def bar(): pass\n"
        if "diff" in args
        else " M foo.py\n",
    )

    diag.collect("build", tmp_path, "sess-123", "failure")

    assert "def bar" in (tmp_path / "git_diff.txt").read_text()
    assert "M foo.py" in (tmp_path / "git_status.txt").read_text()
    metadata = json.loads((tmp_path / "metadata.json").read_text())
    assert metadata["content_redacted"] is False


def test_aws_shaped_content_triggers_redaction(tmp_path, monkeypatch):
    key = _fake_aws_key()
    monkeypatch.setattr(
        diag,
        "_run_git",
        lambda args: f"aws_access_key_id = {key}" if "diff" in args else "",
    )

    diag.collect("build", tmp_path, "sess-123", "failure")

    diff_text = (tmp_path / "git_diff.txt").read_text()
    status_text = (tmp_path / "git_status.txt").read_text()
    assert key not in diff_text
    assert key not in status_text
    assert "withheld" in diff_text
    assert "withheld" in status_text
    metadata = json.loads((tmp_path / "metadata.json").read_text())
    assert metadata["content_redacted"] is True


def test_github_token_shaped_content_triggers_redaction(tmp_path, monkeypatch):
    token = "ghp_" + "FAKE0000000000TESTONLYNOTREALVALUE00"
    monkeypatch.setattr(
        diag, "_run_git", lambda args: f"GITHUB_TOKEN={token}" if "diff" in args else ""
    )

    diag.collect("build", tmp_path, "sess-123", "failure")

    diff_text = (tmp_path / "git_diff.txt").read_text()
    assert token not in diff_text
    assert "withheld" in diff_text


def test_slack_token_shaped_content_triggers_redaction(tmp_path, monkeypatch):
    token = "-".join(["xoxb", "FAKE0000000000", "TESTONLYNOTREAL"])
    monkeypatch.setattr(
        diag, "_run_git", lambda args: f"SLACK_TOKEN={token}" if "diff" in args else ""
    )

    diag.collect("build", tmp_path, "sess-123", "failure")

    diff_text = (tmp_path / "git_diff.txt").read_text()
    assert token not in diff_text
    assert "withheld" in diff_text


def test_private_key_shaped_content_triggers_redaction(tmp_path, monkeypatch):
    monkeypatch.setattr(
        diag,
        "_run_git",
        lambda args: "-----BEGIN RSA PRIVATE KEY-----\nsomefakebody\n" if "diff" in args else "",
    )

    diag.collect("build", tmp_path, "sess-123", "failure")

    diff_text = (tmp_path / "git_diff.txt").read_text()
    assert "BEGIN RSA PRIVATE KEY" not in diff_text
    assert "withheld" in diff_text


def test_openai_key_in_api_key_context_triggers_redaction(tmp_path, monkeypatch):
    key = _fake_openai_key()
    monkeypatch.setattr(
        diag, "_run_git", lambda args: f'OPENAI_API_KEY="{key}"' if "diff" in args else ""
    )

    diag.collect("build", tmp_path, "sess-123", "failure")

    diff_text = (tmp_path / "git_diff.txt").read_text()
    status_text = (tmp_path / "git_status.txt").read_text()
    assert key not in diff_text
    assert key not in status_text
    assert "withheld" in diff_text
    metadata = json.loads((tmp_path / "metadata.json").read_text())
    assert metadata["content_redacted"] is True


def test_bare_sk_key_without_api_key_context_is_not_flagged():
    # The contextual gate is deliberate: a bare `sk-...`-shaped substring
    # with no api-key/openai label nearby must not cause every diff
    # containing the letters "sk-" to be redacted.
    key = _fake_openai_key()
    assert "OpenAI API Key" not in diag._looks_unsafe(f"see the {key} discussion in ticket sk-1")


def test_google_api_key_triggers_redaction(tmp_path, monkeypatch):
    key = _fake_google_api_key()
    monkeypatch.setattr(
        diag, "_run_git", lambda args: f'GOOGLE_API_KEY="{key}"' if "diff" in args else ""
    )

    diag.collect("build", tmp_path, "sess-123", "failure")

    diff_text = (tmp_path / "git_diff.txt").read_text()
    assert key not in diff_text
    assert "withheld" in diff_text
    metadata = json.loads((tmp_path / "metadata.json").read_text())
    assert metadata["content_redacted"] is True


def test_azure_storage_connection_string_triggers_redaction(tmp_path, monkeypatch):
    account_key = _fake_azure_account_key()
    connection_string = (
        "DefaultEndpointsProtocol=https;AccountName=test;"
        f"AccountKey={account_key};EndpointSuffix=core.windows.net"
    )
    def _fake_run_git(args):
        return f'AZURE_STORAGE_CONNECTION_STRING="{connection_string}"' if "diff" in args else ""

    monkeypatch.setattr(diag, "_run_git", _fake_run_git)

    diag.collect("build", tmp_path, "sess-123", "failure")

    diff_text = (tmp_path / "git_diff.txt").read_text()
    assert account_key not in diff_text
    assert connection_string not in diff_text
    assert "withheld" in diff_text
    metadata = json.loads((tmp_path / "metadata.json").read_text())
    assert metadata["content_redacted"] is True


def test_bare_azure_account_key_triggers_redaction(tmp_path, monkeypatch):
    # Same credential material, without the surrounding connection-string
    # fields -- must still be caught on its own.
    account_key = _fake_azure_account_key()
    monkeypatch.setattr(
        diag, "_run_git", lambda args: f"AccountKey={account_key}" if "diff" in args else ""
    )

    diag.collect("build", tmp_path, "sess-123", "failure")

    diff_text = (tmp_path / "git_diff.txt").read_text()
    assert account_key not in diff_text
    assert "withheld" in diff_text


def test_extra_risk_prefix_triggers_redaction(tmp_path, monkeypatch):
    # Anthropic-key-shaped prefix, not covered by classifier.scanner's
    # service-credential patterns -- the belt-and-suspenders check.
    monkeypatch.setattr(
        diag, "_run_git", lambda args: "ANTHROPIC_API_KEY=sk-ant-fake0000" if "diff" in args else ""
    )

    diag.collect("build", tmp_path, "sess-123", "failure")

    diff_text = (tmp_path / "git_diff.txt").read_text()
    assert "sk-ant-fake0000" not in diff_text
    assert "withheld" in diff_text


def test_metadata_never_contains_the_diff_or_status_text(tmp_path, monkeypatch):
    def _fake_run_git(args):
        return "UNIQUE_MARKER_abc123" if "diff" in args else "STATUS_MARKER_xyz"

    monkeypatch.setattr(diag, "_run_git", _fake_run_git)

    diag.collect("correct_2", tmp_path, "sess-456", "failure")

    metadata_text = (tmp_path / "metadata.json").read_text()
    assert "UNIQUE_MARKER_abc123" not in metadata_text
    assert "STATUS_MARKER_xyz" not in metadata_text


def test_metadata_reports_configured_max_turns_and_job(tmp_path, monkeypatch):
    monkeypatch.setattr(diag, "_run_git", lambda args: "")

    diag.collect("correct_3", tmp_path, "sess-789", "failure")

    metadata = json.loads((tmp_path / "metadata.json").read_text())
    assert metadata["configured_max_turns"] == 60
    assert metadata["job"] == "correct_3"
    assert metadata["failed_step"] == "Run Claude Code correction"
    assert metadata["session_id"] == "sess-789"


def test_build_job_reports_the_build_step_name(tmp_path, monkeypatch):
    monkeypatch.setattr(diag, "_run_git", lambda args: "")

    diag.collect("build", tmp_path, "sess-1", "failure")

    metadata = json.loads((tmp_path / "metadata.json").read_text())
    assert metadata["failed_step"] == "Run Claude Code builder"


def test_output_never_includes_environment_dump(tmp_path, monkeypatch):
    # collect() never shells out to anything but `git status`/`git diff` --
    # there is no path by which an env dump could appear in its output.
    calls = []

    def _fake_run_git(args):
        calls.append(args)
        return ""

    monkeypatch.setattr(diag, "_run_git", _fake_run_git)
    diag.collect("build", tmp_path, "sess-1", "failure")

    assert calls == [["status", "--porcelain"], ["diff"]]


def test_main_requires_four_arguments(capsys):
    rc = diag.main([])
    assert rc == 2
    assert "usage" in capsys.readouterr().out
