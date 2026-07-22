"""Structural tests for .github/workflows/agent-orchestrator.yml.

These parse the actual workflow YAML and assert the authority-separation
properties that keep the Claude builder job read-only and confine all
write-capable GitHub operations (commit/push/PR) to the separate publish
job. This is not a substitute for a real workflow_dispatch run -- it can't
verify GitHub's own enforcement of `permissions:` or Claude Code's own
enforcement of its `settings.json` -- but it does catch an accidental
regression of the properties a human reviewer would otherwise have to
re-verify by eye on every future edit.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

WORKFLOW_PATH = Path(__file__).parent.parent / ".github" / "workflows" / "agent-orchestrator.yml"


@pytest.fixture(scope="module")
def workflow() -> dict:
    with open(WORKFLOW_PATH) as f:
        return yaml.safe_load(f)


@pytest.fixture(scope="module")
def build_job(workflow) -> dict:
    return workflow["jobs"]["build"]


@pytest.fixture(scope="module")
def publish_job(workflow) -> dict:
    return workflow["jobs"]["publish"]


def _all_run_text(job: dict) -> str:
    return "\n".join(step.get("run", "") for step in job["steps"])


def _all_uses(job: dict) -> list[str]:
    return [step.get("uses", "") for step in job["steps"]]


def test_workflow_trigger_is_manual_only(workflow):
    trigger = workflow.get("on") or workflow.get(True)
    assert set(trigger.keys()) == {"workflow_dispatch"}
    assert trigger["workflow_dispatch"]["inputs"]["issue_number"]["required"] is True


def test_build_job_permissions_are_read_only(build_job):
    assert build_job["permissions"] == {"contents": "read", "issues": "read"}


def test_build_job_has_no_write_permissions(build_job):
    perms = build_job["permissions"]
    assert "pull-requests" not in perms
    assert perms.get("contents") == "read"


def test_publish_job_has_the_write_scopes(publish_job):
    assert publish_job["permissions"] == {
        "contents": "write",
        "issues": "read",
        "pull-requests": "write",
    }


def test_no_job_grants_administration_or_workflow_authority(workflow):
    for job in workflow["jobs"].values():
        perms = job.get("permissions", {})
        assert "administration" not in perms
        assert "actions" not in perms
        assert "secrets" not in perms
        assert "security-events" not in perms


def test_publish_depends_on_build(publish_job):
    assert publish_job["needs"] == "build"


def test_publish_only_runs_when_build_succeeded_with_complete_status(publish_job):
    condition = publish_job["if"]
    assert "needs.build.result == 'success'" in condition
    assert "needs.build.outputs.status == 'COMPLETE'" in condition


def test_build_job_declares_outputs_publish_depends_on(build_job):
    assert "status" in build_job["outputs"]
    assert "branch" in build_job["outputs"]
    assert "base_sha" in build_job["outputs"]


def test_claude_code_action_runs_only_in_build(build_job, publish_job):
    assert any("claude-code-action" in u for u in _all_uses(build_job))
    assert not any("claude-code-action" in u for u in _all_uses(publish_job))


def test_git_push_and_gh_pr_create_run_only_in_publish(build_job, publish_job):
    build_text = _all_run_text(build_job)
    publish_text = _all_run_text(publish_job)

    assert "git push" not in build_text
    assert "gh pr create" not in build_text

    assert "git push" in publish_text
    assert "gh pr create" in publish_text


def test_no_force_push_anywhere(build_job, publish_job):
    combined = _all_run_text(build_job) + _all_run_text(publish_job)
    assert "--force" not in combined
    assert "push -f" not in combined
    assert "push --force-with-lease" not in combined


def test_no_merge_or_ready_command_anywhere(build_job, publish_job):
    combined = _all_run_text(build_job) + _all_run_text(publish_job)
    assert "gh pr merge" not in combined
    assert "gh pr ready" not in combined


def test_build_job_checkout_does_not_persist_credentials(build_job):
    checkout = next(
        s for s in build_job["steps"] if s.get("uses", "").startswith("actions/checkout")
    )
    assert checkout["with"]["persist-credentials"] is False


def test_build_job_produces_and_uploads_an_artifact(build_job):
    assert any(u.startswith("actions/upload-artifact") for u in _all_uses(build_job))
    build_text = _all_run_text(build_job)
    assert "implementation.patch" in build_text
    assert "build_metadata.json" in build_text


def test_publish_job_downloads_the_artifact(publish_job):
    assert any(u.startswith("actions/download-artifact") for u in _all_uses(publish_job))


def test_publish_job_verifies_base_sha_before_applying_patch(publish_job):
    names = [s.get("name") for s in publish_job["steps"]]
    assert names.index("Verify base SHA integrity") < names.index("Apply implementation patch")


def test_publish_job_checks_branch_does_not_already_exist(publish_job):
    combined = _all_run_text(publish_job)
    assert "git ls-remote" in combined
    assert "--exit-code" in combined


def test_publish_job_rechecks_protected_paths_after_applying_patch(publish_job):
    names = [s.get("name") for s in publish_job["steps"]]
    apply_index = names.index("Apply implementation patch")
    recheck_index = names.index("Re-check protected governance paths")
    assert apply_index < recheck_index
    combined = _all_run_text(publish_job)
    assert "check_builder_result.py" in combined


def test_settings_deny_protected_governance_paths(build_job):
    builder_step = next(s for s in build_job["steps"] if s.get("name") == "Run Claude Code builder")
    settings = json.loads(builder_step["with"]["settings"])
    deny = settings["permissions"]["deny"]

    assert any(".github/workflows/**" in rule for rule in deny)
    assert any(".agent-policy.yml" in rule for rule in deny)
    assert any("docs/AGENT_CONTRACT.md" in rule for rule in deny)
    # Both Edit and Write must be denied -- Edit alone would still let a
    # *new* file be created under a protected path via the Write tool.
    assert any(rule.startswith("Edit(") for rule in deny)
    assert any(rule.startswith("Write(") for rule in deny)


def test_settings_deny_git_mutation_and_gh_via_bash(build_job):
    builder_step = next(s for s in build_job["steps"] if s.get("name") == "Run Claude Code builder")
    settings = json.loads(builder_step["with"]["settings"])
    deny = settings["permissions"]["deny"]

    for mutating in ("Bash(git add*)", "Bash(git commit*)", "Bash(git push*)", "Bash(gh*)"):
        assert mutating in deny


def test_no_step_in_build_calls_check_builder_result_after_a_write(build_job):
    # The result/protected-path check must precede ruff/pytest/artifact
    # creation, so a failing check stops the job before any further work.
    names = [s.get("name") for s in build_job["steps"]]
    check_index = names.index("Stage and check builder result")
    assert check_index < names.index("Lint with ruff")
    assert check_index < names.index("Create implementation artifact")
