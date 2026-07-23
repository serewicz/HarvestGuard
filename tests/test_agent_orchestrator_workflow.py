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


@pytest.fixture(scope="module")
def review_job(workflow) -> dict:
    return workflow["jobs"]["review"]


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


def test_build_job_branch_output_references_the_branch_step(build_job):
    # Regression test: the "branch" step is what actually computes and
    # emits the branch name; a prior version wired the job-level output to
    # steps.set_outputs.outputs.branch instead, a step that never wrote a
    # "branch" key to $GITHUB_OUTPUT, so the output silently resolved to
    # an empty string.
    assert build_job["outputs"]["branch"] == "${{ steps.branch.outputs.branch }}"


def test_branch_step_actually_emits_branch_to_github_output(build_job):
    branch_step = next(s for s in build_job["steps"] if s.get("id") == "branch")
    assert branch_step["name"] == "Determine implementation branch name"
    assert 'echo "branch=$BRANCH" >> "$GITHUB_OUTPUT"' in branch_step["run"]


def test_publish_job_consumes_build_branch_output(publish_job):
    combined = _all_run_text(publish_job)
    assert "${{ needs.build.outputs.branch }}" in combined or any(
        step.get("env", {}).get("BRANCH") == "${{ needs.build.outputs.branch }}"
        for step in publish_job["steps"]
    )


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


# --- Codex Principal Review stage -----------------------------------------
#
# These mirror the authority-separation properties already covered above,
# applied to the new `review` job: it must be read-only end to end (no
# GitHub write scope, no mutating git/gh command, no merge/ready path), it
# must be the only place the Codex action runs, and it must actually pass
# and enforce the exact PR head SHA rather than trusting Codex's self-report.


def test_review_depends_on_publish(review_job):
    assert review_job["needs"] == "publish"


def test_review_only_runs_when_publish_succeeded(review_job):
    assert "needs.publish.result == 'success'" in review_job["if"]


def test_review_job_permissions_are_read_only(review_job):
    assert review_job["permissions"] == {
        "contents": "read",
        "pull-requests": "read",
        "issues": "read",
    }


def test_review_job_has_no_write_permissions(review_job):
    perms = review_job["permissions"]
    assert all(scope == "read" for scope in perms.values())


def test_review_job_checkout_does_not_persist_credentials(review_job):
    checkout = next(
        s for s in review_job["steps"] if s.get("uses", "").startswith("actions/checkout")
    )
    assert checkout["with"]["persist-credentials"] is False


def test_review_job_checks_out_the_exact_publish_pr_head_sha(review_job):
    checkout = next(
        s for s in review_job["steps"] if s.get("uses", "").startswith("actions/checkout")
    )
    assert checkout["with"]["ref"] == "${{ needs.publish.outputs.pr_head_sha }}"


def test_publish_job_declares_pr_number_and_head_sha_outputs(publish_job):
    assert "pr_number" in publish_job["outputs"]
    assert "pr_head_sha" in publish_job["outputs"]


def test_codex_action_runs_only_in_review(build_job, publish_job, review_job):
    assert not any("codex-action" in u for u in _all_uses(build_job))
    assert not any("codex-action" in u for u in _all_uses(publish_job))
    assert any("codex-action" in u for u in _all_uses(review_job))


def test_codex_step_uses_read_only_permission_profile(review_job):
    codex_step = next(s for s in review_job["steps"] if "codex-action" in s.get("uses", ""))
    assert codex_step["with"]["permission-profile"] == ":read-only"


def test_codex_step_uses_the_openai_api_key_secret(review_job):
    codex_step = next(s for s in review_job["steps"] if "codex-action" in s.get("uses", ""))
    assert codex_step["with"]["openai-api-key"] == "${{ secrets.OPENAI_API_KEY }}"


def test_codex_step_declares_the_structured_output_schema(review_job):
    codex_step = next(s for s in review_job["steps"] if "codex-action" in s.get("uses", ""))
    assert codex_step["with"]["output-schema-file"] == "scripts/codex_review_schema.json"


def test_review_job_validates_result_against_exact_pr_head_sha(review_job):
    names = [s.get("name") for s in review_job["steps"]]
    validate_step = review_job["steps"][names.index("Validate Codex review result")]
    assert "check_codex_review.py" in validate_step["run"]
    assert validate_step["env"]["PR_HEAD_SHA"] == "${{ needs.publish.outputs.pr_head_sha }}"


def test_codex_review_runs_after_validate_ci_checks(review_job):
    names = [s.get("name") for s in review_job["steps"]]
    codex_index = next(
        i for i, s in enumerate(review_job["steps"]) if "codex-action" in s.get("uses", "")
    )
    assert names.index("Wait for required CI checks on the PR") < codex_index
    assert codex_index < names.index("Validate Codex review result")


def test_review_job_has_no_write_capable_git_or_gh_command(review_job):
    combined = _all_run_text(review_job)
    for forbidden in (
        "git push",
        "git commit",
        "git checkout -b",
        "gh pr create",
        "gh pr edit",
        "gh pr merge",
        "gh pr ready",
        "gh pr review",
        "gh pr comment",
        "--force",
    ):
        assert forbidden not in combined


def test_review_job_uploads_result_as_artifact_and_does_not_post_to_pr(review_job):
    assert any(u.startswith("actions/upload-artifact") for u in _all_uses(review_job))
    combined = _all_run_text(review_job)
    assert "gh pr comment" not in combined
    assert "gh api" not in combined
