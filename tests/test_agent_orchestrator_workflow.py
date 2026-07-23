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


@pytest.fixture(scope="module")
def correct_job(workflow) -> dict:
    return workflow["jobs"]["correct"]


@pytest.fixture(scope="module")
def publish_correction_job(workflow) -> dict:
    return workflow["jobs"]["publish_correction"]


@pytest.fixture(scope="module")
def rereview_job(workflow) -> dict:
    return workflow["jobs"]["rereview"]


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


def test_claude_code_action_runs_only_in_read_only_jobs(workflow):
    # Claude runs in exactly two places -- build and correct -- and both
    # hold read-only GitHub tokens. It must never appear in a job with any
    # write scope (publish, publish_correction).
    for job_id, job in workflow["jobs"].items():
        has_claude = any("claude-code-action" in u for u in _all_uses(job))
        if job_id in ("build", "correct"):
            assert has_claude
        else:
            assert not has_claude, f"claude-code-action must not run in {job_id}"


def test_git_push_and_gh_pr_create_run_only_in_publish(build_job, publish_job):
    build_text = _all_run_text(build_job)
    publish_text = _all_run_text(publish_job)

    assert "git push" not in build_text
    assert "gh pr create" not in build_text

    assert "git push" in publish_text
    assert "gh pr create" in publish_text


def test_no_force_push_anywhere(workflow):
    combined = "".join(_all_run_text(job) for job in workflow["jobs"].values())
    assert "--force" not in combined
    assert "push -f" not in combined
    assert "push --force-with-lease" not in combined


def test_no_merge_or_ready_command_anywhere(workflow):
    combined = "".join(_all_run_text(job) for job in workflow["jobs"].values())
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


def test_codex_action_runs_only_in_the_two_read_only_review_jobs(workflow):
    for job_id, job in workflow["jobs"].items():
        has_codex = any("codex-action" in u for u in _all_uses(job))
        if job_id in ("review", "rereview"):
            assert has_codex
        else:
            assert not has_codex, f"codex-action must not run in {job_id}"


def test_codex_step_uses_read_only_permission_profile(review_job):
    codex_step = next(s for s in review_job["steps"] if "codex-action" in s.get("uses", ""))
    assert codex_step["with"]["permission-profile"] == ":read-only"


def test_codex_step_uses_the_openai_api_key_secret(review_job):
    codex_step = next(s for s in review_job["steps"] if "codex-action" in s.get("uses", ""))
    assert codex_step["with"]["openai-api-key"] == "${{ secrets.OPENAI_API_KEY }}"


def test_codex_step_declares_the_structured_output_schema(review_job):
    codex_step = next(s for s in review_job["steps"] if "codex-action" in s.get("uses", ""))
    assert codex_step["with"]["output-schema-file"] == "scripts/codex_review_schema.json"


def test_review_job_routes_result_against_exact_pr_head_sha(review_job):
    names = [s.get("name") for s in review_job["steps"]]
    route_step = review_job["steps"][names.index("Route Codex review result")]
    assert "route_codex_review.py" in route_step["run"]
    assert route_step["env"]["PR_HEAD_SHA"] == "${{ needs.publish.outputs.pr_head_sha }}"
    assert route_step["id"] == "route"


def test_review_job_exposes_the_routed_status_as_an_output(review_job):
    assert review_job["outputs"]["review_status"] == "${{ steps.route.outputs.status }}"


def test_codex_review_runs_before_route_step(review_job):
    names = [s.get("name") for s in review_job["steps"]]
    codex_index = next(
        i for i, s in enumerate(review_job["steps"]) if "codex-action" in s.get("uses", "")
    )
    assert codex_index < names.index("Route Codex review result")


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


# --- CI gating hardening: fail closed on the exact PR head SHA -------------

WAIT_STEP_NAME = "Wait for required CI checks on the exact PR head SHA"


def test_ci_wait_step_uses_the_committed_required_ci_checker(review_job):
    wait_step = next(s for s in review_job["steps"] if s.get("name") == WAIT_STEP_NAME)
    assert "scripts/check_required_ci.py" in wait_step["run"]
    assert "$PR_HEAD_SHA" in wait_step["run"]
    assert wait_step["env"]["PR_HEAD_SHA"] == "${{ needs.publish.outputs.pr_head_sha }}"


def test_ci_wait_step_fetches_check_runs_for_the_exact_sha_not_the_pr(review_job):
    wait_step = next(s for s in review_job["steps"] if s.get("name") == WAIT_STEP_NAME)
    # Regression guard: the earlier version used `gh pr checks`, which
    # reflects the PR's *current* head, not necessarily the SHA this job
    # actually checked out and is about to hand to Codex.
    assert "commits/$PR_HEAD_SHA/check-runs" in wait_step["run"]
    assert "gh pr checks" not in wait_step["run"]


def test_ci_wait_step_is_bounded(review_job):
    wait_step = next(s for s in review_job["steps"] if s.get("name") == WAIT_STEP_NAME)
    assert "MAX_WAIT_SECONDS" in wait_step["run"]
    assert "Timed out" in wait_step["run"]


def test_ci_wait_step_precedes_codex_invocation(review_job):
    names = [s.get("name") for s in review_job["steps"]]
    codex_index = next(
        i for i, s in enumerate(review_job["steps"]) if "codex-action" in s.get("uses", "")
    )
    assert names.index(WAIT_STEP_NAME) < codex_index


# --- Codex step hardening ---------------------------------------------------


def test_codex_step_sets_drop_sudo_safety_strategy_explicitly(review_job):
    codex_step = next(s for s in review_job["steps"] if "codex-action" in s.get("uses", ""))
    assert codex_step["with"]["safety-strategy"] == "drop-sudo"


# --- Review artifact preserved even when validation fails closed -----------


def test_upload_review_artifact_step_runs_even_on_failure(review_job):
    upload_step = next(
        s for s in review_job["steps"] if s.get("name") == "Upload Codex review artifact (cycle 0)"
    )
    assert upload_step["if"] == "always()"
    assert upload_step["with"]["if-no-files-found"] == "ignore"
    assert upload_step["with"]["name"] == "codex-review-cycle-0"


# --- One-cycle correction loop ----------------------------------------------
#
# These pin the structural properties of the correction chain:
# correct (Claude, read-only) -> publish_correction (deterministic, write)
# -> rereview (Codex, read-only, strict final gate). The behavioral halves
# (routing exit codes, cycle-limit math, log redaction) live in
# tests/test_route_codex_review.py and tests/test_check_cycle_limit.py.


def test_correct_runs_only_after_a_blockers_verdict(correct_job):
    # APPROVED first review -> review_status is APPROVED -> this condition
    # is false -> no correction. NEEDS_HUMAN/malformed -> the review job
    # itself failed -> result != success -> no correction.
    condition = correct_job["if"]
    assert "needs.review.result == 'success'" in condition
    assert "needs.review.outputs.review_status == 'BLOCKERS'" in condition


def test_correct_job_permissions_are_read_only(correct_job):
    assert correct_job["permissions"] == {
        "contents": "read",
        "issues": "read",
        "pull-requests": "read",
    }


def test_correct_job_checks_out_the_reviewed_sha_without_credentials(correct_job):
    checkout = next(
        s for s in correct_job["steps"] if s.get("uses", "").startswith("actions/checkout")
    )
    assert checkout["with"]["ref"] == "${{ needs.publish.outputs.pr_head_sha }}"
    assert checkout["with"]["persist-credentials"] is False


def test_correct_job_enforces_the_cycle_limit_before_claude_runs(correct_job):
    names = [s.get("name") for s in correct_job["steps"]]
    limit_index = names.index("Enforce correction cycle limit")
    limit_step = correct_job["steps"][limit_index]
    assert "check_cycle_limit.py .agent-policy.yml 1" in limit_step["run"]
    claude_index = next(
        i for i, s in enumerate(correct_job["steps"]) if "claude-code-action" in s.get("uses", "")
    )
    assert limit_index < claude_index


def test_correct_job_settings_deny_protected_paths_and_git_mutation(correct_job):
    claude_step = next(
        s for s in correct_job["steps"] if "claude-code-action" in s.get("uses", "")
    )
    deny = json.loads(claude_step["with"]["settings"])["permissions"]["deny"]
    assert any(".github/workflows/**" in rule for rule in deny)
    assert any(".agent-policy.yml" in rule for rule in deny)
    assert any("docs/AGENT_CONTRACT.md" in rule for rule in deny)
    for mutating in ("Bash(git add*)", "Bash(git commit*)", "Bash(git push*)", "Bash(gh*)"):
        assert mutating in deny


def test_correct_job_gates_its_result_before_producing_the_artifact(correct_job):
    # A FAILED/NEEDS_HUMAN/violating result fails this step, so the job
    # fails, publish_correction's `if:` never fires, and nothing is pushed.
    names = [s.get("name") for s in correct_job["steps"]]
    check_index = names.index("Stage and check correction result")
    assert "check_builder_result.py" in correct_job["steps"][check_index]["run"]
    assert check_index < names.index("Create correction artifact")


def test_correct_job_uploads_the_cycle_1_correction_artifact(correct_job):
    upload = next(
        s for s in correct_job["steps"] if s.get("uses", "").startswith("actions/upload-artifact")
    )
    assert upload["with"]["name"] == "claude-correction-cycle-1"


def test_correct_job_never_pushes_or_touches_gh_pr(correct_job):
    combined = _all_run_text(correct_job)
    assert "git push" not in combined
    assert "git commit" not in combined
    assert "gh pr" not in combined


def test_publish_correction_runs_only_for_a_complete_correction(publish_correction_job):
    condition = publish_correction_job["if"]
    assert "needs.correct.result == 'success'" in condition
    assert "needs.correct.outputs.status == 'COMPLETE'" in condition


def test_publish_correction_permissions_are_exactly_write_contents_read_prs(
    publish_correction_job,
):
    assert publish_correction_job["permissions"] == {
        "contents": "write",
        "pull-requests": "read",
    }


def test_publish_correction_verifies_branch_head_before_anything_else(publish_correction_job):
    names = [s.get("name") for s in publish_correction_job["steps"]]
    verify_index = names.index("Verify PR branch head still equals the reviewed SHA")
    verify_step = publish_correction_job["steps"][verify_index]
    assert "git ls-remote origin" in verify_step["run"]
    assert verify_step["env"]["REVIEWED_SHA"] == "${{ needs.publish.outputs.pr_head_sha }}"
    # Stale-SHA check must precede patch application, commit, and push.
    assert verify_index < names.index("Apply correction patch")
    assert verify_index < names.index("Commit correction")
    assert verify_index < names.index("Push correction to the PR branch")


def test_publish_correction_verifies_the_patch_base_sha(publish_correction_job):
    names = [s.get("name") for s in publish_correction_job["steps"]]
    base_index = names.index("Verify correction base SHA and cycle")
    assert base_index < names.index("Apply correction patch")


def test_publish_correction_rechecks_protected_paths_after_applying(publish_correction_job):
    names = [s.get("name") for s in publish_correction_job["steps"]]
    apply_index = names.index("Apply correction patch")
    recheck_index = names.index("Re-check protected governance paths")
    assert apply_index < recheck_index < names.index("Commit correction")
    assert "check_builder_result.py" in _all_run_text(publish_correction_job)


def test_publish_correction_commits_once_and_pushes_plainly(publish_correction_job):
    combined = _all_run_text(publish_correction_job)
    assert combined.count("git commit") == 1
    assert combined.count("git push") == 1
    push_step = next(
        s
        for s in publish_correction_job["steps"]
        if s.get("name") == "Push correction to the PR branch"
    )
    # Plain push to the existing branch ref -- no force, no new branch, no
    # second PR.
    assert push_step["run"] == 'git push origin "HEAD:refs/heads/$BRANCH"'


def test_publish_correction_never_creates_a_pr(publish_correction_job):
    assert "gh pr create" not in _all_run_text(publish_correction_job)


def test_gh_pr_create_appears_exactly_once_in_the_whole_workflow(workflow):
    combined = "".join(_all_run_text(job) for job in workflow["jobs"].values())
    assert combined.count("gh pr create") == 1  # publish only -- never a second PR


def test_rereview_runs_only_after_a_successful_correction_publish(rereview_job):
    assert rereview_job["needs"] == ["publish", "publish_correction"]
    assert "needs.publish_correction.result == 'success'" in rereview_job["if"]


def test_rereview_permissions_are_read_only(rereview_job):
    assert rereview_job["permissions"] == {
        "contents": "read",
        "pull-requests": "read",
        "issues": "read",
    }


def test_rereview_checks_out_the_exact_correction_sha_without_credentials(rereview_job):
    checkout = next(
        s for s in rereview_job["steps"] if s.get("uses", "").startswith("actions/checkout")
    )
    assert checkout["with"]["ref"] == "${{ needs.publish_correction.outputs.correction_sha }}"
    assert checkout["with"]["persist-credentials"] is False


def test_rereview_gates_on_required_ci_for_the_correction_sha_before_codex(rereview_job):
    names = [s.get("name") for s in rereview_job["steps"]]
    wait_index = names.index("Wait for required CI checks on the correction SHA")
    wait_step = rereview_job["steps"][wait_index]
    assert "check_required_ci.py" in wait_step["run"]
    assert "MAX_WAIT_SECONDS" in wait_step["run"]
    assert (
        wait_step["env"]["PR_HEAD_SHA"]
        == "${{ needs.publish_correction.outputs.correction_sha }}"
    )
    codex_index = next(
        i for i, s in enumerate(rereview_job["steps"]) if "codex-action" in s.get("uses", "")
    )
    # CI fail -> the wait step exits 1 -> Codex never runs.
    assert wait_index < codex_index


def test_rereview_validates_strictly_against_the_correction_sha(rereview_job):
    # The strict gate (check_codex_review.py, not the router): a second
    # BLOCKERS, NEEDS_HUMAN, or any non-empty important exits non-zero and
    # ends the run -- and no job in the workflow depends on rereview, so
    # a second correction cannot exist to trigger.
    names = [s.get("name") for s in rereview_job["steps"]]
    validate_step = rereview_job["steps"][names.index("Validate Codex re-review result")]
    assert "check_codex_review.py" in validate_step["run"]
    assert "route_codex_review.py" not in validate_step["run"]
    assert (
        validate_step["env"]["PR_HEAD_SHA"]
        == "${{ needs.publish_correction.outputs.correction_sha }}"
    )


def test_rereview_uploads_the_cycle_1_artifact_even_on_failure(rereview_job):
    upload = next(
        s
        for s in rereview_job["steps"]
        if s.get("name") == "Upload Codex review artifact (cycle 1)"
    )
    assert upload["if"] == "always()"
    assert upload["with"]["name"] == "codex-review-cycle-1"
    assert upload["with"]["if-no-files-found"] == "ignore"


def test_nothing_depends_on_rereview_so_no_second_cycle_can_exist(workflow):
    for job_id, job in workflow["jobs"].items():
        needs = job.get("needs") or []
        needs = [needs] if isinstance(needs, str) else needs
        assert "rereview" not in needs, f"{job_id} must not chain off the final review"


def test_exactly_one_correction_chain_exists(workflow):
    job_ids = set(workflow["jobs"].keys())
    assert job_ids == {"build", "publish", "review", "correct", "publish_correction", "rereview"}
    all_uses = [u for job in workflow["jobs"].values() for u in _all_uses(job)]
    assert sum("codex-action" in u for u in all_uses) == 2  # cycle 0 + cycle 1, no more
    assert sum("claude-code-action" in u for u in all_uses) == 2  # build + one correction


def test_no_agent_runs_in_a_write_capable_job(workflow):
    for job_id, job in workflow["jobs"].items():
        perms = job.get("permissions", {})
        has_write = any(scope == "write" for scope in perms.values())
        runs_agent = any(
            "claude-code-action" in u or "codex-action" in u for u in _all_uses(job)
        )
        assert not (has_write and runs_agent), f"{job_id} runs an agent with write scope"


# --- Codex escalation criteria ----------------------------------------------
#
# The classification guidance must keep ordinary implementation defects on
# the BLOCKERS path (eligible for the one correction cycle) and reserve
# NEEDS_HUMAN for genuine human decisions. Both Codex prompts are defined
# separately (cycle 0 and the re-review), so both are checked. Prompts are
# whitespace-normalized before matching so YAML line wrapping cannot split
# a phrase across lines and silently break these assertions.


def _codex_prompt_text(job: dict) -> str:
    codex_step = next(s for s in job["steps"] if "codex-action" in s.get("uses", ""))
    return " ".join(codex_step["with"]["prompt"].split())


ESCALATION_GUIDANCE_PHRASES = [
    # The explicit tie-breaking instruction, verbatim.
    "When a finding has a clear expected behavior and a bounded technical "
    "correction, classify it as BLOCKERS rather than NEEDS_HUMAN.",
    "NEEDS_HUMAN is not a severity level; it means a human decision is required.",
    # BLOCKER must cover ordinary implementation defects...
    "incorrect behavior, requirement mismatches, missing validation, swallowed "
    "errors, incorrect exit behavior, broken or insufficient tests, unsafe "
    "implementation details, regressions, and documentation that contradicts "
    "implemented behavior",
    # ...and stay BLOCKER regardless of significance.
    "do not escalate them to NEEDS_HUMAN merely because they require code changes",
    # NEEDS_HUMAN is reserved for genuine human decisions.
    "NEEDS_HUMAN is reserved for findings that genuinely require a human decision",
    "product-scope decisions",
    "architecture choices with multiple materially different valid approaches",
    "requested changes to protected governance paths",
]


@pytest.mark.parametrize("phrase", ESCALATION_GUIDANCE_PHRASES)
def test_cycle_0_review_prompt_contains_escalation_guidance(review_job, phrase):
    assert phrase in _codex_prompt_text(review_job)


@pytest.mark.parametrize("phrase", ESCALATION_GUIDANCE_PHRASES)
def test_cycle_1_rereview_prompt_contains_escalation_guidance(rereview_job, phrase):
    assert phrase in _codex_prompt_text(rereview_job)


def test_both_codex_prompts_keep_important_vocabulary_unchanged(review_job, rereview_job):
    # IMPORTANT retains its existing meaning -- the guidance must not have
    # redefined or dropped it in either prompt.
    for job in (review_job, rereview_job):
        assert "IMPORTANT: normally fixed before merge." in _codex_prompt_text(job)


def test_correction_jobs_never_cat_or_echo_the_review_json(correct_job, rereview_job):
    # The review/blocker text flows only through context files written by
    # python (which print counts, never content); no shell step may dump
    # the raw review JSON into the log. The redaction behavior of the
    # routing/validation scripts themselves is unit-tested in
    # tests/test_route_codex_review.py and tests/test_check_codex_review.py.
    combined = _all_run_text(correct_job) + _all_run_text(rereview_job)
    assert 'cat "$REVIEW_PATH"' not in combined
    assert 'cat "$PRIOR_REVIEW_PATH"' not in combined
    assert "codex_review.json' | jq" not in combined
    assert "print(json.dumps" not in combined
