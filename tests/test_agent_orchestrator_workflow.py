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


CORRECTION_CYCLES = (1, 2, 3)

CORRECT_IDS = tuple(f"correct_{n}" for n in CORRECTION_CYCLES)
PUBLISH_CORRECTION_IDS = tuple(f"publish_correction_{n}" for n in CORRECTION_CYCLES)
REVIEW_IDS = ("review", "review_1", "review_2", "review_3")

SECRET_EXPR = "${{ secrets.HARVESTGUARD_AUTOMATION_TOKEN }}"
PAT_JOB_IDS = ("publish",) + PUBLISH_CORRECTION_IDS


def _reviewed_sha_expr(n: int) -> str:
    """The exact SHA cycle-n corrections are built against and verified by."""
    if n == 1:
        return "${{ needs.publish.outputs.pr_head_sha }}"
    return "${{ needs.publish_correction_%d.outputs.correction_sha }}" % (n - 1)


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


def test_publish_job_github_token_is_read_only(publish_job):
    # Since the automation PAT became the write path, the job's own
    # GITHUB_TOKEN needs only checkout + PR-number reads.
    assert publish_job["permissions"] == {
        "contents": "read",
        "pull-requests": "read",
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
    # Claude runs in exactly four places -- build and the three correction
    # jobs -- and all hold read-only GitHub tokens. It must never appear in
    # a job with any write scope (publish, publish_correction_*).
    for job_id, job in workflow["jobs"].items():
        has_claude = any("claude-code-action" in u for u in _all_uses(job))
        if job_id == "build" or job_id in CORRECT_IDS:
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


def test_codex_action_runs_only_in_the_read_only_review_jobs(workflow):
    for job_id, job in workflow["jobs"].items():
        has_codex = any("codex-action" in u for u in _all_uses(job))
        if job_id in REVIEW_IDS:
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


# --- Three-cycle correction loop ---------------------------------------------
#
# The correction chain (correct_N -> publish_correction_N -> review_N) now
# exists exactly three times, wired sequentially on the SAME PR. These pin
# the structural properties of every cycle; the behavioral halves (routing
# exit codes, cycle-limit math, log redaction) live in
# tests/test_route_codex_review.py, tests/test_check_codex_review.py, and
# tests/test_check_cycle_limit.py.


def test_the_job_graph_is_exactly_the_twelve_known_jobs(workflow):
    assert set(workflow["jobs"].keys()) == {
        "build",
        "publish",
        "review",
        "correct_1",
        "publish_correction_1",
        "review_1",
        "correct_2",
        "publish_correction_2",
        "review_2",
        "correct_3",
        "publish_correction_3",
        "review_3",
    }


def test_exactly_four_codex_and_four_claude_invocations_exist(workflow):
    all_uses = [u for job in workflow["jobs"].values() for u in _all_uses(job)]
    assert sum("codex-action" in u for u in all_uses) == 4
    assert sum("claude-code-action" in u for u in all_uses) == 4


def test_nothing_depends_on_review_3_so_no_cycle_4_can_exist(workflow):
    for job_id, job in workflow["jobs"].items():
        needs = job.get("needs") or []
        needs = [needs] if isinstance(needs, str) else needs
        assert "review_3" not in needs, f"{job_id} must not chain off the final review"


@pytest.mark.parametrize("n", CORRECTION_CYCLES)
def test_correct_n_runs_only_after_a_blockers_verdict_from_the_prior_review(workflow, n):
    # APPROVED -> review_status is APPROVED -> condition false -> skip.
    # NEEDS_HUMAN/malformed/mismatch -> the review job itself failed ->
    # result != success -> skip. Only a routed BLOCKERS verdict proceeds.
    job = workflow["jobs"][f"correct_{n}"]
    prior_review = "review" if n == 1 else f"review_{n - 1}"
    assert f"needs.{prior_review}.result == 'success'" in job["if"]
    assert f"needs.{prior_review}.outputs.review_status == 'BLOCKERS'" in job["if"]


@pytest.mark.parametrize("n", CORRECTION_CYCLES)
def test_correct_n_permissions_are_read_only(workflow, n):
    assert workflow["jobs"][f"correct_{n}"]["permissions"] == {
        "contents": "read",
        "issues": "read",
        "pull-requests": "read",
    }


@pytest.mark.parametrize("n", CORRECTION_CYCLES)
def test_correct_n_checks_out_the_exact_reviewed_sha_without_credentials(workflow, n):
    job = workflow["jobs"][f"correct_{n}"]
    checkout = next(s for s in job["steps"] if s.get("uses", "").startswith("actions/checkout"))
    assert checkout["with"]["ref"] == _reviewed_sha_expr(n)
    assert checkout["with"]["persist-credentials"] is False


@pytest.mark.parametrize("n", CORRECTION_CYCLES)
def test_correct_n_enforces_its_own_cycle_limit_before_claude_runs(workflow, n):
    job = workflow["jobs"][f"correct_{n}"]
    names = [s.get("name") for s in job["steps"]]
    limit_index = names.index("Enforce correction cycle limit")
    assert f"check_cycle_limit.py .agent-policy.yml {n}" in job["steps"][limit_index]["run"]
    claude_index = next(
        i for i, s in enumerate(job["steps"]) if "claude-code-action" in s.get("uses", "")
    )
    assert limit_index < claude_index


@pytest.mark.parametrize("n", CORRECTION_CYCLES)
def test_correct_n_settings_deny_protected_paths_and_git_mutation(workflow, n):
    job = workflow["jobs"][f"correct_{n}"]
    claude_step = next(s for s in job["steps"] if "claude-code-action" in s.get("uses", ""))
    deny = json.loads(claude_step["with"]["settings"])["permissions"]["deny"]
    assert any(".github/workflows/**" in rule for rule in deny)
    assert any(".agent-policy.yml" in rule for rule in deny)
    assert any("docs/AGENT_CONTRACT.md" in rule for rule in deny)
    for mutating in ("Bash(git add*)", "Bash(git commit*)", "Bash(git push*)", "Bash(gh*)"):
        assert mutating in deny


@pytest.mark.parametrize("n", CORRECTION_CYCLES)
def test_correct_n_gates_its_result_before_producing_the_artifact(workflow, n):
    # A FAILED/NEEDS_HUMAN/violating result fails this step, so the job
    # fails, publish_correction_N's `if:` never fires, nothing is pushed.
    job = workflow["jobs"][f"correct_{n}"]
    names = [s.get("name") for s in job["steps"]]
    check_index = names.index("Stage and check correction result")
    assert "check_builder_result.py" in job["steps"][check_index]["run"]
    assert check_index < names.index("Create correction artifact")


@pytest.mark.parametrize("n", CORRECTION_CYCLES)
def test_correct_n_consumes_the_prior_review_artifact_and_uploads_its_own(workflow, n):
    job = workflow["jobs"][f"correct_{n}"]
    download = next(
        s for s in job["steps"] if s.get("uses", "").startswith("actions/download-artifact")
    )
    assert download["with"]["name"] == f"codex-review-cycle-{n - 1}"
    upload = next(
        s for s in job["steps"] if s.get("uses", "").startswith("actions/upload-artifact")
    )
    assert upload["with"]["name"] == f"claude-correction-cycle-{n}"


@pytest.mark.parametrize("n", CORRECTION_CYCLES)
def test_correct_n_never_pushes_or_touches_gh_pr(workflow, n):
    combined = _all_run_text(workflow["jobs"][f"correct_{n}"])
    assert "git push" not in combined
    assert "git commit" not in combined
    assert "gh pr" not in combined


@pytest.mark.parametrize("n", CORRECTION_CYCLES)
def test_publish_correction_n_runs_only_for_a_complete_correction(workflow, n):
    job = workflow["jobs"][f"publish_correction_{n}"]
    assert f"needs.correct_{n}.result == 'success'" in job["if"]
    assert f"needs.correct_{n}.outputs.status == 'COMPLETE'" in job["if"]


@pytest.mark.parametrize("n", CORRECTION_CYCLES)
def test_publish_correction_n_github_token_is_read_only(workflow, n):
    # The PAT is the write path; the job token only reads for checkout
    # and the ls-remote stale check.
    assert workflow["jobs"][f"publish_correction_{n}"]["permissions"] == {
        "contents": "read",
    }


@pytest.mark.parametrize("job_id", PAT_JOB_IDS)
def test_publish_side_checkouts_do_not_persist_credentials(workflow, job_id):
    job = workflow["jobs"][job_id]
    checkout = next(s for s in job["steps"] if s.get("uses", "").startswith("actions/checkout"))
    assert checkout["with"]["persist-credentials"] is False


@pytest.mark.parametrize("n", CORRECTION_CYCLES)
def test_publish_correction_n_verifies_the_branch_head_before_anything_else(workflow, n):
    # Stale-SHA protection at every cycle: the remote PR branch head must
    # still equal the exact SHA the prior Codex review evaluated.
    job = workflow["jobs"][f"publish_correction_{n}"]
    names = [s.get("name") for s in job["steps"]]
    verify_index = names.index("Verify PR branch head still equals the reviewed SHA")
    verify_step = job["steps"][verify_index]
    assert "git ls-remote origin" in verify_step["run"]
    assert verify_step["env"]["REVIEWED_SHA"] == _reviewed_sha_expr(n)
    assert verify_index < names.index("Apply correction patch")
    assert verify_index < names.index("Commit correction")
    assert verify_index < names.index("Push correction to the PR branch")


@pytest.mark.parametrize("n", CORRECTION_CYCLES)
def test_publish_correction_n_verifies_the_patch_base_sha_and_cycle(workflow, n):
    job = workflow["jobs"][f"publish_correction_{n}"]
    names = [s.get("name") for s in job["steps"]]
    base_index = names.index("Verify correction base SHA and cycle")
    base_step = job["steps"][base_index]
    assert base_step["env"]["REVIEWED_SHA"] == _reviewed_sha_expr(n)
    assert f'"correction_cycle") != {n}:' in base_step["run"]
    assert base_index < names.index("Apply correction patch")


@pytest.mark.parametrize("n", CORRECTION_CYCLES)
def test_publish_correction_n_rechecks_protected_paths_after_applying(workflow, n):
    job = workflow["jobs"][f"publish_correction_{n}"]
    names = [s.get("name") for s in job["steps"]]
    apply_index = names.index("Apply correction patch")
    recheck_index = names.index("Re-check protected governance paths")
    assert apply_index < recheck_index < names.index("Commit correction")
    assert "check_builder_result.py" in _all_run_text(job)


@pytest.mark.parametrize("n", CORRECTION_CYCLES)
def test_publish_correction_n_commits_once_and_pushes_once_plainly(workflow, n):
    job = workflow["jobs"][f"publish_correction_{n}"]
    combined = _all_run_text(job)
    assert combined.count("git commit") == 1
    assert combined.count("git push") == 1
    assert "gh pr create" not in combined


@pytest.mark.parametrize("n", CORRECTION_CYCLES)
def test_review_n_runs_only_after_its_publish_and_checks_out_its_exact_sha(workflow, n):
    job = workflow["jobs"][f"review_{n}"]
    assert job["needs"] == ["publish", f"publish_correction_{n}"]
    assert f"needs.publish_correction_{n}.result == 'success'" in job["if"]
    checkout = next(s for s in job["steps"] if s.get("uses", "").startswith("actions/checkout"))
    assert (
        checkout["with"]["ref"]
        == "${{ needs.publish_correction_%d.outputs.correction_sha }}" % n
    )
    assert checkout["with"]["persist-credentials"] is False


@pytest.mark.parametrize("n", CORRECTION_CYCLES)
def test_review_n_permissions_are_read_only(workflow, n):
    assert workflow["jobs"][f"review_{n}"]["permissions"] == {
        "contents": "read",
        "pull-requests": "read",
        "issues": "read",
    }


@pytest.mark.parametrize("n", CORRECTION_CYCLES)
def test_review_n_gates_on_required_ci_for_its_exact_sha_before_codex(workflow, n):
    # CI failure, or a missing required check, fails this bounded wait ->
    # Codex never runs at this cycle and nothing advances.
    job = workflow["jobs"][f"review_{n}"]
    names = [s.get("name") for s in job["steps"]]
    wait_index = names.index("Wait for required CI checks on the correction SHA")
    wait_step = job["steps"][wait_index]
    assert "check_required_ci.py" in wait_step["run"]
    assert "MAX_WAIT_SECONDS" in wait_step["run"]
    assert (
        wait_step["env"]["PR_HEAD_SHA"]
        == "${{ needs.publish_correction_%d.outputs.correction_sha }}" % n
    )
    codex_index = next(
        i for i, s in enumerate(job["steps"]) if "codex-action" in s.get("uses", "")
    )
    assert wait_index < codex_index


@pytest.mark.parametrize("n", (1, 2))
def test_intermediate_review_n_routes_rather_than_hard_failing(workflow, n):
    # Cycles 1 and 2 use the router (BLOCKERS -> next correction may
    # trigger); only review_3 is the strict terminal gate.
    job = workflow["jobs"][f"review_{n}"]
    names = [s.get("name") for s in job["steps"]]
    route_step = job["steps"][names.index("Route Codex re-review result")]
    assert "route_codex_review.py" in route_step["run"]
    assert route_step["id"] == "route"
    assert job["outputs"]["review_status"] == "${{ steps.route.outputs.status }}"


def test_review_3_is_the_strict_final_gate(workflow):
    job = workflow["jobs"]["review_3"]
    combined = _all_run_text(job)
    assert "check_codex_review.py" in combined
    assert "route_codex_review.py" not in combined
    assert "outputs" not in job or not job.get("outputs")


@pytest.mark.parametrize("n", CORRECTION_CYCLES)
def test_review_n_uploads_its_cycle_artifact_even_on_failure(workflow, n):
    job = workflow["jobs"][f"review_{n}"]
    upload = next(
        s for s in job["steps"] if s.get("uses", "").startswith("actions/upload-artifact")
    )
    assert upload["with"]["name"] == f"codex-review-cycle-{n}"
    assert upload["if"] == "always()"
    assert upload["with"]["if-no-files-found"] == "ignore"


@pytest.mark.parametrize("n", CORRECTION_CYCLES)
def test_review_n_carries_the_prior_blockers_via_artifact_not_logs(workflow, n):
    job = workflow["jobs"][f"review_{n}"]
    download = next(
        s for s in job["steps"] if s.get("uses", "").startswith("actions/download-artifact")
    )
    assert download["with"]["name"] == f"codex-review-cycle-{n - 1}"


def test_gh_pr_create_appears_exactly_once_in_the_whole_workflow(workflow):
    combined = "".join(_all_run_text(job) for job in workflow["jobs"].values())
    assert combined.count("gh pr create") == 1  # publish only -- never a second PR


def test_no_agent_runs_in_a_write_capable_job(workflow):
    # "Write-capable" covers both a write-scoped GITHUB_TOKEN and the
    # automation PAT -- an agent may hold neither.
    for job_id, job in workflow["jobs"].items():
        perms = job.get("permissions", {})
        has_write = any(scope == "write" for scope in perms.values())
        has_write = has_write or "HARVESTGUARD_AUTOMATION_TOKEN" in repr(job)
        runs_agent = any(
            "claude-code-action" in u or "codex-action" in u for u in _all_uses(job)
        )
        assert not (has_write and runs_agent), f"{job_id} runs an agent with write authority"


@pytest.mark.parametrize("job_id", CORRECT_IDS + ("review_1", "review_2", "review_3"))
def test_correction_and_review_jobs_never_cat_or_echo_review_json(workflow, job_id):
    # Review/blocker text flows only through context files written by
    # python (which print counts, never content); no shell step may dump
    # raw review JSON into the log.
    combined = _all_run_text(workflow["jobs"][job_id])
    assert 'cat "$REVIEW_PATH"' not in combined
    assert 'cat "$PRIOR_REVIEW_PATH"' not in combined
    assert "print(json.dumps" not in combined


# --- HARVESTGUARD_AUTOMATION_TOKEN containment -------------------------------
#
# The PAT exists to make agent-branch pushes, draft-PR creation, and
# correction pushes emit real events (GITHUB_TOKEN events deliberately do
# not trigger workflows, which forced a manual "Approve workflows to run"
# click). It must be reachable ONLY by the exact deterministic steps that
# perform those writes -- never by an agent, a log, an artifact, or a
# context file -- and its absence must fail closed, never fall back.

def test_automation_token_appears_only_in_deterministic_publish_jobs(workflow):
    for job_id, job in workflow["jobs"].items():
        referenced = "HARVESTGUARD_AUTOMATION_TOKEN" in repr(job)
        if job_id in PAT_JOB_IDS:
            assert referenced, f"{job_id} should use the automation token"
        else:
            # In particular: never in build, any correct_N (Claude), or
            # any review job (Codex).
            assert not referenced, f"{job_id} must never see the automation token"


def test_automation_token_is_step_scoped_to_exactly_the_write_steps(workflow):
    for job_id in PAT_JOB_IDS:
        job = workflow["jobs"][job_id]
        expected = (
            {"Push implementation branch", "Open draft pull request"}
            if job_id == "publish"
            else {"Push correction to the PR branch"}
        )
        holders = {
            s.get("name")
            for s in job["steps"]
            if "HARVESTGUARD_AUTOMATION_TOKEN" in repr(s)
        }
        assert holders == expected, f"{job_id}: token leaked beyond {expected}: {holders}"


@pytest.mark.parametrize("job_id", PAT_JOB_IDS)
def test_trigger_producing_pushes_use_the_pat_not_github_token(workflow, job_id):
    job = workflow["jobs"][job_id]
    push_name = (
        "Push implementation branch" if job_id == "publish" else "Push correction to the PR branch"
    )
    push_step = next(s for s in job["steps"] if s.get("name") == push_name)
    assert push_step["env"]["AUTOMATION_TOKEN"] == SECRET_EXPR
    # The push goes through an explicit x-access-token URL -- not the
    # `origin` remote, whose persisted credential is GITHUB_TOKEN.
    assert "x-access-token:${AUTOMATION_TOKEN}@github.com" in push_step["run"]
    assert "git push origin" not in push_step["run"]
    # Fail closed when the secret is absent -- no GITHUB_TOKEN fallback.
    assert '-z "${AUTOMATION_TOKEN:-}"' in push_step["run"]
    assert "exit 1" in push_step["run"]


def test_draft_pr_creation_uses_the_pat_not_github_token(workflow):
    steps = workflow["jobs"]["publish"]["steps"]
    step = next(s for s in steps if s.get("name") == "Open draft pull request")
    assert step["env"]["GH_TOKEN"] == SECRET_EXPR
    assert step["env"]["GH_TOKEN"] != "${{ github.token }}"
    assert '-z "${GH_TOKEN:-}"' in step["run"]


def test_automation_token_is_never_echoed(workflow):
    for job in workflow["jobs"].values():
        for step in job["steps"]:
            run = step.get("run", "")
            assert "echo $AUTOMATION_TOKEN" not in run
            assert 'echo "$AUTOMATION_TOKEN' not in run
            assert "echo $GH_TOKEN" not in run
            assert 'echo "$GH_TOKEN' not in run


def test_automation_token_is_not_written_to_artifacts_or_context_files(workflow):
    # No artifact-upload or context/metadata-writing step may reference
    # the secret at all: the only steps that hold it are the push/PR-create
    # steps, which write nothing to disk.
    for job in workflow["jobs"].values():
        for step in job["steps"]:
            if step.get("uses", "").startswith("actions/upload-artifact"):
                assert "HARVESTGUARD_AUTOMATION_TOKEN" not in repr(step)
            name = step.get("name") or ""
            if "context file" in name or "artifact" in name.lower():
                assert "HARVESTGUARD_AUTOMATION_TOKEN" not in repr(step)


# --- Codex escalation criteria ----------------------------------------------
#
# All four Codex prompts (cycle 0 plus the three re-reviews) must keep
# ordinary implementation defects on the BLOCKERS path and reserve
# NEEDS_HUMAN for genuine human decisions. Whitespace-normalized so YAML
# line wrapping cannot split a phrase.


def _codex_prompt_text(job: dict) -> str:
    codex_step = next(s for s in job["steps"] if "codex-action" in s.get("uses", ""))
    return " ".join(codex_step["with"]["prompt"].split())


ESCALATION_GUIDANCE_PHRASES = [
    "When a finding has a clear expected behavior and a bounded technical "
    "correction, classify it as BLOCKERS rather than NEEDS_HUMAN.",
    "NEEDS_HUMAN is not a severity level; it means a human decision is required.",
    "incorrect behavior, requirement mismatches, missing validation, swallowed "
    "errors, incorrect exit behavior, broken or insufficient tests, unsafe "
    "implementation details, regressions, and documentation that contradicts "
    "implemented behavior",
    "do not escalate them to NEEDS_HUMAN merely because they require code changes",
    "NEEDS_HUMAN is reserved for findings that genuinely require a human decision",
    "product-scope decisions",
    "architecture choices with multiple materially different valid approaches",
    "requested changes to protected governance paths",
]


@pytest.mark.parametrize("job_id", REVIEW_IDS)
@pytest.mark.parametrize("phrase", ESCALATION_GUIDANCE_PHRASES)
def test_every_codex_prompt_contains_the_escalation_guidance(workflow, job_id, phrase):
    assert phrase in _codex_prompt_text(workflow["jobs"][job_id])


@pytest.mark.parametrize("job_id", REVIEW_IDS)
def test_every_codex_prompt_keeps_important_vocabulary_unchanged(workflow, job_id):
    assert "IMPORTANT: normally fixed before merge." in _codex_prompt_text(
        workflow["jobs"][job_id]
    )


@pytest.mark.parametrize("job_id", ("review_1", "review_2", "review_3"))
def test_every_rereview_prompt_demands_the_cumulative_pr_at_the_exact_sha(workflow, job_id):
    prompt = _codex_prompt_text(workflow["jobs"][job_id])
    assert "Review the COMPLETE cumulative PR at this exact SHA" in prompt
    assert "git diff origin/main...HEAD" in prompt


@pytest.mark.parametrize("job_id", ("review_1", "review_2"))
def test_intermediate_rereviews_treat_new_bounded_defects_as_correctable(workflow, job_id):
    # Convergence semantics: a defect first noticed at cycle N (different
    # from what cycle N-1 flagged) stays BLOCKERS and routes onward -- it
    # must not be escalated to NEEDS_HUMAN just because it is new.
    prompt = _codex_prompt_text(workflow["jobs"][job_id])
    assert (
        "A newly discovered concrete, bounded defect is a BLOCKER -- it routes "
        "to the next automated correction cycle" in prompt
    )
    assert (
        "convergence over successive bounded corrections on the same PR is "
        "expected behavior, not grounds for NEEDS_HUMAN" in prompt
    )


def test_review_3_prompt_declares_itself_final_with_no_fourth_cycle(workflow):
    prompt = _codex_prompt_text(workflow["jobs"]["review_3"])
    assert "This is the FINAL automated review -- there is no fourth correction cycle." in prompt


# --- Codex review artifact filename convention -------------------------------
#
# Every Codex review artifact carries the SAME internal filename
# (codex_review.json) inside a cycle-specific artifact NAME
# (codex-review-cycle-N). Downstream consumers download artifact N into
# review_cycleN/ and read review_cycleN/codex_review.json -- a mismatch
# here silently breaks the cycle handoff (the cycle-2/3 jobs would fail on
# a missing file), which is exactly the defect this pins against.

REVIEW_ARTIFACT_BASENAME = "codex_review.json"


def test_every_review_cycle_uploads_the_stable_review_basename(workflow):
    for job_id in REVIEW_IDS:
        upload = next(
            s
            for s in workflow["jobs"][job_id]["steps"]
            if s.get("uses", "").startswith("actions/upload-artifact")
        )
        assert upload["with"]["path"].endswith("/" + REVIEW_ARTIFACT_BASENAME), job_id
        # The artifact NAME stays cycle-specific even though the file
        # inside does not.
        cycle = 0 if job_id == "review" else int(job_id.split("_")[1])
        assert upload["with"]["name"] == f"codex-review-cycle-{cycle}"


def test_every_review_producer_writes_the_basename_its_gate_reads(workflow):
    for job_id in REVIEW_IDS:
        job = workflow["jobs"][job_id]
        codex_step = next(s for s in job["steps"] if "codex-action" in s.get("uses", ""))
        gate_step = next(
            s
            for s in job["steps"]
            if "route_codex_review.py" in s.get("run", "")
            or "check_codex_review.py" in s.get("run", "")
        )
        assert codex_step["with"]["output-file"] == gate_step["env"]["RESULT_PATH"], job_id
        assert gate_step["env"]["RESULT_PATH"].endswith("/" + REVIEW_ARTIFACT_BASENAME)


@pytest.mark.parametrize("n", CORRECTION_CYCLES)
def test_cycle_n_consumers_read_exactly_what_the_prior_cycle_uploaded(workflow, n):
    expected = "${{ runner.temp }}/review_cycle%d/%s" % (n - 1, REVIEW_ARTIFACT_BASENAME)
    expected_dir = "${{ runner.temp }}/review_cycle%d" % (n - 1)

    correct = workflow["jobs"][f"correct_{n}"]
    download = next(
        s for s in correct["steps"] if s.get("uses", "").startswith("actions/download-artifact")
    )
    assert download["with"]["path"] == expected_dir
    ctx = next(s for s in correct["steps"] if s.get("name") == "Write correction context file")
    assert ctx["env"]["REVIEW_PATH"] == expected

    review = workflow["jobs"][f"review_{n}"]
    download = next(
        s for s in review["steps"] if s.get("uses", "").startswith("actions/download-artifact")
    )
    assert download["with"]["path"] == expected_dir
    ctx = next(s for s in review["steps"] if s.get("name") == "Write Codex re-review context file")
    assert ctx["env"]["PRIOR_REVIEW_PATH"] == expected
