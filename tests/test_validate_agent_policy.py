"""Tests for scripts/validate_agent_policy.py, the machine-checkable
enforcement of docs/AGENT_CONTRACT.md's hard invariants.
"""

from __future__ import annotations

import copy

import pytest

from scripts.validate_agent_policy import (
    REQUIRED_TOP_LEVEL_KEYS,
    PolicyError,
    load_policy,
    main,
    validate,
)


def _valid_policy() -> dict:
    return {
        "version": 1,
        "authority": {
            "merge_to_main": "human_only",
            "product_boundary_changes": "human_only",
            "architecture_changes": "human_only",
            "security_tradeoffs": "human_only",
            "workflow_changes": "human_only",
            "secrets_changes": "human_only",
            "repository_settings_changes": "human_only",
            "destructive_operations": "human_only",
        },
        "agents": {
            "builder": {
                "provider": "claude",
                "role": "builder",
                "repository_write": "feature_branch_only",
                "max_fix_cycles": 2,
            },
            "reviewer": {
                "provider": "codex",
                "role": "principal_reviewer",
                "repository_write": False,
                "max_review_cycles": 2,
            },
            "security_reviewer": {
                "provider": "grok",
                "role": "ciso_qa",
                "repository_write": False,
                "max_review_cycles": 1,
            },
        },
        "security": {
            "allow_customer_data_to_external_models": False,
            "allow_raw_scan_results_to_external_models": False,
            "allow_agents_to_manage_credentials": False,
            "log_secret_values": False,
        },
        "review": {
            "require_exact_pr_sha": True,
            "require_ci_green": True,
            "require_principal_review": True,
            "max_automated_correction_cycles": 3,
            "security_review_required_paths": ["scanner/**"],
        },
        "cost": {
            "enforce_cycle_limits": True,
            "require_human_on_budget_exhaustion": True,
            "track_usage": True,
        },
        "merge": {
            "automatic": False,
            "human_approval_required": True,
        },
    }


def _set(policy: dict, dotted_path: str, value) -> dict:
    node = policy
    keys = dotted_path.split(".")
    for key in keys[:-1]:
        node = node[key]
    node[keys[-1]] = value
    return policy


# 1. valid policy passes
def test_valid_policy_passes():
    assert validate(_valid_policy()) == []


# 2. missing policy file fails
def test_missing_policy_file_fails(tmp_path):
    with pytest.raises(PolicyError, match="not found"):
        load_policy(tmp_path / "does-not-exist.yml")

    assert main([str(tmp_path / "does-not-exist.yml")]) == 1


# 3. malformed YAML fails
def test_malformed_yaml_fails(tmp_path):
    bad = tmp_path / "bad.yml"
    bad.write_text("merge:\n  automatic: false\n  human_approval_required: [true\n")

    with pytest.raises(PolicyError, match="not valid YAML"):
        load_policy(bad)

    assert main([str(bad)]) == 1


# 4. each required top-level key missing fails
@pytest.mark.parametrize("missing_key", REQUIRED_TOP_LEVEL_KEYS)
def test_each_required_top_level_key_missing_fails(missing_key):
    policy = _valid_policy()
    del policy[missing_key]

    failures = validate(policy)

    assert failures
    assert missing_key in failures[0]


# 5. merge.automatic=true fails
def test_merge_automatic_true_fails():
    policy = _set(_valid_policy(), "merge.automatic", True)
    failures = validate(policy)
    assert any("merge.automatic" in f for f in failures)


# 6. human merge approval=false fails
def test_merge_human_approval_required_false_fails():
    policy = _set(_valid_policy(), "merge.human_approval_required", False)
    failures = validate(policy)
    assert any("merge.human_approval_required" in f for f in failures)


# 7. workflow_changes != human_only fails
def test_authority_workflow_changes_not_human_only_fails():
    policy = _set(_valid_policy(), "authority.workflow_changes", "agent_allowed")
    failures = validate(policy)
    assert any("authority.workflow_changes" in f for f in failures)


# 8. secrets_changes != human_only fails
def test_authority_secrets_changes_not_human_only_fails():
    policy = _set(_valid_policy(), "authority.secrets_changes", "agent_allowed")
    failures = validate(policy)
    assert any("authority.secrets_changes" in f for f in failures)


# 9. agent credential management=true fails
def test_allow_agents_to_manage_credentials_true_fails():
    policy = _set(_valid_policy(), "security.allow_agents_to_manage_credentials", True)
    failures = validate(policy)
    assert any("allow_agents_to_manage_credentials" in f for f in failures)


# 10. customer data external-model permission=true fails
def test_allow_customer_data_to_external_models_true_fails():
    policy = _set(_valid_policy(), "security.allow_customer_data_to_external_models", True)
    failures = validate(policy)
    assert any("allow_customer_data_to_external_models" in f for f in failures)


# 11. raw scan external-model permission=true fails
def test_allow_raw_scan_results_to_external_models_true_fails():
    policy = _set(_valid_policy(), "security.allow_raw_scan_results_to_external_models", True)
    failures = validate(policy)
    assert any("allow_raw_scan_results_to_external_models" in f for f in failures)


# 12. exact PR SHA=false fails
def test_require_exact_pr_sha_false_fails():
    policy = _set(_valid_policy(), "review.require_exact_pr_sha", False)
    failures = validate(policy)
    assert any("require_exact_pr_sha" in f for f in failures)


# 13. correction cycles >2 fails
def test_max_automated_correction_cycles_above_three_fails():
    policy = _set(_valid_policy(), "review.max_automated_correction_cycles", 4)
    failures = validate(policy)
    assert any("max_automated_correction_cycles" in f for f in failures)


def test_max_automated_correction_cycles_non_integer_fails():
    policy = _set(_valid_policy(), "review.max_automated_correction_cycles", "2")
    failures = validate(policy)
    assert any("max_automated_correction_cycles" in f for f in failures)


def test_max_automated_correction_cycles_bool_fails():
    # bool is a subclass of int in Python; True must not be accepted as 1.
    policy = _set(_valid_policy(), "review.max_automated_correction_cycles", True)
    failures = validate(policy)
    assert any("max_automated_correction_cycles" in f for f in failures)


# 14. reviewer repository_write=true fails
def test_reviewer_repository_write_true_fails():
    policy = _set(_valid_policy(), "agents.reviewer.repository_write", True)
    failures = validate(policy)
    assert any("agents.reviewer.repository_write" in f for f in failures)


# 15. security reviewer repository_write=true fails
def test_security_reviewer_repository_write_true_fails():
    policy = _set(_valid_policy(), "agents.security_reviewer.repository_write", True)
    failures = validate(policy)
    assert any("agents.security_reviewer.repository_write" in f for f in failures)


# Additional coverage: log_secret_values, require_ci_green,
# require_principal_review, cost invariants, builder write scope, missing
# role, and the real repo policy file end to end.
def test_log_secret_values_true_fails():
    policy = _set(_valid_policy(), "security.log_secret_values", True)
    assert any("log_secret_values" in f for f in validate(policy))


def test_require_ci_green_false_fails():
    policy = _set(_valid_policy(), "review.require_ci_green", False)
    assert any("require_ci_green" in f for f in validate(policy))


def test_require_principal_review_false_fails():
    policy = _set(_valid_policy(), "review.require_principal_review", False)
    assert any("require_principal_review" in f for f in validate(policy))


def test_cost_enforce_cycle_limits_false_fails():
    policy = _set(_valid_policy(), "cost.enforce_cycle_limits", False)
    assert any("cost.enforce_cycle_limits" in f for f in validate(policy))


def test_cost_require_human_on_budget_exhaustion_false_fails():
    policy = _set(_valid_policy(), "cost.require_human_on_budget_exhaustion", False)
    assert any("require_human_on_budget_exhaustion" in f for f in validate(policy))


def test_builder_repository_write_not_feature_branch_only_fails():
    policy = _set(_valid_policy(), "agents.builder.repository_write", "main")
    assert any("agents.builder.repository_write" in f for f in validate(policy))


def test_missing_agent_role_fails():
    policy = _valid_policy()
    del policy["agents"]["security_reviewer"]
    failures = validate(policy)
    assert any("security_reviewer" in f for f in failures)


def test_main_prints_summary_on_success(tmp_path, capsys):
    import yaml

    policy_path = tmp_path / "policy.yml"
    policy_path.write_text(yaml.safe_dump(_valid_policy()))

    rc = main([str(policy_path)])

    assert rc == 0
    out = capsys.readouterr().out
    assert "Agent policy valid" in out
    assert "merge.automatic: False" in out


def test_main_fails_clearly_without_traceback(tmp_path, capsys):
    import yaml

    policy = _set(_valid_policy(), "merge.automatic", True)
    policy_path = tmp_path / "policy.yml"
    policy_path.write_text(yaml.safe_dump(policy))

    rc = main([str(policy_path)])

    out = capsys.readouterr().out
    assert rc == 1
    assert "::error::" in out
    assert "merge.automatic" in out


def test_real_repo_policy_file_is_valid():
    policy = load_policy(".agent-policy.yml")
    assert validate(policy) == []


def test_validate_does_not_mutate_input():
    policy = _valid_policy()
    snapshot = copy.deepcopy(policy)
    validate(policy)
    assert policy == snapshot
