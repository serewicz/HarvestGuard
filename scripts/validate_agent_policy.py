#!/usr/bin/env python3
"""Validate HarvestGuard's agent governance policy (.agent-policy.yml).

This is the machine-checkable subset of docs/AGENT_CONTRACT.md. Exit code 0
means the policy file exists, parses as YAML, has every required top-level
section, and satisfies every hard invariant below. Used both standalone and
from .github/workflows/agent-orchestrator.yml, which must not proceed to
issue retrieval, any future AI invocation, or any repository mutation if
this fails.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import yaml

DEFAULT_POLICY_PATH = ".agent-policy.yml"

REQUIRED_TOP_LEVEL_KEYS = (
    "version",
    "authority",
    "agents",
    "security",
    "review",
    "cost",
    "merge",
)

REQUIRED_AGENT_ROLES = ("builder", "reviewer", "security_reviewer")


class PolicyError(Exception):
    """The policy file itself could not be loaded (missing, unreadable, or not valid YAML)."""


def load_policy(path: str | Path) -> dict[str, Any]:
    """Read and parse the policy file. Raises PolicyError on any failure."""
    policy_path = Path(path)
    if not policy_path.is_file():
        raise PolicyError(f"Policy file not found: {policy_path}")

    try:
        content = policy_path.read_text()
    except OSError as exc:
        raise PolicyError(f"Unable to read policy file {policy_path}: {exc}") from exc

    try:
        policy = yaml.safe_load(content)
    except yaml.YAMLError as exc:
        raise PolicyError(f"Policy file {policy_path} is not valid YAML: {exc}") from exc

    if not isinstance(policy, dict):
        raise PolicyError(f"Policy file {policy_path} did not parse to a mapping.")

    return policy


def _get(policy: dict[str, Any], dotted_path: str) -> Any:
    node: Any = policy
    for key in dotted_path.split("."):
        if not isinstance(node, dict) or key not in node:
            return None
        node = node[key]
    return node


def _is_strict_int(value: Any) -> bool:
    # bool is a subclass of int in Python; True/False must not pass here.
    return isinstance(value, int) and not isinstance(value, bool)


def _matches(actual: Any, expected: Any) -> bool:
    """Compare a policy value against its required value.

    Booleans are compared by identity (True/False are singletons in
    Python), not just equality -- otherwise a value like 1 would silently
    satisfy an `expected=True` check (1 == True in Python). Everything else
    (e.g. the "human_only"/"feature_branch_only" string checks) is compared
    by value: two equal strings loaded from different places are not
    guaranteed to be the same object, so `is` would be wrong there.
    """
    if isinstance(expected, bool):
        return actual is expected
    return actual == expected


def validate(policy: dict[str, Any]) -> list[str]:
    """Return violation messages; an empty list means the policy is valid."""
    missing_keys = sorted(key for key in REQUIRED_TOP_LEVEL_KEYS if key not in policy)
    if missing_keys:
        # Every check below reads through these sections -- bail out here
        # rather than produce a wall of misleading "got None" noise.
        return [f"Missing required top-level key(s): {', '.join(missing_keys)}"]

    failures: list[str] = []

    # Hard invariants from docs/AGENT_CONTRACT.md. merge.automatic is
    # checked unconditionally, in the same pass as every other invariant --
    # no combination of other settings can skip or override it.
    checks: list[tuple[str, Any, Any]] = [
        ("merge.automatic", _get(policy, "merge.automatic"), False),
        ("merge.human_approval_required", _get(policy, "merge.human_approval_required"), True),
        ("authority.workflow_changes", _get(policy, "authority.workflow_changes"), "human_only"),
        ("authority.secrets_changes", _get(policy, "authority.secrets_changes"), "human_only"),
        (
            "security.allow_agents_to_manage_credentials",
            _get(policy, "security.allow_agents_to_manage_credentials"),
            False,
        ),
        (
            "security.allow_customer_data_to_external_models",
            _get(policy, "security.allow_customer_data_to_external_models"),
            False,
        ),
        (
            "security.allow_raw_scan_results_to_external_models",
            _get(policy, "security.allow_raw_scan_results_to_external_models"),
            False,
        ),
        ("security.log_secret_values", _get(policy, "security.log_secret_values"), False),
        ("review.require_exact_pr_sha", _get(policy, "review.require_exact_pr_sha"), True),
        ("review.require_ci_green", _get(policy, "review.require_ci_green"), True),
        (
            "review.require_principal_review",
            _get(policy, "review.require_principal_review"),
            True,
        ),
        ("cost.enforce_cycle_limits", _get(policy, "cost.enforce_cycle_limits"), True),
        (
            "cost.require_human_on_budget_exhaustion",
            _get(policy, "cost.require_human_on_budget_exhaustion"),
            True,
        ),
        (
            "agents.builder.repository_write",
            _get(policy, "agents.builder.repository_write"),
            "feature_branch_only",
        ),
        (
            "agents.reviewer.repository_write",
            _get(policy, "agents.reviewer.repository_write"),
            False,
        ),
        (
            "agents.security_reviewer.repository_write",
            _get(policy, "agents.security_reviewer.repository_write"),
            False,
        ),
    ]

    for path, actual, expected in checks:
        if not _matches(actual, expected):
            failures.append(f"{path}: expected {expected!r}, got {actual!r}")

    missing_roles = [
        role
        for role in REQUIRED_AGENT_ROLES
        if not isinstance(_get(policy, f"agents.{role}"), dict)
    ]
    if missing_roles:
        failures.append(f"Missing required agent role(s): {', '.join(missing_roles)}")

    # Ceiling raised from 2 to 3 with Tim's explicit authorization (the
    # orchestrator's three-cycle correction loop; see docs/AGENT_CONTRACT.md
    # "Cost governance", updated in the same change).
    cycles = _get(policy, "review.max_automated_correction_cycles")
    if not _is_strict_int(cycles) or cycles > 3:
        failures.append(
            f"review.max_automated_correction_cycles: expected an integer <= 3, got {cycles!r}"
        )

    return failures


def _summary(policy: dict[str, Any]) -> str:
    configured_roles = ", ".join(
        role for role in REQUIRED_AGENT_ROLES if isinstance(_get(policy, f"agents.{role}"), dict)
    )
    lines = [
        f"  version: {policy.get('version')!r}",
        f"  agents: {configured_roles}",
        f"  merge.automatic: {_get(policy, 'merge.automatic')!r}",
        f"  merge.human_approval_required: {_get(policy, 'merge.human_approval_required')!r}",
        "  review.max_automated_correction_cycles: "
        f"{_get(policy, 'review.max_automated_correction_cycles')!r}",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    path = argv[0] if argv else DEFAULT_POLICY_PATH

    try:
        policy = load_policy(path)
    except PolicyError as exc:
        print(f"::error::{exc}")
        return 1

    failures = validate(policy)
    if failures:
        print(f"::error::Agent policy {path} failed validation:")
        for failure in failures:
            print(f"::error::  {failure}")
        return 1

    print(f"Agent policy valid: {path}")
    print(_summary(policy))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
