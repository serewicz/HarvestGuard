"""Tests for scripts/check_cycle_limit.py, the gate that enforces the
automated-correction cycle limit from .agent-policy.yml (plus this
orchestrator version's hard cap of 1) before the `correct` job runs Claude.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from scripts.check_cycle_limit import ORCHESTRATOR_MAX_CORRECTION_CYCLES, check, main

REPO_ROOT = Path(__file__).parent.parent


def _policy(limit) -> dict:
    return {"review": {"max_automated_correction_cycles": limit}}


def _write_policy(tmp_path, limit) -> Path:
    path = tmp_path / "policy.yml"
    path.write_text(yaml.safe_dump(_policy(limit)))
    return path


def test_orchestrator_cap_is_exactly_three():
    # The workflow's static job graph contains exactly three correction
    # chains; this constant must mirror that. See the script's docstring.
    assert ORCHESTRATOR_MAX_CORRECTION_CYCLES == 3


def test_cycles_1_through_3_within_policy_limit_pass():
    for cycle in (1, 2, 3):
        assert check(_policy(3), cycle) == []


def test_cycle_4_fails_under_the_policy_limit_too():
    reasons = check(_policy(3), 4)
    assert reasons
    assert any("hard cap" in r for r in reasons)
    assert any("policy limit" in r for r in reasons)


def test_cycle_4_fails_via_hard_cap_even_if_policy_is_accidentally_raised():
    # check() itself doesn't re-validate the policy ceiling (that's
    # validate_agent_policy.py's job) -- so even a wildly permissive value
    # must not unlock a fourth cycle here.
    reasons = check(_policy(99), 4)
    assert reasons
    assert any("hard cap" in r for r in reasons)


def test_policy_below_requested_cycle_rejects():
    reasons = check(_policy(1), 2)
    assert reasons
    assert any("policy limit" in r for r in reasons)


def test_policy_limit_0_refuses_cycle_1():
    reasons = check(_policy(0), 1)
    assert reasons
    assert any("policy limit" in r for r in reasons)


def test_cycle_0_is_rejected():
    reasons = check(_policy(1), 0)
    assert reasons
    assert any(">= 1" in r for r in reasons)


def test_missing_review_section_fails_closed():
    assert check({}, 1)


def test_missing_limit_key_fails_closed():
    assert check({"review": {}}, 1)


def test_boolean_limit_fails_closed():
    # bool is a subclass of int; `true` must not masquerade as 1.
    reasons = check(_policy(True), 1)
    assert reasons
    assert any("bool" in r for r in reasons)


def test_non_integer_limit_fails_closed():
    assert check(_policy("2"), 1)
    assert check(_policy(1.5), 1)


def test_negative_limit_fails_closed():
    assert check(_policy(-1), 1)


def test_main_passes_for_valid_policy_and_cycle_1(tmp_path, capsys):
    path = _write_policy(tmp_path, 1)
    rc = main([str(path), "1"])
    assert rc == 0
    assert "permitted" in capsys.readouterr().out


def test_main_fails_for_cycle_4(tmp_path, capsys):
    path = _write_policy(tmp_path, 3)
    rc = main([str(path), "4"])
    assert rc == 1
    assert "::error::" in capsys.readouterr().out


def test_main_fails_for_missing_policy_file(tmp_path, capsys):
    rc = main([str(tmp_path / "nope.yml"), "1"])
    assert rc == 1
    assert "not found" in capsys.readouterr().out


def test_main_fails_for_malformed_yaml(tmp_path, capsys):
    path = tmp_path / "policy.yml"
    path.write_text("review: [unclosed")
    rc = main([str(path), "1"])
    assert rc == 1


def test_main_fails_for_non_mapping_policy(tmp_path, capsys):
    path = tmp_path / "policy.yml"
    path.write_text("- just\n- a\n- list\n")
    rc = main([str(path), "1"])
    assert rc == 1


def test_main_rejects_non_integer_cycle_argument(tmp_path, capsys):
    path = _write_policy(tmp_path, 1)
    rc = main([str(path), "one"])
    assert rc == 2


def test_main_requires_two_arguments(capsys):
    rc = main([])
    assert rc == 2
    assert "usage" in capsys.readouterr().out


def test_real_repo_policy_permits_cycles_1_through_3_and_no_more():
    # The committed policy (max_automated_correction_cycles: 3, the
    # contract ceiling) must allow exactly the three cycles this workflow
    # implements -- and both caps must refuse a fourth.
    policy = yaml.safe_load((REPO_ROOT / ".agent-policy.yml").read_text())
    for cycle in (1, 2, 3):
        assert check(policy, cycle) == []
    assert check(policy, 4)
