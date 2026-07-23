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


def test_orchestrator_cap_is_exactly_one():
    # The workflow's static job graph contains exactly one correction
    # chain; this constant must mirror that. See the script's docstring.
    assert ORCHESTRATOR_MAX_CORRECTION_CYCLES == 1


def test_cycle_1_within_policy_limit_passes():
    assert check(_policy(1), 1) == []
    assert check(_policy(2), 1) == []


def test_cycle_2_fails_even_when_policy_allows_2():
    # The policy ceiling is 2 (per docs/AGENT_CONTRACT.md), but this
    # orchestrator version only implements one cycle -- the hard cap must
    # refuse cycle 2 regardless of policy headroom.
    reasons = check(_policy(2), 2)
    assert reasons
    assert any("hard cap" in r for r in reasons)


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


def test_main_fails_for_cycle_2(tmp_path, capsys):
    path = _write_policy(tmp_path, 2)
    rc = main([str(path), "2"])
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


def test_real_repo_policy_permits_exactly_cycle_1():
    # The committed policy (max_automated_correction_cycles: 2, the
    # contract ceiling) must allow the one cycle this workflow implements
    # -- and the hard cap must still refuse a second one.
    policy = yaml.safe_load((REPO_ROOT / ".agent-policy.yml").read_text())
    assert check(policy, 1) == []
    assert check(policy, 2)
