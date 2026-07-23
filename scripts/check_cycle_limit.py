#!/usr/bin/env python3
"""Enforce the automated-correction cycle limit before a correction runs.

Called by the `correct` job in .github/workflows/agent-orchestrator.yml as:

    python3 scripts/check_cycle_limit.py .agent-policy.yml <cycle_number>

Exit 0 only if the requested correction cycle number is permitted by BOTH:

1. This orchestrator version's hard cap (ORCHESTRATOR_MAX_CORRECTION_CYCLES
   = 3). The workflow's static job graph contains exactly three correction
   chains, so this constant is a belt-and-braces mirror of that structure --
   raising it without also adding the corresponding jobs (and policy
   review) would be meaningless, which is the point: two things have to
   change together, visibly. A cycle number above 3 is rejected here even
   if the policy value were accidentally raised later.

2. `review.max_automated_correction_cycles` in .agent-policy.yml. The
   policy value is the governance ceiling (docs/AGENT_CONTRACT.md allows at
   most 3, raised from 2 with Tim's explicit authorization); if a future
   policy edit lowers it, this gate refuses the excess cycles -- or all
   corrections at 0 -- with no workflow change needed. Every correction
   cycle re-runs this gate independently.

Fails closed on every malformed input: missing/unreadable/invalid policy
file, missing key, boolean-typed or non-integer or negative limit, and any
cycle number below 1.
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

# Mirror of the workflow's static structure: exactly three correction
# chains (correct_N -> publish_correction_N -> review_N, N in 1..3) exist,
# and nothing depends on review_3. See the module docstring for why this
# is deliberately duplicated here.
ORCHESTRATOR_MAX_CORRECTION_CYCLES = 3

POLICY_KEY_PATH = ("review", "max_automated_correction_cycles")


def check(policy: dict, cycle_number: int) -> list[str]:
    """Return violation reasons; an empty list means the cycle may run."""
    failures: list[str] = []

    section = policy.get(POLICY_KEY_PATH[0])
    if not isinstance(section, dict):
        return [f"policy is missing the '{POLICY_KEY_PATH[0]}' section"]

    limit = section.get(POLICY_KEY_PATH[1])
    # bool is a subclass of int -- reject it explicitly so `true` cannot
    # masquerade as the integer 1.
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 0:
        failures.append(
            f"{'.'.join(POLICY_KEY_PATH)} must be a non-negative integer, "
            f"got type {type(limit).__name__}"
        )
        return failures

    if cycle_number < 1:
        failures.append(f"cycle number must be >= 1, got {cycle_number}")

    if cycle_number > ORCHESTRATOR_MAX_CORRECTION_CYCLES:
        failures.append(
            f"cycle {cycle_number} exceeds this orchestrator's hard cap of "
            f"{ORCHESTRATOR_MAX_CORRECTION_CYCLES} automated correction cycle(s)"
        )

    if cycle_number > limit:
        failures.append(
            f"cycle {cycle_number} exceeds the policy limit of {limit} "
            f"({'.'.join(POLICY_KEY_PATH)} in .agent-policy.yml)"
        )

    return failures


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) < 2:
        print("::error::usage: check_cycle_limit.py <policy.yml> <cycle_number>")
        return 2

    policy_path = Path(argv[0])
    try:
        cycle_number = int(argv[1])
    except ValueError:
        print(f"::error::cycle_number must be an integer, got: {argv[1]}")
        return 2

    if not policy_path.is_file():
        print(f"::error::Policy file not found: {policy_path}")
        return 1

    try:
        policy = yaml.safe_load(policy_path.read_text())
    except (OSError, yaml.YAMLError) as exc:
        print(f"::error::Unable to load policy file {policy_path}: {exc}")
        return 1

    if not isinstance(policy, dict):
        print(f"::error::Policy file {policy_path} did not parse to a mapping.")
        return 1

    failures = check(policy, cycle_number)
    if failures:
        print(f"::error::Correction cycle {cycle_number} is not permitted:")
        for failure in failures:
            print(f"::error::  {failure}")
        return 1

    limit = policy[POLICY_KEY_PATH[0]][POLICY_KEY_PATH[1]]
    print(
        f"Correction cycle {cycle_number} permitted "
        f"(policy limit {limit}, orchestrator cap {ORCHESTRATOR_MAX_CORRECTION_CYCLES})."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
