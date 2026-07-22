#!/usr/bin/env python3
"""Gate the Agent Orchestrator's builder step.

Decides whether the Claude builder's self-reported structured result is
safe to commit, validate, and open a draft PR for. Reads the builder's
result JSON (path given as argv[1]) and a list of changed file paths (one
per line on stdin, e.g. piped from `git diff --name-only`).

Exit code 0 means proceed (status is COMPLETE, no scope expansion was
flagged, and no changed file falls under a protected governance path).
Any other outcome -- NEEDS_HUMAN, FAILED, malformed/missing result,
unrecognized status, or a protected path in the diff -- exits nonzero with a
clear reason and must stop the workflow before any commit/push/PR step
runs.

The protected-path check here is defense-in-depth, not the primary control.
The primary control is Claude Code's own tool-permission configuration (the
`settings` passed to anthropics/claude-code-action in
.github/workflows/agent-orchestrator.yml), which denies Edit/Write on these
same paths at the tool layer -- this check should be unreachable in
practice, and its firing indicates something upstream didn't work as
configured.
"""

from __future__ import annotations

import fnmatch
import json
import sys
from pathlib import Path
from typing import Any

# Mirrors docs/AGENT_CONTRACT.md's "Important workflow-change boundary":
# the builder must never modify the workflow that governs it, the policy it
# is validated against, or the contract itself. "Repository-security
# configuration" (the fourth protected category in the contract) has no
# single file target -- it's enforced by the builder simply never having
# `gh`/git-push/administration capability at all, not by a path glob.
PROTECTED_PATH_GLOBS = (
    ".github/workflows/*",
    ".agent-policy.yml",
    "docs/AGENT_CONTRACT.md",
)

VALID_STATUSES = ("COMPLETE", "NEEDS_HUMAN", "FAILED")


class ResultError(Exception):
    """The result file itself could not be loaded (missing or not valid JSON)."""


def load_result(path: str | Path) -> dict[str, Any]:
    result_path = Path(path)
    if not result_path.is_file():
        raise ResultError(f"Builder result file not found: {result_path}")

    try:
        data = json.loads(result_path.read_text())
    except json.JSONDecodeError as exc:
        raise ResultError(f"Builder result file is not valid JSON: {exc}") from exc

    if not isinstance(data, dict):
        raise ResultError("Builder result file did not parse to a JSON object.")

    return data


def find_protected_matches(changed_files: list[str]) -> list[str]:
    matches = []
    for raw in changed_files:
        path = raw.strip()
        if not path:
            continue
        if any(fnmatch.fnmatch(path, pattern) for pattern in PROTECTED_PATH_GLOBS):
            matches.append(path)
    return matches


def check(result: dict[str, Any], changed_files: list[str]) -> list[str]:
    """Return reasons to stop; an empty list means it's safe to proceed."""
    status = result.get("status")
    if status not in VALID_STATUSES:
        return [f"status: expected one of {VALID_STATUSES}, got {status!r}"]

    if status == "NEEDS_HUMAN":
        return [f"Builder returned NEEDS_HUMAN: {result.get('summary', '(no summary provided)')}"]

    if status == "FAILED":
        return [f"Builder returned FAILED: {result.get('summary', '(no summary provided)')}"]

    # status == "COMPLETE" from here.
    reasons: list[str] = []

    if result.get("scope_expansion_requested"):
        reasons.append(
            "Builder flagged scope_expansion_requested even though it reported "
            "COMPLETE -- treating this as NEEDS_HUMAN. Scope expansion requires "
            "human approval (see docs/AGENT_CONTRACT.md)."
        )

    protected_hits = find_protected_matches(changed_files)
    if protected_hits:
        reasons.append(
            "SECURITY: changed files include protected governance path(s) the "
            "builder must never modify: " + ", ".join(sorted(protected_hits))
        )

    return reasons


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if not argv:
        print("::error::usage: check_builder_result.py <result.json> < changed_files.txt")
        return 2

    try:
        result = load_result(argv[0])
    except ResultError as exc:
        print(f"::error::{exc}")
        return 1

    changed_files = sys.stdin.read().splitlines()

    reasons = check(result, changed_files)
    if reasons:
        print("::error::Builder run did not pass -- stopping before commit/push/PR:")
        for reason in reasons:
            print(f"::error::  {reason}")
        return 1

    print("Builder result OK: status=COMPLETE, no scope expansion, no protected paths touched.")
    print(f"  summary: {result.get('summary', '(none)')}")
    limitations = result.get("known_limitations") or []
    if limitations:
        print("  known_limitations:")
        for item in limitations:
            print(f"    - {item}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
