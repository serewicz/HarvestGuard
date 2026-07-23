#!/usr/bin/env python3
"""Validate that every required HarvestGuard CI check is present, tied to
the exact PR head SHA, complete, and successful.

Reads a JSON array of GitHub check-run objects (as returned by
`GET /repos/{owner}/{repo}/commits/{sha}/check-runs`, filtered down to at
least {name, head_sha, status, conclusion}) and checks it against the
required check names and an expected SHA.

This intentionally does not distinguish "still pending" from "genuinely
failed" -- both are simply not ready. The caller (the `review` job's polling
loop in .github/workflows/agent-orchestrator.yml) re-fetches and re-runs
this on an interval until it succeeds or a bounded timeout elapses, so a
non-zero exit here always just means "not ready yet, keep waiting or give
up" rather than needing its own retry/backoff logic.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Iterable

# Mirrors the matrix-generated check names from .github/workflows/ci.yml's
# `test` job (`name: Test (Python ${{ matrix.python-version }})`) and the
# `required_status_checks.contexts` configured on the `main` branch
# protection rule. Keep this in sync if either changes.
REQUIRED_CHECKS: tuple[str, ...] = (
    "Test (Python 3.10)",
    "Test (Python 3.11)",
    "Test (Python 3.12)",
)

_SUCCESS_CONCLUSION = "success"


def check(
    check_runs: list[dict[str, Any]],
    expected_sha: str,
    required: Iterable[str] = REQUIRED_CHECKS,
) -> list[str]:
    """Return failure reasons; an empty list means every required check
    exists for the exact SHA, has completed, and succeeded."""
    failures: list[str] = []

    for name in required:
        # GitHub's check-runs API returns the most recent run first for a
        # given name, so matches[0] is the current one if a check was
        # re-run.
        matches = [
            run
            for run in check_runs
            if run.get("name") == name and run.get("head_sha") == expected_sha
        ]
        if not matches:
            failures.append(
                f"{name}: no check run found for SHA {expected_sha} "
                "(missing, or only present for a different/stale SHA)"
            )
            continue

        run = matches[0]
        status = run.get("status")
        conclusion = run.get("conclusion")

        if status != "completed":
            failures.append(f"{name}: not complete yet (status={status!r})")
            continue

        if conclusion != _SUCCESS_CONCLUSION:
            failures.append(f"{name}: did not succeed (conclusion={conclusion!r})")

    return failures


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) < 2:
        print("::error::usage: check_required_ci.py <check_runs.json> <expected_sha>")
        return 2

    path, expected_sha = argv[0], argv[1]
    check_runs_path = Path(path)

    if not check_runs_path.is_file():
        print(f"::error::Check-runs file not found: {check_runs_path}")
        return 1

    try:
        content = check_runs_path.read_text()
    except OSError as exc:
        print(f"::error::Unable to read check-runs file {check_runs_path}: {exc}")
        return 1

    try:
        data = json.loads(content) if content.strip() else []
    except json.JSONDecodeError as exc:
        print(f"::error::Check-runs file {check_runs_path} is not valid JSON: {exc}")
        return 1

    if not isinstance(data, list):
        print(f"::error::Check-runs file {check_runs_path} did not parse to a JSON list.")
        return 1

    failures = check(data, expected_sha)
    if failures:
        print(f"Required CI checks not ready for SHA {expected_sha}:")
        for failure in failures:
            print(f"  - {failure}")
        return 1

    print(f"All required CI checks passed for SHA {expected_sha}:")
    for name in REQUIRED_CHECKS:
        print(f"  - {name}: success")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
