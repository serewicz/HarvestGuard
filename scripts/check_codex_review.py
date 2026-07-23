#!/usr/bin/env python3
"""Validate the Codex Principal Reviewer's structured output.

Reads the review JSON Codex wrote (path given as argv[1]) and checks it
against the expected PR head SHA (given as argv[2]). Exit code 0 means the
review is well-formed AND actually reviewed the exact commit the workflow
checked out -- both matter: a well-formed review of the wrong commit is as
useless as a malformed one, so `reviewed_sha` mismatching the expected SHA
is treated as a hard failure, not a warning.

This is read-only validation only -- it never modifies the repository,
never comments on or mutates the PR, and has no merge/approve path. See
.github/workflows/agent-orchestrator.yml's `review` job, which is the only
place this is currently invoked from.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

VALID_STATUSES = ("APPROVED", "BLOCKERS", "NEEDS_HUMAN")
REQUIRED_FIELDS = ("status", "reviewed_sha", "blockers", "important", "follow_up", "summary")
LIST_FIELDS = ("blockers", "important", "follow_up")


class ReviewError(Exception):
    """The review output file itself could not be loaded (missing, empty, or not valid JSON)."""


def load_review(path: str | Path) -> dict[str, Any]:
    review_path = Path(path)
    if not review_path.is_file():
        raise ReviewError(f"Codex review output file not found: {review_path}")

    try:
        content = review_path.read_text()
    except OSError as exc:
        raise ReviewError(f"Unable to read Codex review output {review_path}: {exc}") from exc

    if not content.strip():
        raise ReviewError(f"Codex review output {review_path} is empty.")

    try:
        review = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ReviewError(f"Codex review output {review_path} is not valid JSON: {exc}") from exc

    if not isinstance(review, dict):
        raise ReviewError(f"Codex review output {review_path} did not parse to a JSON object.")

    return review


def check(review: dict[str, Any], expected_sha: str) -> list[str]:
    """Return violation reasons; an empty list means the review is valid and
    reviewed the expected commit."""
    missing = [field for field in REQUIRED_FIELDS if field not in review]
    if missing:
        # Every other check below reads these fields -- bail out rather
        # than produce a wall of misleading "missing" noise.
        return [f"Missing required field(s): {', '.join(missing)}"]

    failures: list[str] = []

    status = review.get("status")
    if status not in VALID_STATUSES:
        failures.append(f"status: expected one of {VALID_STATUSES}, got {status!r}")

    reviewed_sha = review.get("reviewed_sha")
    if reviewed_sha != expected_sha:
        failures.append(
            f"reviewed_sha mismatch: expected {expected_sha!r}, got {reviewed_sha!r} -- "
            "Codex must review the exact PR head SHA."
        )

    for field in LIST_FIELDS:
        value = review.get(field)
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            failures.append(f"{field}: expected a list of strings, got {value!r}")

    summary = review.get("summary")
    if not isinstance(summary, str) or not summary.strip():
        failures.append("summary: expected a non-empty string")

    return failures


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) < 2:
        print("::error::usage: check_codex_review.py <review.json> <expected_sha>")
        return 2

    path, expected_sha = argv[0], argv[1]

    try:
        review = load_review(path)
    except ReviewError as exc:
        print(f"::error::{exc}")
        return 1

    failures = check(review, expected_sha)
    if failures:
        print(f"::error::Codex review {path} failed validation:")
        for failure in failures:
            print(f"::error::  {failure}")
        return 1

    print(f"Codex review valid: {path}")
    print(f"  status: {review['status']}")
    print(f"  reviewed_sha: {review['reviewed_sha']}")
    print(f"  blockers ({len(review['blockers'])}):")
    for item in review["blockers"]:
        print(f"    - {item}")
    print(f"  important ({len(review['important'])}):")
    for item in review["important"]:
        print(f"    - {item}")
    print(f"  follow_up ({len(review['follow_up'])}):")
    for item in review["follow_up"]:
        print(f"    - {item}")
    print(f"  summary: {review['summary']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
