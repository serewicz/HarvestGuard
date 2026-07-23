#!/usr/bin/env python3
"""Validate the Codex Principal Reviewer's structured output, in two
distinct stages:

1. check_schema() -- is the output well-formed at all (required fields
   present, correctly typed, status a recognized enum value)? This says
   nothing about whether the review itself is good news.

2. check_ready_to_merge() -- given a well-formed review, is it actually a
   clean, exact-SHA APPROVED verdict? This fails closed: BLOCKERS,
   NEEDS_HUMAN, any non-empty `blockers`, any non-empty `important`, or a
   `reviewed_sha` that doesn't exactly match the expected PR head SHA are
   all treated as "not ready", not merely logged as a mixed result.
   FOLLOW_UP items never block -- they are valid observations that belong
   in separate work, not reasons to hold up this PR.

Exit code 0 requires both stages to pass. This is read-only validation
only -- it never modifies the repository, never comments on or mutates the
PR, and has no merge/approve path. See
.github/workflows/agent-orchestrator.yml's `review` job, which is the only
place this is currently invoked from.

main() intentionally never prints the arbitrary model-generated text in
`blockers`/`important`/`follow_up`/`summary` -- only counts and the status/
SHA. The full text is preserved in the workflow's uploaded review artifact,
not the Actions run log. The same rule applies to *malformed* output:
validation errors name the field and the expected constraint (plus at most
the actual Python type name), never the field's value or repr -- a
malformed field is still model-controlled text, and an error message is
still a log line.
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


def check_schema(review: dict[str, Any]) -> list[str]:
    """Return shape-validity violations; an empty list means the review is
    well-formed. Says nothing about whether the verdict itself is good news
    -- see check_ready_to_merge() for that."""
    missing = [field for field in REQUIRED_FIELDS if field not in review]
    if missing:
        # Every other check below reads these fields -- bail out rather
        # than produce a wall of misleading "missing" noise.
        return [f"Missing required field(s): {', '.join(missing)}"]

    # Failure messages below name only the field, the expected constraint,
    # and at most the actual Python type name -- never the value itself or
    # its repr. Malformed or not, these fields are model-controlled text,
    # and these messages land in the Actions run log.
    failures: list[str] = []

    status = review.get("status")
    if status not in VALID_STATUSES:
        failures.append(
            f"status: must be one of {VALID_STATUSES}, got type {type(status).__name__}"
        )

    reviewed_sha = review.get("reviewed_sha")
    if not isinstance(reviewed_sha, str) or not reviewed_sha.strip():
        failures.append(
            f"reviewed_sha: must be a non-empty string, got type {type(reviewed_sha).__name__}"
        )

    for field in LIST_FIELDS:
        value = review.get(field)
        if not isinstance(value, list):
            failures.append(f"{field}: must be a list of strings, got type {type(value).__name__}")
        elif not all(isinstance(item, str) for item in value):
            bad_types = sorted({type(item).__name__ for item in value if not isinstance(item, str)})
            failures.append(
                f"{field}: must be a list of strings, "
                f"got a list containing non-string type(s): {', '.join(bad_types)}"
            )

    summary = review.get("summary")
    if not isinstance(summary, str) or not summary.strip():
        failures.append(
            f"summary: must be a non-empty string, got type {type(summary).__name__}"
        )

    return failures


def check_ready_to_merge(review: dict[str, Any], expected_sha: str) -> list[str]:
    """Return merge-readiness violations for a review already known to be
    schema-valid. Fails closed: only an exact-SHA APPROVED review with no
    blockers and no important findings counts as ready. BLOCKERS and
    NEEDS_HUMAN are legitimate, well-formed outcomes -- they just aren't
    ready to proceed. FOLLOW_UP items never block."""
    failures: list[str] = []

    # The expected SHA is workflow-controlled (from needs.publish.outputs)
    # and safe to print; the review's own reviewed_sha is model-controlled
    # arbitrary text and is deliberately not echoed back.
    reviewed_sha = review.get("reviewed_sha")
    if reviewed_sha != expected_sha:
        failures.append(
            f"reviewed_sha mismatch: expected {expected_sha!r}, got a value that does not "
            "match -- Codex must review the exact PR head SHA."
        )

    status = review.get("status")
    if status != "APPROVED":
        failures.append(f"status is {status!r}, not APPROVED")

    blockers = review.get("blockers") or []
    if blockers:
        failures.append(f"blockers is non-empty ({len(blockers)} item(s))")

    important = review.get("important") or []
    if important:
        failures.append(f"important is non-empty ({len(important)} item(s))")

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

    schema_failures = check_schema(review)
    if schema_failures:
        print(f"::error::Codex review {path} is not well-formed:")
        for failure in schema_failures:
            print(f"::error::  {failure}")
        return 1

    # Schema is valid from here on. Only concise structured metadata is
    # printed to the run log -- never the arbitrary model-generated text in
    # blockers/important/follow_up/summary. That full text is preserved in
    # the uploaded review artifact instead (see the workflow's "Upload
    # Codex review artifact" step), not the Actions log. status is safe to
    # print here (schema just constrained it to the three known enum
    # values); reviewed_sha is only schema-checked to be a non-empty
    # string, so it's still arbitrary model text unless it matches the
    # workflow-controlled expected SHA -- print it only in that case.
    print(f"Codex review status: {review['status']}")
    if review["reviewed_sha"] == expected_sha:
        print(f"Reviewed SHA: {review['reviewed_sha']}")
    else:
        print("Reviewed SHA: (does not match the expected PR head SHA)")
    print(f"Blockers: {len(review['blockers'])}")
    print(f"Important: {len(review['important'])}")
    print(f"Follow-up: {len(review['follow_up'])}")

    ready_failures = check_ready_to_merge(review, expected_sha)
    if ready_failures:
        print("::error::Codex review is not ready to proceed:")
        for failure in ready_failures:
            print(f"::error::  {failure}")
        return 1

    print("Codex review is APPROVED for the exact PR head SHA with no blockers or important items.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
