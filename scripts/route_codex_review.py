#!/usr/bin/env python3
"""Route the cycle-0 Codex Principal Review to one of three outcomes.

scripts/check_codex_review.py is the strict gate: it exits non-zero for
anything except a clean exact-SHA APPROVED. That remains the right behavior
for the FINAL review of a run (see the `rereview` job), but the first
review now has a third legitimate outcome: a well-formed BLOCKERS verdict
routes to exactly one automated Claude correction cycle instead of ending
the workflow. This script implements that routing decision for the
`review` job in .github/workflows/agent-orchestrator.yml:

  exit 0, status output "APPROVED"  -- clean exact-SHA APPROVED with no
      blockers and no important findings. No correction runs (the
      downstream jobs' `if:` conditions see the status output and skip).

  exit 0, status output "BLOCKERS"  -- schema-valid, exact-SHA-matching
      BLOCKERS verdict with at least one blocker. The job stays green so
      the `correct` job's `if:` condition can trigger the one permitted
      correction cycle.

  exit 1 (job fails, nothing downstream runs) -- everything else:
      malformed output, reviewed_sha mismatch, NEEDS_HUMAN, an APPROVED
      verdict contradicted by non-empty blockers/important, or a BLOCKERS
      verdict with an empty blocker list. All of these need a human.

Same log-redaction contract as check_codex_review.py: only counts, status,
and the workflow-controlled expected SHA are ever printed -- never the
model-generated text in blockers/important/follow_up/summary, well-formed
or not.
"""

from __future__ import annotations

import os
import sys

try:
    # Executed as a script (python3 scripts/route_codex_review.py) -- the
    # scripts/ directory itself is sys.path[0].
    from check_codex_review import ReviewError, check_ready_to_merge, check_schema, load_review
except ImportError:
    # Imported as a module from the repo root (pytest).
    from scripts.check_codex_review import (
        ReviewError,
        check_ready_to_merge,
        check_schema,
        load_review,
    )


def _write_outputs(status: str, review: dict) -> None:
    """Append the routing decision to $GITHUB_OUTPUT when running inside
    GitHub Actions; a no-op elsewhere (tests set the variable explicitly)."""
    output_path = os.environ.get("GITHUB_OUTPUT")
    if not output_path:
        return
    with open(output_path, "a") as f:
        f.write(f"status={status}\n")
        f.write(f"blockers_count={len(review['blockers'])}\n")
        f.write(f"important_count={len(review['important'])}\n")
        f.write(f"follow_up_count={len(review['follow_up'])}\n")


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) < 2:
        print("::error::usage: route_codex_review.py <review.json> <expected_sha>")
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

    # Metadata-only logging, same contract as check_codex_review.py.
    print(f"Codex review status: {review['status']}")
    if review["reviewed_sha"] == expected_sha:
        print(f"Reviewed SHA: {review['reviewed_sha']}")
    else:
        print("Reviewed SHA: (does not match the expected PR head SHA)")
    print(f"Blockers: {len(review['blockers'])}")
    print(f"Important: {len(review['important'])}")
    print(f"Follow-up: {len(review['follow_up'])}")

    if review["reviewed_sha"] != expected_sha:
        # A mismatched SHA disqualifies every outcome, including the
        # correction route -- a correction built against a review of the
        # wrong commit would be fixing the wrong thing.
        print(
            f"::error::reviewed_sha mismatch: expected {expected_sha!r}, got a value "
            "that does not match -- not routing anywhere."
        )
        return 1

    _write_outputs(review["status"], review)

    if not check_ready_to_merge(review, expected_sha):
        print("Route: APPROVED -- no correction cycle needed.")
        return 0

    if review["status"] == "BLOCKERS" and review["blockers"]:
        print(
            f"Route: BLOCKERS ({len(review['blockers'])} blocker(s)) -- eligible for "
            "the single automated correction cycle."
        )
        return 0

    print("::error::Codex review requires a human -- not eligible for automated correction:")
    print(f"::error::  status is {review['status']!r} with {len(review['blockers'])} blocker(s) ")
    print(f"::error::  and {len(review['important'])} important finding(s).")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
