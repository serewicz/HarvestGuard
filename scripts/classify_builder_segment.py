#!/usr/bin/env python3
"""Classify whether a failed first Claude segment exhausted its turn budget."""

from __future__ import annotations

import json
import sys
from pathlib import Path

TURN_MARKERS = ("reached max turns", "max turns reached", "max_turns")


def should_continue(conclusion: str, result_path: Path, execution_path: Path | None) -> bool:
    if result_path.is_file():
        try:
            status = json.loads(result_path.read_text()).get("status")
        except (json.JSONDecodeError, OSError, AttributeError):
            status = None
        if status in {"COMPLETE", "NEEDS_HUMAN", "FAILED"}:
            return False
    if conclusion != "failure" or execution_path is None or not execution_path.is_file():
        return False
    text = execution_path.read_text(errors="replace").lower()
    return any(marker in text for marker in TURN_MARKERS)


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 3:
        print("::error::usage: classify_builder_segment.py <conclusion> <result> <execution>")
        return 2
    run_segment_2 = should_continue(args[0], Path(args[1]), Path(args[2]) if args[2] else None)
    print("true" if run_segment_2 else "false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
