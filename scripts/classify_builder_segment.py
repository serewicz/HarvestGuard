#!/usr/bin/env python3
"""Classify segment continuation from Claude's structured terminal event."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

EXHAUSTED_SUBTYPES = {"error_max_turns"}


def _json_documents(path: Path) -> list[Any]:
    if not path.is_file():
        return []
    text = path.read_text(errors="replace")
    try:
        return [json.loads(text)]
    except json.JSONDecodeError:
        documents = []
        for line in text.splitlines():
            try:
                documents.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return documents


def _terminal_events(value: Any):
    if isinstance(value, dict):
        if value.get("type") == "result" and isinstance(value.get("subtype"), str):
            yield value
        for child in value.values():
            yield from _terminal_events(child)
    elif isinstance(value, list):
        for child in value:
            yield from _terminal_events(child)


def terminal_event(execution_path: Path | None) -> dict[str, Any] | None:
    if execution_path is None:
        return None
    events = [
        event
        for document in _json_documents(execution_path)
        for event in _terminal_events(document)
    ]
    return events[-1] if events else None


def should_continue(conclusion: str, result_path: Path, execution_path: Path | None) -> bool:
    if result_path.is_file():
        try:
            status = json.loads(result_path.read_text()).get("status")
        except (json.JSONDecodeError, OSError, AttributeError):
            status = None
        if status in {"COMPLETE", "NEEDS_HUMAN", "FAILED"}:
            return False
    if conclusion != "failure":
        return False
    event = terminal_event(execution_path)
    return bool(event and event.get("subtype") in EXHAUSTED_SUBTYPES)


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
