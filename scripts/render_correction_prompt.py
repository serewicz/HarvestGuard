#!/usr/bin/env python3
"""Render the single correction prompt used by Claude and recovery."""

from __future__ import annotations

import sys
from pathlib import Path

TEMPLATE_PATH = Path(__file__).with_name("correction_prompt.txt")


def render(cycle: int, context_path: str) -> str:
    if cycle not in {1, 2, 3}:
        raise ValueError("correction cycle must be 1, 2, or 3")
    return (
        TEMPLATE_PATH.read_text()
        .replace("__CYCLE__", str(cycle))
        .replace("__CONTEXT_PATH__", context_path)
    )


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 3:
        print("::error::usage: render_correction_prompt.py <cycle> <context-path> <output-path>")
        return 2
    Path(args[2]).write_text(render(int(args[0]), args[1]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
