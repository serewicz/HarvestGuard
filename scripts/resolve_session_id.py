#!/usr/bin/env python3
"""Resolve the Claude Code session id needed to safely `--resume` a segment.

Prefers `anthropics/claude-code-action@v1`'s own `session_id` output when it
is present. That output has been observed empty/null after a segment ends
with `error_max_turns` (see the turn-40 checkpoint from workflow run
31514961738, issue #100: `steps.claude_1.outputs.session_id` was empty even
though the action's own execution result recorded a real session id). When
the action output is absent, this falls back to extracting the session id
from the terminal `result` event in the action's `execution_file` output --
the same sanitized event `scripts/classify_builder_segment.py` already
parses for the segment-continuation decision.

Prints the resolved session id (nothing else) to stdout when a valid one is
found, and prints nothing when it is not. Callers MUST treat empty stdout as
"no valid session id" and fail closed before using it for `--resume` --
`claude --resume ""` fails immediately with "--resume requires a valid
session ID or session title when used with --print", so an empty value must
never reach that flag.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any

# Invoked as `python3 scripts/resolve_session_id.py` (repo root not on
# sys.path[0] in that form, unlike pytest) as well as imported in tests via
# `from scripts.resolve_session_id import ...`. Add the repo root explicitly
# so `scripts.classify_builder_segment` resolves in both contexts, mirroring
# scripts/collect_failure_diagnostics.py's existing sys.path handling.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from scripts.classify_builder_segment import terminal_event  # noqa: E402

# Claude Code session ids are UUIDs in practice; this is deliberately a
# little looser (opaque token shape, no embedded whitespace) rather than a
# strict UUID match, so a future non-UUID session identifier isn't rejected
# outright -- the goal here is only to reject empty/blank/whitespace-mangled
# values, not to re-validate the action's own id format.
_SESSION_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$")


def _valid(candidate: Any) -> str | None:
    if not isinstance(candidate, str):
        return None
    stripped = candidate.strip()
    if not stripped or not _SESSION_ID_RE.match(stripped):
        return None
    return stripped


def resolve(action_session_id: str, execution_path: Path | None) -> str | None:
    """Prefer the action's own output; fall back to the sanitized execution
    result only when that output is absent."""
    direct = _valid(action_session_id)
    if direct:
        return direct
    event = terminal_event(execution_path)
    if event is None:
        return None
    return _valid(event.get("session_id"))


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 2:
        print(
            "::error::usage: resolve_session_id.py <action-session-id> <execution-file>",
            file=sys.stderr,
        )
        return 2
    action_session_id, execution_file = args
    resolved = resolve(action_session_id, Path(execution_file) if execution_file else None)
    if resolved:
        print(resolved)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
