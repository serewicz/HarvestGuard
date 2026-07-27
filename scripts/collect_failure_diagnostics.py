#!/usr/bin/env python3
"""Collect safe, sanitized diagnostics after a Claude Code action step fails
(most commonly: the max-turns limit was reached).

Called by the `build`/`correct_1`/`correct_2`/`correct_3` jobs in
.github/workflows/agent-orchestrator.yml as:

    python3 scripts/collect_failure_diagnostics.py \\
        <job_label> <output_dir> <session_id> <step_conclusion>

Writes, to <output_dir>:

- metadata.json -- safe metadata only: job label, failed step name, Claude
  Code session id (an opaque identifier, not a credential -- see the
  action's own `session_id` output), the step's reported conclusion, the
  configured turn limit, and a UTC timestamp.
- git_status.txt / git_diff.txt -- the working tree's uncommitted state at
  the moment of failure, so a human can see exactly how far the builder got
  without re-running it.

This never captures environment variables, the Claude action's own
execution-output JSON (which is not proven safe to expose -- see the module
docstring's design note below), or any repository secret. It never prints
file contents to stdout; only short, count-based confirmation lines.

Design note on the execution-output JSON: `anthropics/claude-code-action@v1`
exposes an `execution_file` output pointing at Claude Code's own transcript,
and the action's own docs carry an explicit security warning about secret
exposure for its `show_full_output` input. Nothing here parses or uploads
that file -- only the metadata fields listed above, taken from the action's
already-public `session_id` output and this workflow's own known
configuration (job label, turn limit), are captured. This is a deliberate
fail-closed choice: safe sanitization of an arbitrary model transcript
cannot be guaranteed from a workflow step, so it is not attempted.

Before writing git_status.txt/git_diff.txt, both are scanned with
HarvestGuard's own production sensitive-data classifier
(classifier.scanner.classify_text -- AWS keys, GitHub tokens, Slack tokens,
private-key headers, generic secrets), a small set of literal high-risk
API-key prefixes, and a few additional credential shapes the production
classifier does not cover (contextual OpenAI-style `sk-...` keys, Google
`AIza...` API keys, and Azure Storage account keys/connection strings --
see `_EXTRA_PATTERNS` below). If ANYTHING matches, both files are replaced
in full with a redaction notice -- never partially masked, never a mix of
real and redacted content -- the metadata.json is still written either
way, so a human always has a way to identify which run to investigate
manually.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

# Invoked as `python3 scripts/collect_failure_diagnostics.py` (see the
# workflow), which puts scripts/ rather than the repo root on sys.path[0] --
# unlike pytest, which adds the repo root automatically. Add it explicitly
# so `classifier` (a repo-root package) is importable either way.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from classifier.scanner import classify_text  # noqa: E402

# Static, matches the workflow's `--max-turns` configuration. Not read from
# the environment or the execution-output file -- this script never opens
# that file.
CONFIGURED_MAX_TURNS = 80

# Literal API-key-shaped prefixes not covered by classifier.scanner's
# service-credential patterns (which cover AWS/GitHub-classic/Slack/private
# keys). Belt-and-suspenders only: Claude's tool permissions never expose
# real secret values to its own file-editing context, so a match here would
# be unexpected, but the check is cheap and the cost of a false positive
# (falling back to metadata-only) is low.
_EXTRA_RISK_PREFIXES = ("sk-ant-", "sk-proj-", "github_pat_")

# Additional credential shapes not covered by classifier.scanner or the
# plain-prefix list above (see the module docstring). Each entry is
# (category name shown in the redaction notice, compiled pattern).
#
# - Legacy/bare OpenAI key (`sk-<20+ alnum>`): the bare `sk-` prefix alone
#   is too generic to scan for on its own, so this only matches when an
#   "api key"/"openai"-shaped label appears within 40 characters either
#   side of it -- e.g. `OPENAI_API_KEY="sk-..."` or `api_key = "sk-..."`.
# - Google API key: the well-known `AIza` prefix, long enough to not be
#   coincidental.
# - Azure Storage Account key: `AccountKey=<20+ base64-ish chars>`, which
#   matches both a bare AccountKey assignment and one embedded inside a
#   full `DefaultEndpointsProtocol=...;AccountKey=...;...` connection
#   string (the connection string always contains this same substring).
# - Azure Storage connection string: the same AccountKey material preceded
#   (within a bounded distance, real connection strings put AccountName
#   between the two) by `DefaultEndpointsProtocol=` -- named separately so
#   the redaction notice calls out the full connection-string shape
#   specifically, not only the embedded key.
_EXTRA_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "OpenAI API Key",
        re.compile(
            r"(?:api[_-]?key|openai)[^\n]{0,40}sk-[A-Za-z0-9]{20,}"
            r"|sk-[A-Za-z0-9]{20,}[^\n]{0,40}(?:api[_-]?key|openai)",
            re.IGNORECASE,
        ),
    ),
    ("Google API Key", re.compile(r"\bAIza[0-9A-Za-z_-]{20,}\b")),
    ("Azure Storage Account Key", re.compile(r"AccountKey=[A-Za-z0-9+/=]{20,}")),
    (
        "Azure Storage Connection String",
        re.compile(
            r"DefaultEndpointsProtocol=.{0,100}AccountKey=[A-Za-z0-9+/=]{10,}",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
)

# Bound the diff artifact's size regardless of repository state.
_MAX_DIFF_BYTES = 200_000


def _run_git(args: list[str]) -> str:
    result = subprocess.run(
        ["git", *args], capture_output=True, text=True, check=False
    )
    return result.stdout


def _looks_unsafe(text: str) -> list[str]:
    """Return category names found; an empty list means the text looks safe
    to write out verbatim."""
    categories = set(classify_text(text))
    categories.update(prefix for prefix in _EXTRA_RISK_PREFIXES if prefix in text)
    categories.update(name for name, pattern in _EXTRA_PATTERNS if pattern.search(text))
    return sorted(categories)


def collect(job_label: str, output_dir: Path, session_id: str, step_conclusion: str) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)

    status_text = _run_git(["status", "--porcelain"])
    diff_text = _run_git(["diff"])[:_MAX_DIFF_BYTES]

    risk_categories = _looks_unsafe(status_text + "\n" + diff_text)

    if risk_categories:
        redaction_note = (
            "Working-tree status/diff withheld: automated scanning "
            f"matched {', '.join(risk_categories)}-shaped content, so it was "
            "not safe to include verbatim in this diagnostics artifact. "
            "See metadata.json for the session id to investigate manually "
            "(e.g. via `claude --resume <session_id>` locally, if you have "
            "access to the underlying session)."
        )
        (output_dir / "git_status.txt").write_text(redaction_note + "\n")
        (output_dir / "git_diff.txt").write_text(redaction_note + "\n")
        print(f"Diagnostics: working-tree content redacted ({len(risk_categories)} categories).")
    else:
        (output_dir / "git_status.txt").write_text(status_text)
        (output_dir / "git_diff.txt").write_text(diff_text)
        print(
            f"Diagnostics: wrote git_status.txt ({len(status_text)} chars), "
            f"git_diff.txt ({len(diff_text)} chars)."
        )

    failed_step = (
        "Run Claude Code builder" if job_label == "build" else "Run Claude Code correction"
    )
    metadata = {
        "job": job_label,
        "failed_step": failed_step,
        "session_id": session_id or None,
        "step_conclusion": step_conclusion,
        "configured_max_turns": CONFIGURED_MAX_TURNS,
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "content_redacted": bool(risk_categories),
    }
    (output_dir / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
    print(f"Diagnostics: wrote metadata.json for job={job_label!r} conclusion={step_conclusion!r}.")


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) < 4:
        print(
            "::error::usage: collect_failure_diagnostics.py "
            "<job_label> <output_dir> <session_id> <step_conclusion>"
        )
        return 2

    job_label, output_dir, session_id, step_conclusion = argv[0], Path(argv[1]), argv[2], argv[3]
    collect(job_label, output_dir, session_id, step_conclusion)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
