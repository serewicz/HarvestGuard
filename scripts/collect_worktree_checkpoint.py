#!/usr/bin/env python3
"""Create a portable, security-checked agent worktree checkpoint."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

from classifier.patterns import SEVERE_CATEGORIES
from scripts.collect_failure_diagnostics import _looks_unsafe

CONFIGURED_SEGMENT_TURNS = 40
EXCLUDED_PARTS = {
    ".git", ".venv", "venv", "env", "node_modules", "__pycache__",
    ".pytest_cache", ".ruff_cache", ".mypy_cache", ".tox", ".nox",
    ".cache", "keychains", "credentials", ".aws", ".config",
}
EXCLUDED_NAMES = {".env", ".env.local", ".env.production", ".netrc", ".npmrc"}
EXTRA_SECRET_CATEGORIES = {
    "sk-" + "ant-", "sk-" + "proj-", "github_" + "pat_",
    "OpenAI API Key", "Google API Key",
    "Azure Storage Account Key", "Azure Storage Connection String",
}


def _git(args: list[str], *, text: bool = False, check: bool = True) -> bytes | str:
    return subprocess.run(
        ["git", *args], check=check, capture_output=True, text=text
    ).stdout


def _nul_paths(raw: bytes) -> list[str]:
    return [part.decode("utf-8", "surrogateescape") for part in raw.split(b"\0") if part]


def _safe_untracked(repo: Path) -> list[tuple[str, Path]]:
    raw = _git(["ls-files", "--others", "--exclude-standard", "-z"])
    assert isinstance(raw, bytes)
    found: list[tuple[str, Path]] = []
    for rel in _nul_paths(raw):
        pure = PurePosixPath(rel)
        if pure.is_absolute() or ".." in pure.parts:
            raise ValueError(f"untracked path escapes repository: {rel!r}")
        if pure.name in EXCLUDED_NAMES or any(part in EXCLUDED_PARTS for part in pure.parts):
            continue
        resolved = (repo / rel).resolve()
        if repo != resolved and repo not in resolved.parents:
            raise ValueError(f"untracked path escapes repository: {rel!r}")
        if resolved.is_symlink() or not resolved.is_file():
            continue
        found.append((rel, resolved))
    return sorted(found, key=lambda item: item[0])


def _copy_optional(source: str | None, destination: Path) -> bool:
    if not source:
        return False
    path = Path(source)
    if not path.is_file():
        return False
    shutil.copyfile(path, destination)
    return True


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def collect(
    job_label: str,
    checkpoint_number: int,
    output_dir: Path,
    session_id: str = "",
    step_conclusion: str = "",
) -> None:
    repo = Path(_git(["rev-parse", "--show-toplevel"], text=True).strip()).resolve()
    output_dir.mkdir(parents=True, exist_ok=False)
    base_sha = os.environ.get("CHECKPOINT_BASE_SHA") or str(
        _git(["merge-base", "HEAD", "origin/main"], text=True).strip()
    )
    head = str(_git(["rev-parse", "HEAD"], text=True).strip())
    branch = str(_git(["branch", "--show-current"], text=True).strip())
    status = _git(["status", "--short", "-z"])
    status_text = _git(["status", "--short"])
    staged = _git(["diff", "--cached", "--binary", "--full-index"])
    unstaged = _git(["diff", "--binary", "--full-index"])
    assert isinstance(status, bytes) and isinstance(status_text, bytes)
    assert isinstance(staged, bytes) and isinstance(unstaged, bytes)
    (output_dir / "git-status-short-z.bin").write_bytes(status)
    (output_dir / "git-status.txt").write_bytes(status_text)
    (output_dir / "staged.patch").write_bytes(staged)
    (output_dir / "unstaged.patch").write_bytes(unstaged)

    manifest: list[dict[str, object]] = []
    untracked = _safe_untracked(repo)
    archive = output_dir / "untracked-files.tar.gz"
    with tarfile.open(archive, "w:gz", format=tarfile.PAX_FORMAT) as bundle:
        for rel, path in untracked:
            manifest.append({"path": rel, "size": path.stat().st_size, "sha256": _sha256(path)})
            bundle.add(path, arcname=rel, recursive=False)
    (output_dir / "untracked-manifest.json").write_text(
        json.dumps({"files": manifest}, ensure_ascii=False, indent=2) + "\n"
    )

    optional = {}
    for env_name, filename in (
        ("CHECKPOINT_BUILDER_RESULT", "builder-result.json"),
        ("CHECKPOINT_BUILDER_STDOUT", "builder-stdout.txt"),
        ("CHECKPOINT_BUILDER_STDERR", "builder-stderr.txt"),
        ("CHECKPOINT_TEST_RESULTS", "test-results.txt"),
        ("CHECKPOINT_CORRECTION_PROMPT", "correction-prompt.json"),
        ("CHECKPOINT_CODEX_BLOCKERS", "codex-blocker-input.json"),
    ):
        optional[filename] = _copy_optional(os.environ.get(env_name), output_dir / filename)

    metadata = {
        "kind": "harvestguard-agent-checkpoint",
        "issue_number": int(os.environ["ISSUE_NUMBER"]) if os.environ.get("ISSUE_NUMBER") else None,
        "repository": os.environ.get("GITHUB_REPOSITORY"),
        "workflow_run_id": os.environ.get("GITHUB_RUN_ID"),
        "workflow_run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
        "job": job_label,
        "checkpoint_number": checkpoint_number,
        "configured_segment_turns": CONFIGURED_SEGMENT_TURNS,
        "base_sha": base_sha,
        "head": head,
        "branch": branch,
        "session_id": session_id or None,
        "step_conclusion": step_conclusion or None,
        "git_status_short": status_text.decode("utf-8", "surrogateescape"),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "untracked_file_count": len(manifest),
        "optional_files": optional,
    }
    (output_dir / "checkpoint-metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
    (output_dir / "RECOVERY.md").write_text(f"""# Agent checkpoint recovery

This checkpoint was recorded from base `{base_sha}` at cumulative turn {checkpoint_number}.

1. Clone HarvestGuard, or fetch all updates in an existing clone.
2. Create a recovery branch at `{base_sha}`: `git switch -c agent-recovery {base_sha}`.
3. Apply staged changes: `git apply --index --binary staged.patch`.
4. Apply unstaged changes: `git apply --binary unstaged.patch`.
5. Restore new files: `tar -xzf untracked-files.tar.gz`.
6. Verify every restored file's size and SHA-256 against `untracked-manifest.json`.
7. Inspect `git status --short` and compare it with `git-status-short-z.bin`.
8. Read the builder result and diagnostics when present, then continue manually
   from the existing work. Do not rerun completed work.
""")
    text_files = [
        path for path in output_dir.iterdir()
        if path.is_file() and path.name not in {"untracked-files.tar.gz", "git-status-short-z.bin"}
    ]
    secret_categories = SEVERE_CATEGORIES | EXTRA_SECRET_CATEGORIES
    risks = {
        path.name: sorted(
            set(_looks_unsafe(path.read_bytes().decode("utf-8", "replace")))
            & secret_categories
        )
        for path in text_files
    }
    risks = {name: matches for name, matches in risks.items() if matches}
    if risks:
        shutil.rmtree(output_dir)
        raise ValueError("checkpoint text failed secret scanning: " + ", ".join(sorted(risks)))
    print(f"Checkpoint {checkpoint_number}: preserved {len(manifest)} untracked file(s).")


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 5:
        print(
            "::error::usage: collect_worktree_checkpoint.py "
            "<job> <40|80> <output-dir> <session-id> <conclusion>"
        )
        return 2
    collect(args[0], int(args[1]), Path(args[2]), args[3], args[4])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
