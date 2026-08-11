#!/usr/bin/env python3
"""Create a portable, security-checked agent worktree checkpoint."""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

CONFIGURED_SEGMENT_TURNS = 40
EXCLUDED_PARTS = {
    ".git", ".venv", "venv", "env", "node_modules", "__pycache__",
    ".pytest_cache", ".ruff_cache", ".mypy_cache", ".tox", ".nox",
    ".cache", "keychains", "keychain", "credentials", ".aws", ".azure",
    ".config", ".ssh", ".gnupg", ".kube", ".docker", ".claude", ".codex",
    "auth-cache", "authentication-cache",
}
EXCLUDED_EXACT_NAMES = {
    ".env", ".netrc", ".npmrc", "auth.json", "credentials.json",
    "application_default_credentials.json", "adc.json", "service_account.json",
    "access_tokens.db", "credentials.db", "keychain.db", "login.keychain-db",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "identity",
    ".pypirc", ".git-credentials", ".gitconfig", ".boto", "azureprofile.json",
    "accesstokens.json", "tokencache.dat", "clouds.yaml", "kubeconfig",
}
EXCLUDED_NAME_PATTERNS = (
    ".env.*", "credential*.json", "token*.json", "secrets*.json",
    "service-account*.json", "service_account*.json", "*-credentials.json",
    "msal_token_cache*",
)
SECRET_PATTERNS = (
    re.compile(rb"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    # Requires a real base64-shaped body of meaningful length after the PEM
    # header, not just the header text alone. Every other pattern in this
    # tuple already requires a genuine random-looking suffix (16-36+ chars)
    # before it counts as credential-shaped; the bare header alone does
    # not, and this repository's own established test convention (see
    # tests/test_classifier.py's PRIVATE_KEY_RE fixture, which quotes the
    # same header with only a short truncated "MIIBOgIBAAJBAK..." example
    # body) legitimately writes that header without real key material to
    # test HarvestGuard's own secret-detection logic. A real PEM key always
    # has a substantial base64-encoded body -- even the shortest common key
    # type comfortably exceeds 40 characters -- so this keeps genuine key
    # material excluded while no longer flagging a bare header mention.
    re.compile(
        rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"
        rb"\s*(?:[A-Za-z0-9+/=]\s*){40,}"
    ),
    re.compile(rb"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(rb"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(rb"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(rb"\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}\b"),
    re.compile(rb"\bAIza[0-9A-Za-z_-]{20,}\b"),
    re.compile(rb"AccountKey=[A-Za-z0-9+/=]{20,}"),
)
TERMINAL_DIAGNOSTIC_FIELDS = (
    "type", "subtype", "is_error", "duration_ms", "duration_api_ms",
    "num_turns", "session_id", "total_cost_usd", "usage",
)
VERIFY_SCRIPT = '''#!/usr/bin/env python3
import hashlib
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
manifest = json.loads(pathlib.Path("untracked-manifest.json").read_text())
for item in manifest["files"]:
    path = (root / item["path"]).resolve()
    if root != path and root not in path.parents:
        raise SystemExit(f"unsafe manifest path: {item['path']!r}")
    data = path.read_bytes()
    if len(data) != item["size"]:
        raise SystemExit(f"size mismatch: {item['path']}")
    if hashlib.sha256(data).hexdigest() != item["sha256"]:
        raise SystemExit(f"SHA-256 mismatch: {item['path']}")
print(f"verified {len(manifest['files'])} restored untracked file(s)")
'''


def _git(args: list[str], *, text: bool = False) -> bytes | str:
    return subprocess.run(["git", *args], check=True, capture_output=True, text=text).stdout


def _nul_paths(raw: bytes) -> list[str]:
    return [part.decode("utf-8", "surrogateescape") for part in raw.split(b"\0") if part]


def _approved_fixture(path: PurePosixPath) -> bool:
    return bool(path.parts and path.parts[0] == "tests" and "fixtures" in path.parts[:-1])


def _path_exclusion(path: PurePosixPath) -> str | None:
    if _approved_fixture(path):
        return None
    lowered_parts = tuple(part.lower() for part in path.parts)
    name = lowered_parts[-1]
    if any(part in EXCLUDED_PARTS for part in lowered_parts):
        return "authentication, dependency, environment, or cache path"
    if name in EXCLUDED_EXACT_NAMES:
        return "credential or authentication filename"
    if any(fnmatch.fnmatchcase(name, pattern) for pattern in EXCLUDED_NAME_PATTERNS):
        return "credential or environment filename pattern"
    return None


def _contains_secret(data: bytes) -> bool:
    return any(pattern.search(data) for pattern in SECRET_PATTERNS)


def _safe_untracked(repo: Path) -> tuple[list[tuple[str, Path]], list[dict[str, str]]]:
    raw = _git(["ls-files", "--others", "--exclude-standard", "-z"])
    assert isinstance(raw, bytes)
    included: list[tuple[str, Path]] = []
    excluded: list[dict[str, str]] = []
    for rel in _nul_paths(raw):
        pure = PurePosixPath(rel)
        if pure.is_absolute() or ".." in pure.parts:
            raise ValueError(f"untracked path escapes repository: {rel!r}")
        resolved = (repo / rel).resolve()
        if repo != resolved and repo not in resolved.parents:
            raise ValueError(f"untracked path escapes repository: {rel!r}")
        reason = _path_exclusion(pure)
        if reason:
            excluded.append({"path": rel, "reason": reason})
            continue
        if resolved.is_symlink() or not resolved.is_file():
            excluded.append({"path": rel, "reason": "symlink or non-regular file"})
            continue
        if not _approved_fixture(pure) and _contains_secret(resolved.read_bytes()):
            excluded.append({"path": rel, "reason": "credential-shaped content"})
            continue
        included.append((rel, resolved))
    return sorted(included), sorted(excluded, key=lambda item: item["path"])


def _copy_optional(source: str | None, destination: Path) -> bool:
    if not source or not Path(source).is_file():
        return False
    shutil.copyfile(source, destination)
    return True


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _walk_terminal_events(value: Any):
    if isinstance(value, dict):
        if value.get("type") == "result" and isinstance(value.get("subtype"), str):
            yield value
        for child in value.values():
            yield from _walk_terminal_events(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_terminal_events(child)


def _structured_documents(path: Path) -> list[Any]:
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


def _write_execution_diagnostics(source: str | None, destination: Path) -> bool:
    if not source or not Path(source).is_file():
        return False
    events = [
        event
        for document in _structured_documents(Path(source))
        for event in _walk_terminal_events(document)
    ]
    if not events:
        return False
    terminal = events[-1]
    sanitized = {key: terminal[key] for key in TERMINAL_DIAGNOSTIC_FIELDS if key in terminal}
    destination.write_text(json.dumps(sanitized, indent=2) + "\n")
    return True


def _write_test_summary(result_path: str | None, destination: Path) -> bool:
    if not result_path or not Path(result_path).is_file():
        return False
    try:
        result = json.loads(Path(result_path).read_text())
    except (json.JSONDecodeError, OSError):
        return False
    validation = result.get("validation")
    if not isinstance(validation, dict):
        return False
    destination.write_text(json.dumps({"validation": validation}, indent=2) + "\n")
    return True


def _secret_risks(path: Path) -> bool:
    return _contains_secret(path.read_bytes())


def collect(
    job_label: str,
    checkpoint_number: int,
    output_dir: Path,
    session_id: str = "",
    step_conclusion: str = "",
) -> None:
    repo = Path(str(_git(["rev-parse", "--show-toplevel"], text=True)).strip()).resolve()
    head = str(_git(["rev-parse", "HEAD"], text=True)).strip()
    configured_base = os.environ.get("CHECKPOINT_BASE_SHA")
    if job_label.startswith("correct_") and not configured_base:
        raise ValueError("correction checkpoints require CHECKPOINT_BASE_SHA")
    base_sha = configured_base or head
    output_dir.mkdir(parents=True, exist_ok=False)
    branch = os.environ.get("CHECKPOINT_BRANCH") or str(
        _git(["branch", "--show-current"], text=True)
    ).strip()
    status = _git(["status", "--short", "-z"])
    status_text = _git(["status", "--short"])
    staged = _git(["diff", "--cached", "--binary", "--full-index"])
    unstaged = _git(["diff", "--binary", "--full-index"])
    assert all(isinstance(item, bytes) for item in (status, status_text, staged, unstaged))
    (output_dir / "git-status-short-z.bin").write_bytes(status)
    (output_dir / "git-status.txt").write_bytes(status_text)
    (output_dir / "staged.patch").write_bytes(staged)
    (output_dir / "unstaged.patch").write_bytes(unstaged)

    untracked, excluded = _safe_untracked(repo)
    manifest = []
    with tarfile.open(
        output_dir / "untracked-files.tar.gz", "w:gz", format=tarfile.PAX_FORMAT
    ) as bundle:
        for rel, path in untracked:
            manifest.append({"path": rel, "size": path.stat().st_size, "sha256": _sha256(path)})
            bundle.add(path, arcname=rel, recursive=False)
    (output_dir / "untracked-manifest.json").write_text(
        json.dumps({"files": manifest}, ensure_ascii=False, indent=2) + "\n"
    )
    (output_dir / "excluded-untracked.json").write_text(
        json.dumps({"excluded": excluded}, ensure_ascii=False, indent=2) + "\n"
    )
    (output_dir / "verify-untracked.py").write_text(VERIFY_SCRIPT)

    result_path = os.environ.get("CHECKPOINT_BUILDER_RESULT")
    optional = {
        "builder-result.json": _copy_optional(result_path, output_dir / "builder-result.json"),
        "builder-execution-diagnostics.json": _write_execution_diagnostics(
            os.environ.get("CHECKPOINT_EXECUTION_FILE"),
            output_dir / "builder-execution-diagnostics.json",
        ),
        "test-results.json": _write_test_summary(result_path, output_dir / "test-results.json"),
        "correction-prompt.txt": _copy_optional(
            os.environ.get("CHECKPOINT_CORRECTION_PROMPT"), output_dir / "correction-prompt.txt"
        ),
        "codex-blocker-input.json": _copy_optional(
            os.environ.get("CHECKPOINT_CODEX_BLOCKERS"), output_dir / "codex-blocker-input.json"
        ),
    }
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
        "excluded_untracked_count": len(excluded),
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
6. Verify every restored size and SHA-256: `python3 verify-untracked.py /path/to/checkout`.
7. Inspect `git status --short` and compare it with `git-status.txt`.
8. Read the builder result and sanitized diagnostics when present, then continue
   manually from the existing work. Do not rerun completed work.
""")
    text_files = [
        path for path in output_dir.iterdir()
        if path.is_file() and path.name not in {"untracked-files.tar.gz", "git-status-short-z.bin"}
    ]
    risks = [path.name for path in text_files if _secret_risks(path)]
    if risks:
        shutil.rmtree(output_dir)
        raise ValueError("checkpoint text failed secret scanning: " + ", ".join(sorted(risks)))
    print(
        f"Checkpoint {checkpoint_number}: preserved {len(manifest)} untracked file(s); "
        f"excluded {len(excluded)} unsafe path(s)."
    )


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
