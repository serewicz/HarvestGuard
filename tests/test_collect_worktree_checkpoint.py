"""Recovery, direct-invocation, and safety tests for agent checkpoints."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

import scripts.collect_worktree_checkpoint as checkpoint

SCRIPT = Path(checkpoint.__file__).resolve()


def git(repo: Path, *args: str):
    return subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True)


def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    git(root, "init", "-b", "main")
    git(root, "config", "user.name", "Test")
    git(root, "config", "user.email", "test.invalid")
    (root / "tracked.txt").write_text("base\n")
    git(root, "add", "tracked.txt")
    git(root, "commit", "-m", "base")
    return root


def extract_untracked(checkpoint_dir: Path, destination: Path) -> None:
    with tarfile.open(checkpoint_dir / "untracked-files.tar.gz") as bundle:
        bundle.extractall(destination, filter="data")


def test_complete_checkpoint_round_trip_and_executable_verification(tmp_path, monkeypatch):
    root = repo(tmp_path)
    (root / "tracked.txt").write_text("staged\n")
    git(root, "add", "tracked.txt")
    (root / "tracked.txt").write_text("unstaged\n")
    files = {
        "new text.txt": b"hello\n",
        "tests/fixtures/nested/blob.bin": b"\x00\xfffixture\n",
        "unicodé/雪.txt": b"snow\n",
        "--leading-dash": b"dash\n",
    }
    for rel, data in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    monkeypatch.chdir(root)
    out = tmp_path / "checkpoint"
    checkpoint.collect("build", 40, out, "session", "failure")

    manifest = json.loads((out / "untracked-manifest.json").read_text())["files"]
    assert {item["path"] for item in manifest} == set(files)
    for item in manifest:
        assert item["size"] == len(files[item["path"]])
        assert item["sha256"] == hashlib.sha256(files[item["path"]]).hexdigest()

    restored = tmp_path / "restored"
    git(root, "clone", str(root), str(restored))
    subprocess.run(
        ["git", "apply", "--index", "--binary", str(out / "staged.patch")],
        cwd=restored,
        check=True,
    )
    subprocess.run(
        ["git", "apply", "--binary", str(out / "unstaged.patch")],
        cwd=restored,
        check=True,
    )
    extract_untracked(out, restored)
    verified = subprocess.run(
        [sys.executable, "verify-untracked.py", str(restored)],
        cwd=out,
        check=True,
        capture_output=True,
        text=True,
    )
    assert "verified 4 restored" in verified.stdout
    assert "staged" in git(restored, "diff", "--cached").stdout
    assert "unstaged" in git(restored, "diff").stdout


def test_exact_workflow_cli_invocation_creates_checkpoint(tmp_path):
    root = repo(tmp_path)
    scripts = root / "scripts"
    scripts.mkdir()
    shutil.copyfile(SCRIPT, scripts / SCRIPT.name)
    out = tmp_path / "cli-checkpoint"
    result = subprocess.run(
        [
            "python3",
            "scripts/collect_worktree_checkpoint.py",
            "build",
            "40",
            str(out),
            "s",
            "success",
        ],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    assert "Checkpoint 40" in result.stdout
    assert (out / "checkpoint-metadata.json").is_file()
    assert (out / "untracked-files.tar.gz").is_file()


def test_correction_restores_from_explicit_reviewed_head(tmp_path, monkeypatch):
    root = repo(tmp_path)
    base_a = git(root, "rev-parse", "HEAD").stdout.strip()
    (root / "implementation.txt").write_text("implementation B\n")
    git(root, "add", "implementation.txt")
    git(root, "commit", "-m", "implementation B")
    reviewed_b = git(root, "rev-parse", "HEAD").stdout.strip()
    assert reviewed_b != base_a
    (root / "implementation.txt").write_text("staged correction C\n")
    git(root, "add", "implementation.txt")
    (root / "implementation.txt").write_text("unstaged correction C\n")
    (root / "new-correction.txt").write_text("untracked correction C\n")
    monkeypatch.chdir(root)
    monkeypatch.setenv("CHECKPOINT_BASE_SHA", reviewed_b)
    out = tmp_path / "correction-checkpoint"
    checkpoint.collect("correct_1", 80, out)
    metadata = json.loads((out / "checkpoint-metadata.json").read_text())
    assert metadata["base_sha"] == reviewed_b
    assert reviewed_b in (out / "RECOVERY.md").read_text()

    restored = tmp_path / "correction-restored"
    git(root, "clone", str(root), str(restored))
    git(restored, "checkout", reviewed_b)
    subprocess.run(
        ["git", "apply", "--index", "--binary", str(out / "staged.patch")],
        cwd=restored,
        check=True,
    )
    subprocess.run(
        ["git", "apply", "--binary", str(out / "unstaged.patch")],
        cwd=restored,
        check=True,
    )
    extract_untracked(out, restored)
    assert (restored / "implementation.txt").read_text() == "unstaged correction C\n"
    assert (restored / "new-correction.txt").read_text() == "untracked correction C\n"


def test_correction_requires_explicit_base_sha(tmp_path, monkeypatch):
    root = repo(tmp_path)
    monkeypatch.chdir(root)
    with pytest.raises(ValueError, match="require CHECKPOINT_BASE_SHA"):
        checkpoint.collect("correct_1", 80, tmp_path / "missing-base")


def test_empty_untracked_set_and_missing_optional_files_work(tmp_path, monkeypatch):
    root = repo(tmp_path)
    monkeypatch.chdir(root)
    out = tmp_path / "empty"
    checkpoint.collect("build", 40, out)
    assert json.loads((out / "untracked-manifest.json").read_text()) == {"files": []}
    with tarfile.open(out / "untracked-files.tar.gz") as bundle:
        assert bundle.getmembers() == []
    metadata = json.loads((out / "checkpoint-metadata.json").read_text())
    assert not any(metadata["optional_files"].values())


def test_credential_paths_excluded_and_approved_fixture_preserved(tmp_path, monkeypatch):
    root = repo(tmp_path)
    excluded = {
        "auth.json": b"\x00binary auth store",
        "credentials.json": b"credential data",
        ".env.staging": b"VALUE=data",
        "token-cache.json": b"token data",
        ".ssh/id_ed25519": b"\x00private key bytes",
        "azureProfile.json": b"cloud authentication profile",
    }
    for rel, data in excluded.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    fixture = root / "tests" / "fixtures" / "crypto" / "credentials.json"
    fixture.parent.mkdir(parents=True)
    fixture.write_bytes(b"\x00approved disposable binary fixture")
    monkeypatch.chdir(root)
    out = tmp_path / "excluded"
    checkpoint.collect("build", 40, out)
    report = json.loads((out / "excluded-untracked.json").read_text())["excluded"]
    assert {item["path"] for item in report} == set(excluded)
    assert all(set(item) == {"path", "reason"} for item in report)
    with tarfile.open(out / "untracked-files.tar.gz") as bundle:
        assert bundle.getnames() == ["tests/fixtures/crypto/credentials.json"]
        archived = bundle.extractfile("tests/fixtures/crypto/credentials.json")
        assert archived is not None and archived.read() == fixture.read_bytes()


def test_credential_shaped_content_outside_fixture_is_excluded(tmp_path, monkeypatch):
    root = repo(tmp_path)
    fake_token = ("github_" + "pat_" + "abcdefghijklmnopqrstuvwxyz0123456789").encode()
    (root / "opaque.bin").write_bytes(b"\x00" + fake_token)
    monkeypatch.chdir(root)
    out = tmp_path / "content-excluded"
    checkpoint.collect("build", 40, out)
    report = json.loads((out / "excluded-untracked.json").read_text())["excluded"]
    assert report == [{"path": "opaque.bin", "reason": "credential-shaped content"}]


def test_path_traversal_from_git_is_rejected(tmp_path, monkeypatch):
    root = repo(tmp_path)
    monkeypatch.chdir(root)
    real_git = checkpoint._git

    def fake_git(args, **kwargs):
        if args[:2] == ["ls-files", "--others"]:
            return b"../escape\0"
        return real_git(args, **kwargs)

    monkeypatch.setattr(checkpoint, "_git", fake_git)
    with pytest.raises(ValueError, match="escapes repository"):
        checkpoint._safe_untracked(root)


def test_prompt_context_result_diagnostics_and_test_summary_are_distinct(tmp_path, monkeypatch):
    root = repo(tmp_path)
    prompt = tmp_path / "prompt.txt"
    context = tmp_path / "context.json"
    result = tmp_path / "result.json"
    execution = tmp_path / "execution.json"
    prompt.write_text("actual rendered correction prompt\n")
    context.write_text('{"codex_blockers":["fix the bug"]}\n')
    result.write_text('{"status":"FAILED","validation":{"ruff":"pass","pytest":"fail"}}\n')
    execution.write_text(
        '[{"type":"assistant","message":"private transcript"},'
        '{"type":"result","subtype":"error_during_execution","num_turns":7,'
        '"result":"private result prose"}]'
    )
    monkeypatch.setenv("CHECKPOINT_CORRECTION_PROMPT", str(prompt))
    monkeypatch.setenv("CHECKPOINT_CODEX_BLOCKERS", str(context))
    monkeypatch.setenv("CHECKPOINT_BUILDER_RESULT", str(result))
    monkeypatch.setenv("CHECKPOINT_EXECUTION_FILE", str(execution))
    monkeypatch.setenv("CHECKPOINT_BASE_SHA", git(root, "rev-parse", "HEAD").stdout.strip())
    monkeypatch.chdir(root)
    out = tmp_path / "optional"
    checkpoint.collect("correct_1", 80, out)
    assert (out / "correction-prompt.txt").read_bytes() == prompt.read_bytes()
    assert (out / "codex-blocker-input.json").read_bytes() == context.read_bytes()
    assert (out / "correction-prompt.txt").read_bytes() != context.read_bytes()
    diagnostics = json.loads((out / "builder-execution-diagnostics.json").read_text())
    assert diagnostics == {"type": "result", "subtype": "error_during_execution", "num_turns": 7}
    assert "private" not in (out / "builder-execution-diagnostics.json").read_text()
    assert json.loads((out / "test-results.json").read_text()) == {
        "validation": {"ruff": "pass", "pytest": "fail"}
    }


def test_secret_scanner_fails_closed_for_checkpoint_text(tmp_path, monkeypatch):
    root = repo(tmp_path)
    (root / "tracked.txt").write_text("github_" + "pat_" + "abcdefghijklmnopqrstuvwxyz0123456789\n")
    monkeypatch.chdir(root)
    out = tmp_path / "unsafe"
    with pytest.raises(ValueError, match="secret scanning"):
        checkpoint.collect("build", 40, out)
    assert not out.exists()


def test_main_requires_exact_arguments(capsys):
    assert checkpoint.main([]) == 2
    assert "usage" in capsys.readouterr().out
