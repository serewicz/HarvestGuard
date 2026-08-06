"""Recovery and safety tests for complete agent checkpoints."""

from __future__ import annotations

import hashlib
import json
import subprocess
import tarfile
from pathlib import Path

import pytest

import scripts.collect_worktree_checkpoint as checkpoint


def git(repo: Path, *args: str, text: bool = True):
    return subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=text)


def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    git(root, "init", "-b", "main")
    git(root, "config", "user.name", "Test")
    git(root, "config", "user.email", "test.invalid")
    (root / "tracked.txt").write_text("base\n")
    git(root, "add", "tracked.txt")
    git(root, "commit", "-m", "base")
    git(root, "remote", "add", "origin", str(root))
    git(root, "fetch", "origin", "main:refs/remotes/origin/main")
    return root


def test_complete_checkpoint_round_trip(tmp_path, monkeypatch):
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
    with tarfile.open(out / "untracked-files.tar.gz") as bundle:
        for rel, expected in files.items():
            member = bundle.extractfile(rel)
            assert member is not None and member.read() == expected

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
    with tarfile.open(out / "untracked-files.tar.gz") as bundle:
        bundle.extractall(restored, filter="data")
    for rel, expected in files.items():
        assert (restored / rel).read_bytes() == expected
    assert "staged" in git(restored, "diff", "--cached").stdout
    assert "unstaged" in git(restored, "diff").stdout
    assert git(root, "rev-parse", "HEAD").stdout.strip() in (out / "RECOVERY.md").read_text()


def test_empty_untracked_set_and_missing_builder_result_work(tmp_path, monkeypatch):
    root = repo(tmp_path)
    monkeypatch.chdir(root)
    out = tmp_path / "empty"
    checkpoint.collect("build", 40, out)
    assert json.loads((out / "untracked-manifest.json").read_text()) == {"files": []}
    with tarfile.open(out / "untracked-files.tar.gz") as bundle:
        assert bundle.getmembers() == []
    assert not (out / "builder-result.json").exists()


def test_ignored_and_sensitive_paths_are_excluded(tmp_path, monkeypatch):
    root = repo(tmp_path)
    (root / ".gitignore").write_text("ignored.bin\n")
    (root / "ignored.bin").write_bytes(b"ignored")
    (root / ".venv").mkdir()
    (root / ".venv" / "token").write_text("not archived")
    (root / ".env").write_text("NOT_A_REAL_SECRET=value\n")
    monkeypatch.chdir(root)
    out = tmp_path / "excluded"
    checkpoint.collect("correct_1", 80, out, step_conclusion="failure")
    entries = json.loads((out / "untracked-manifest.json").read_text())["files"]
    assert [entry["path"] for entry in entries] == [".gitignore"]
    with tarfile.open(out / "untracked-files.tar.gz") as bundle:
        names = bundle.getnames()
    assert ".git" not in names and ".venv/token" not in names and "ignored.bin" not in names


def test_optional_failure_artifacts_are_copied(tmp_path, monkeypatch):
    root = repo(tmp_path)
    result = tmp_path / "result.json"
    result.write_text('{"status":"FAILED"}\n')
    monkeypatch.setenv("CHECKPOINT_BUILDER_RESULT", str(result))
    monkeypatch.chdir(root)
    out = tmp_path / "failed"
    checkpoint.collect("build", 80, out, "session", "failure")
    assert (out / "builder-result.json").read_bytes() == result.read_bytes()


def test_secret_scanner_fails_closed(tmp_path, monkeypatch):
    root = repo(tmp_path)
    fake_token = "github_" + "pat_" + "abcdefghijklmnopqrstuvwxyz0123456789"
    (root / "tracked.txt").write_text(fake_token + "\n")
    monkeypatch.chdir(root)
    out = tmp_path / "unsafe"
    with pytest.raises(ValueError, match="secret scanning"):
        checkpoint.collect("build", 40, out)
    assert not out.exists()


def test_main_requires_exact_arguments(capsys):
    assert checkpoint.main([]) == 2
    assert "usage" in capsys.readouterr().out
