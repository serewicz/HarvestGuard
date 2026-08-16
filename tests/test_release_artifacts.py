"""Offline manifest regression for the wheel and sdist intended for PyPI.

Set ``HARVESTGUARD_RUN_NETWORK_INSTALL_TESTS=1`` to additionally exercise fresh
virtualenv installs. Those integration checks may resolve dependencies from a
package index and are deliberately excluded from the default offline suite.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

from harvestguard_version import __version__, version_string

ROOT = Path(__file__).parent.parent
FORBIDDEN_TOP_LEVEL = {"dashboard", "demo", "docs", "tests"}
RUN_NETWORK_INSTALL_TESTS = os.environ.get("HARVESTGUARD_RUN_NETWORK_INSTALL_TESTS") == "1"


def _venv_bin(venv_dir: Path, name: str) -> Path:
    if sys.platform == "win32":
        return venv_dir / "Scripts" / f"{name}.exe"
    return venv_dir / "bin" / name


@pytest.fixture(scope="module")
def release_artifacts(tmp_path_factory) -> tuple[Path, Path]:
    output = tmp_path_factory.mktemp("release-artifacts")
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "build",
            "--no-isolation",
            "--outdir",
            str(output),
            str(ROOT),
        ],
        cwd=output,
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )
    assert completed.returncode == 0, (completed.stdout + completed.stderr)[-4000:]

    wheels = list(output.glob("*.whl"))
    sdists = list(output.glob("*.tar.gz"))
    assert [path.name for path in wheels] == [f"harvestguard-{__version__}-py3-none-any.whl"]
    assert [path.name for path in sdists] == [f"harvestguard-{__version__}.tar.gz"]
    return wheels[0], sdists[0]


def _wheel_paths(wheel: Path) -> set[Path]:
    with zipfile.ZipFile(wheel) as archive:
        return {Path(name) for name in archive.namelist() if not name.endswith("/")}


def _sdist_paths(sdist: Path) -> set[Path]:
    with tarfile.open(sdist) as archive:
        members = {Path(member.name) for member in archive.getmembers() if member.isfile()}
    roots = {path.parts[0] for path in members}
    assert roots == {f"harvestguard-{__version__}"}
    return {Path(*path.parts[1:]) for path in members}


@pytest.mark.parametrize("artifact_kind", ["wheel", "sdist"])
def test_release_artifacts_exclude_repository_only_content(release_artifacts, artifact_kind):
    wheel, sdist = release_artifacts
    paths = _wheel_paths(wheel) if artifact_kind == "wheel" else _sdist_paths(sdist)

    top_level = {path.parts[0] for path in paths if path.parts}
    assert FORBIDDEN_TOP_LEVEL.isdisjoint(top_level)
    assert Path("main.py") not in paths


def test_release_artifacts_contain_expected_package_content(release_artifacts):
    wheel, sdist = release_artifacts
    wheel_paths = _wheel_paths(wheel)
    sdist_paths = _sdist_paths(sdist)

    expected_package_files = {
        Path("harvestguard.py"),
        Path("harvestguard_version.py"),
        Path("scanner/filesystem.py"),
        Path("code_analysis/rules/crypto.yaml"),
    }
    assert expected_package_files <= wheel_paths
    assert expected_package_files <= sdist_paths
    assert any(path.name == "LICENSE" for path in wheel_paths)
    assert Path("LICENSE") in sdist_paths
    assert any(
        path.parts[-2:] == (f"harvestguard-{__version__}.dist-info", "METADATA")
        for path in wheel_paths
    )
    assert Path("PKG-INFO") in sdist_paths


def test_sdist_contains_complete_build_inputs_without_partial_tests(release_artifacts):
    _wheel, sdist = release_artifacts
    paths = _sdist_paths(sdist)

    for required in ("LICENSE", "MANIFEST.in", "README.md", "pyproject.toml"):
        assert Path(required) in paths
    assert not any(path.parts and path.parts[0] == "tests" for path in paths)
    assert not any(path.parts[:2] == ("tests", "fixtures") for path in paths)


def test_artifact_content_matches_public_documentation(release_artifacts):
    wheel, sdist = release_artifacts
    assert FORBIDDEN_TOP_LEVEL.isdisjoint(
        {path.parts[0] for path in _wheel_paths(wheel) if path.parts}
    )
    assert FORBIDDEN_TOP_LEVEL.isdisjoint(
        {path.parts[0] for path in _sdist_paths(sdist) if path.parts}
    )

    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    release = (ROOT / "docs" / "RELEASE.md").read_text(encoding="utf-8")
    normalized_readme = " ".join(readme.split())
    normalized_release = " ".join(release.split())
    assert "Neither the wheel nor the source archive contains" in normalized_readme
    assert "`demo/`, `tests/`, `docs/`" in normalized_release
    assert "are **not** in either artifact" in normalized_release


@pytest.mark.parametrize("artifact_kind", ["wheel", "sdist"])
@pytest.mark.skipif(
    not RUN_NETWORK_INSTALL_TESTS,
    reason="set HARVESTGUARD_RUN_NETWORK_INSTALL_TESTS=1 for networked install validation",
)
def test_each_built_artifact_installs_and_runs_the_cli(
    release_artifacts, artifact_kind, tmp_path
):
    wheel, sdist = release_artifacts
    artifact = wheel if artifact_kind == "wheel" else sdist
    venv_dir = tmp_path / artifact_kind
    subprocess.run(
        [sys.executable, "-m", "venv", str(venv_dir)],
        capture_output=True,
        text=True,
        timeout=300,
        check=True,
    )
    install = subprocess.run(
        [
            str(_venv_bin(venv_dir, "python")),
            "-m",
            "pip",
            "install",
            str(artifact),
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )
    assert install.returncode == 0, (install.stdout + install.stderr)[-4000:]

    for args, expected in (
        (("--version",), version_string()),
        (("--help",), "usage: harvestguard"),
        (("scan", "--help"), "usage: harvestguard scan"),
    ):
        completed = subprocess.run(
            [str(_venv_bin(venv_dir, "harvestguard")), *args],
            cwd=tmp_path,
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
        assert completed.returncode == 0, completed.stderr[-2000:]
        assert expected in completed.stdout

    target = tmp_path / f"{artifact_kind}-target"
    target.mkdir()
    (target / "synthetic.txt").write_text("review-only synthetic file\n", encoding="utf-8")
    scan = subprocess.run(
        [
            str(_venv_bin(venv_dir, "harvestguard")),
            "scan",
            str(target),
            "--type",
            "filesystem",
            "--json",
            "--quiet",
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    assert scan.returncode == 0, scan.stderr[-2000:]
    payload = json.loads(scan.stdout)
    assert isinstance(payload, list) and payload
