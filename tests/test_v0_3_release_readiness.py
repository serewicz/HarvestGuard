"""Release-preparation contract for Issue #136."""

from __future__ import annotations

import re
from pathlib import Path

from harvestguard_version import __version__, version_string

ROOT = Path(__file__).parent.parent
PYPROJECT = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
CHANGELOG = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
RELEASE = (ROOT / "docs" / "RELEASE.md").read_text(encoding="utf-8")
NOTES_PATH = ROOT / "docs" / "release-notes" / "v0.3.0.md"
NOTES = NOTES_PATH.read_text(encoding="utf-8")


def test_v0_3_release_identity_is_consistent():
    match = re.search(r'^version\s*=\s*"([^"]+)"', PYPROJECT, re.MULTILINE)
    assert match is not None
    assert match.group(1) == __version__ == "0.3.0"
    assert version_string() == "harvestguard 0.3.0"
    assert "## 0.3.0 — Validation, Trust, and First External Use" in CHANGELOG
    assert NOTES_PATH.is_file()


def test_release_preparation_has_an_ordered_maintainer_publication_checklist():
    heading = "### Maintainer publication checklist (v0.3.0)"
    assert heading in RELEASE
    checklist = RELEASE.split(heading, 1)[1].split("\n## ", 1)[0]
    steps = re.findall(r"^(\d+)\. ", checklist, re.MULTILINE)
    assert steps == [str(number) for number in range(1, 9)]
    for marker in (
        "reviewed merge commit",
        "annotated tag `v0.3.0`",
        "python -m twine check dist/*",
        "Upload only those two validated artifacts to PyPI",
        "Create GitHub Release `v0.3.0`",
        "brand-new environment",
        "no GHCR `v0.3.0` image",
    ):
        assert marker in checklist


def test_release_materials_keep_preparation_separate_from_publication():
    preparation = RELEASE.split("## v0.3.0 release preparation (issue #136)", 1)[1]
    assert "creates no tag, release, package" in " ".join(preparation.split()).lower()
    assert "publishes nothing by itself" in NOTES.lower()
    assert "separate maintainer actions" in NOTES.lower()


def test_v0_3_notes_disclose_evidence_limits_and_claims_boundary():
    normalized = " ".join(NOTES.lower().split())
    for marker in (
        "no ubuntu transcript is committed",
        "oci container",
        "used pandas below 3.0",
        "#140",
        "`age_encrypted` was skipped",
        "only `--type crypto` was exercised",
        "windows and wsl are neither validated nor claimed supported",
        "does not claim complete inventory",
        "no sla",
    ):
        assert marker in normalized


def test_v0_3_release_notes_use_tag_pinned_repository_links():
    body = NOTES.split("\n---\n", 1)[1]
    repository_links = re.findall(
        r"https://github\.com/serewicz/HarvestGuard/(?:blob|tree)/([^/]+)/", body
    )
    assert repository_links
    assert set(repository_links) == {"v0.3.0"}
