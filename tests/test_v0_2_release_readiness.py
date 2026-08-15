"""The v0.2 pre-1.0 release readiness audit (GitHub issue #119).

The audit in docs/RELEASE.md is a go/no-go *evidence record*, so the properties
worth protecting are the ones that would let it quietly stop being evidence:
that it still states the version identity the repository actually declares,
that every open item still names an owner rather than trailing off, that its
release commands are recorded as unexecuted rather than performed, and that
nothing in it claims a release, tag, or publication that does not exist.

These tests deliberately run no subprocess and no scan: the audit's own checks
are reproduced by the commands recorded in the document, and by the test files
it cites.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from harvestguard_version import __version__

ROOT = Path(__file__).parent.parent
RELEASE = ROOT / "docs" / "RELEASE.md"
RELEASE_TEXT = RELEASE.read_text(encoding="utf-8")
CHANGELOG_TEXT = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")

AUDIT_HEADING = "## v0.2 pre-1.0 release readiness audit"


def _section(text: str, heading: str) -> str:
    """Return the body of a top-level Markdown section, heading excluded."""
    lines = text.splitlines()
    start = lines.index(heading)
    for offset, line in enumerate(lines[start + 1 :], start=start + 1):
        if line.startswith("## "):
            return "\n".join(lines[start + 1 : offset])
    return "\n".join(lines[start + 1 :])


def _anchor(heading_text: str) -> str:
    """Slugify a Markdown heading the way GitHub generates its anchor."""
    slug = heading_text.strip().lower()
    slug = re.sub(r"[^\w\- ]+", "", slug, flags=re.UNICODE)
    return slug.replace(" ", "-")


def _anchors(markdown_path: Path) -> set[str]:
    return {
        _anchor(match.group(1))
        for match in re.finditer(
            r"^#{1,6}\s+(.+?)\s*$", markdown_path.read_text(encoding="utf-8"), flags=re.MULTILINE
        )
    }


AUDIT = _section(RELEASE_TEXT, AUDIT_HEADING)


def _table_rows(section: str, first_cell_pattern: str) -> list[list[str]]:
    """Return the cells of every table row whose first cell matches."""
    rows = []
    for line in section.splitlines():
        stripped = line.strip()
        if not stripped.startswith("|"):
            continue
        cells = [cell.strip() for cell in stripped.strip("|").split("|")]
        if cells and re.fullmatch(first_cell_pattern, cells[0]):
            rows.append(cells)
    return rows


# --- The audit exists and covers what a go/no-go decision needs -------------


def test_release_doc_carries_the_v0_2_readiness_audit():
    assert AUDIT_HEADING in RELEASE_TEXT
    assert AUDIT.strip()


@pytest.mark.parametrize(
    "topic, heading",
    [
        ("what was audited", "### Audit basis"),
        ("current state versus the proposal", "### Current state versus the proposed v0.2 release"),
        ("public-use prerequisites", "### Public-use prerequisites"),
        ("the audited surfaces", "### Surface audit"),
        ("unresolved items", "### Open items for the v0.2 go/no-go"),
        ("the proposed checklist", "### Proposed v0.2 release checklist"),
    ],
)
def test_audit_covers_every_required_topic(topic, heading):
    assert heading in AUDIT, f"the v0.2 audit does not cover {topic}"


@pytest.mark.parametrize(
    "surface",
    [
        "Version identity",
        "Changelog",
        "Installation",
        "Release documentation",
        "Supported Python",
        "License",
        "Security reporting",
        "Sample-output provenance",
        "Claims",
        "Release procedure",
        "Demo quickstart",
    ],
)
def test_surface_audit_records_a_result_for_each_audited_surface(surface):
    rows = _table_rows(AUDIT, re.escape(surface))
    assert rows, f"the surface audit has no row for {surface}"
    check, result = rows[0][1], rows[0][2]
    assert check and result, f"{surface} has no reproducible check or no recorded result"


# --- The audit still describes the version the repository declares ----------


def test_audit_records_the_version_identity_that_is_actually_declared():
    # The audit is the record of a *pre-release* state. If the version literal
    # is ever bumped, this fails on purpose: the audit then describes a version
    # the repository no longer declares, and has to be revisited (its own open
    # item B-4 covers the sample artifacts that go stale for the same reason)
    # rather than left standing as evidence for a state that has passed.
    assert f"| Declared version at that commit | `{__version__}` |" in AUDIT
    assert f"| `harvestguard --version` | `harvestguard {__version__}` |" in AUDIT


def test_audit_separates_the_current_state_from_the_proposed_release():
    lowered = AUDIT.lower()
    assert "the repository is **not** at v0.2" in lowered
    # A v0.1.0 tag genuinely exists (verified against git ls-remote / the
    # GitHub API while completing this audit), so the audit must say so plainly
    # and distinguish it from the missing GitHub Release.
    assert "a `v0.1.0` tag already exists" in lowered
    assert "no github release published from it" in lowered
    assert "the annotated `v0.1.0` tag already exists" in lowered


# --- Every unresolved item is owned ----------------------------------------


def test_every_open_item_has_an_id_blocking_state_and_owner_action():
    rows = _table_rows(_section(RELEASE_TEXT, AUDIT_HEADING), r"B-\d+")
    expected = {f"B-{number}" for number in range(1, 10)}
    assert {row[0] for row in rows} == expected

    identifiers = [row[0] for row in rows]
    assert len(set(identifiers)) == len(identifiers), f"duplicate open-item ids: {identifiers}"

    for identifier, item, blocking, owner in rows:
        assert item.strip(), f"{identifier} has no description"
        assert blocking.strip(), f"{identifier} does not say whether it blocks the release"
        assert owner.strip(), f"{identifier} has no owner or action"
        assert "maintainer" in owner.lower(), f"{identifier} names no owner: {owner!r}"


def test_open_items_referenced_in_the_audit_text_are_all_defined():
    defined = {row[0] for row in _table_rows(AUDIT, r"B-\d+")}
    referenced = set(re.findall(r"\bB-\d+\b", AUDIT))
    assert referenced <= defined, f"undefined open items referenced: {sorted(referenced - defined)}"


def test_every_blocking_open_item_is_named_in_the_release_checklist():
    rows = _table_rows(AUDIT, r"B-\d+")
    blocking = {row[0] for row in rows if row[2].lower().startswith("yes")}
    checklist = AUDIT[AUDIT.index("### Proposed v0.2 release checklist") :]

    assert blocking == {"B-1", "B-2", "B-3", "B-4", "B-5", "B-9"}
    for identifier in blocking:
        assert re.search(rf"\b{re.escape(identifier)}\b", checklist), (
            f"the release checklist omits blocking item {identifier}"
        )
    assert "B-1 through B-5 and B-9" in checklist


# --- The checklist identifies release commands without executing them -------


def test_checklist_names_the_tag_and_release_commands():
    checklist = AUDIT[AUDIT.index("### Proposed v0.2 release checklist") :]
    for command in (
        'git tag -a v0.2.0 -m "HarvestGuard v0.2.0"',
        "git push origin v0.2.0",
        "ruff check .",
        "python -m pytest -v",
        "git diff --check",
    ):
        assert command in checklist, f"the checklist does not identify: {command}"
    for required_check in ("Test (Python 3.10)", "Test (Python 3.11)", "Test (Python 3.12)"):
        assert required_check in checklist


def test_checklist_states_that_none_of_it_was_run():
    checklist = AUDIT[AUDIT.index("### Proposed v0.2 release checklist") :]
    assert "**None of these commands was run.**" in checklist


def test_audit_claims_no_tag_release_publication_or_version_change():
    lowered = " ".join(AUDIT.lower().split())
    for forbidden in (
        "v0.2.0 has been released",
        "tag has been created",
        "tag has been pushed",
        "tagged as v0.2.0",
        "the release has been published",
    ):
        assert forbidden not in lowered, f"the audit falsely claims: {forbidden!r}"
    assert "created no `v0.2.0` tag" in lowered
    assert "changed no version literal" in lowered


def test_audit_does_not_erase_the_existing_v0_1_tag_or_ghcr_images():
    lowered = " ".join(AUDIT.lower().split())
    assert "the annotated `v0.1.0` tag already exists" in lowered
    assert "no github release or pypi package has been published" in lowered
    assert "ghcr contains signed commit-sha images and signature/attestation objects" in lowered
    assert "no `v0.1.0` or `v0.2.0` version-tagged image" in lowered
    for broad_claim in (
        "created no tag",
        "no tag exists",
        "published release, package, or version-tagged image | none",
    ):
        assert broad_claim not in lowered


def test_git_tags_table_preserves_the_existing_and_future_tag_distinction():
    [tag_row] = _table_rows(AUDIT, r"Git tags")
    current_state, future_state = tag_row[1], tag_row[2]
    normalized_future = " ".join(future_state.lower().split())

    assert "`v0.1.0` exists" in current_state
    assert "annotated tag" in current_state
    assert "no GitHub Release published from it" in current_state
    assert "`v0.2.0` would be the repository's second version tag" in normalized_future
    assert "separate maintainer decision" in normalized_future
    assert "deleting or replacing `v0.1.0`" in normalized_future

    for former_or_equivalent_claim in (
        "second tag, or its first",
        "second version tag, or its first",
        "`v0.2.0` could be the first tag",
        "`v0.2.0` could be the first version tag",
        "`v0.2.0` would be the first tag",
        "`v0.2.0` would be the first version tag",
    ):
        assert former_or_equivalent_claim not in normalized_future

    assert not re.search(
        r"v0\.2\.0.{0,80}\b(?:could|would)\b.{0,80}\bfirst(?: version)? tag\b",
        normalized_future,
    )


def test_b3_covers_the_completed_first_public_use_work():
    [b3] = _table_rows(AUDIT, r"B-3")
    owner_action = b3[3]
    assert "HG-028…HG-044" in owner_action
    assert "Issues #115 through #118" in owner_action
    assert "#119 release-readiness audit" in owner_action


def test_audit_stays_an_operational_readiness_record():
    lowered = " ".join(AUDIT.lower().split())
    # Issue #119's claims boundary: readiness to release says nothing about the
    # product's completeness, security, compliance, or migration standing.
    assert (
        "it is not evidence of product completeness, cryptographic completeness, security, "
        "compliance, remediation readiness, migration readiness, or quantum readiness" in lowered
    )
    for forbidden in ("production-ready", "we recommend", "risk score"):
        assert forbidden not in lowered, f"the audit strays outside evidence: {forbidden!r}"


# --- What the audit points at actually exists -------------------------------


@pytest.mark.parametrize(
    "artifact",
    [
        "demo/sample_target/README.md",
        "docs/examples/first-run/README.md",
        "docs/examples/first-run/generate_samples.py",
        "docs/examples/executive-evidence-example.md",
        "tests/test_demo_fixture.py",
        "tests/test_first_run_samples.py",
        "tests/test_quickstart_docs.py",
        "tests/test_executive_evidence_example.py",
        "tests/test_clean_install.py",
        "tests/test_release_identity.py",
        "tests/test_product_claims.py",
        "scripts/check_required_ci.py",
    ],
)
def test_prerequisite_evidence_the_audit_cites_is_present(artifact):
    assert (ROOT / artifact).exists(), f"the audit cites {artifact}, which does not exist"


def test_audit_links_and_anchors_resolve():
    for target in re.findall(r"\]\((?!https?:)([^)]+)\)", AUDIT):
        path_part, _, fragment = target.partition("#")
        document = RELEASE if not path_part else (RELEASE.parent / path_part).resolve()
        assert document.exists(), f"broken link target in the v0.2 audit: {target}"
        if fragment:
            assert fragment in _anchors(document), f"broken anchor in the v0.2 audit: {target}"


# --- The changelog surface the audit reports on -----------------------------


def test_changelog_records_the_undescribed_merged_work_and_points_at_the_audit():
    unreleased = _section(CHANGELOG_TEXT, "## Unreleased")
    assert "not yet described by a version entry here" in unreleased
    assert f"`{__version__}` in both `pyproject.toml` and `harvestguard_version.py`" in unreleased
    assert "docs/RELEASE.md#v02-pre-10-release-readiness-audit" in unreleased
    normalized = " ".join(unreleased.lower().split())
    assert "no `v0.2.0` tag or github release has been created" in normalized
    assert "no pypi, wheel, or sdist publication has been made" in normalized
    assert "no version change has been made" in normalized
    assert "no tag, release, package publication" not in normalized
