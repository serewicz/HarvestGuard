"""Release and distribution readiness (GitHub issue #125).

Issue #125 chose a release *path* and prepared the surfaces around it. The
properties worth protecting are the ones whose quiet erosion would either
mislead an outside reader or let a release happen by accident:

- the drafted `0.2.0` changelog entry keeps saying it is a draft for as long as
  the repository still declares `0.1.0`;
- the recorded decision keeps naming a disposition for every audit open item,
  so none of them trails off;
- the deferrals that were deliberate (PyPI, version-tagged images) stay
  recorded as deferrals rather than drifting into implied availability;
- the support/advisory language stays in SUPPORT.md and out of the detector and
  claims documentation;
- nothing in the public-facing release surfaces starts asserting completeness,
  exploitability, business risk, compliance, remediation, migration readiness,
  quantum readiness, or HNDL scoring.

No subprocess and no scan runs here: the commands this preparation ran are
recorded in docs/RELEASE.md, and the scan behaviour they exercise is covered by
the test files that own it (tests/test_first_run_samples.py,
tests/test_quickstart_docs.py, tests/test_release_identity.py).
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from harvestguard_version import __version__

ROOT = Path(__file__).parent.parent
RELEASE = ROOT / "docs" / "RELEASE.md"
RELEASE_NOTES = ROOT / "docs" / "release-notes" / "v0.2.0-draft.md"
SUPPORT = ROOT / "SUPPORT.md"
CHANGELOG = ROOT / "CHANGELOG.md"
README = ROOT / "README.md"

RELEASE_TEXT = RELEASE.read_text(encoding="utf-8")
CHANGELOG_TEXT = CHANGELOG.read_text(encoding="utf-8")
README_TEXT = README.read_text(encoding="utf-8")

DECISION_HEADING = "## Release and distribution decision (v0.2 preparation)"

# The claim boundary issue #125 requires every release-facing surface to hold.
# Each phrase is *assertive* phrasing of something HarvestGuard does not
# establish. These documents deliberately enumerate the same subjects in order
# to disclaim them ("complete or exhaustive inventory of cryptographic
# material", "determine whether an organization is quantum-ready"), so banning
# the bare nouns would fire on the disclaimers themselves; each phrase below is
# chosen to appear only where a claim is actually being made.
FORBIDDEN_ASSERTIONS = (
    "provides a complete inventory",
    "produces a complete inventory",
    "guarantees complete",
    "guarantees that no",
    "proves that no",
    "confirms the absence of",
    "harvestguard is quantum-ready",
    "your organization is quantum-ready",
    "quantum readiness:",
    "migration readiness:",
    "business impact:",
    "recommended remediation:",
    "remediation priority:",
    "is fully compliant",
    "hndl score",
    "risk score of",
)


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
            r"^#{1,6}\s+(.+?)\s*$",
            markdown_path.read_text(encoding="utf-8"),
            flags=re.MULTILINE,
        )
    }


def _local_links(markdown: str) -> list[str]:
    """Every in-repository Markdown link target, external and mailto links excluded."""
    return re.findall(r"\]\((?!https?:|mailto:)([^)\s]+)\)", markdown)


def _table_rows(section: str, first_cell_pattern: str) -> list[list[str]]:
    rows = []
    for line in section.splitlines():
        stripped = line.strip()
        if not stripped.startswith("|"):
            continue
        cells = [cell.strip() for cell in stripped.strip("|").split("|")]
        if cells and re.fullmatch(first_cell_pattern, cells[0]):
            rows.append(cells)
    return rows


def _normalized(text: str) -> str:
    return " ".join(text.lower().split())


def _plain(text: str) -> str:
    """Normalized, with Markdown bold markers dropped so emphasis is not load-bearing."""
    return _normalized(text.replace("**", ""))


def _draft_entry_heading() -> str:
    return next(line for line in CHANGELOG_TEXT.splitlines() if line.startswith("## 0.2.0"))


def _draft_entry() -> str:
    """The body of the drafted `0.2.0` changelog entry, whatever its heading suffix."""
    return _section(CHANGELOG_TEXT, _draft_entry_heading())


DECISION = _section(RELEASE_TEXT, DECISION_HEADING)


# --- The decision exists, is a decision, and is reviewable ------------------


def test_release_doc_records_the_release_and_distribution_decision():
    assert DECISION_HEADING in RELEASE_TEXT
    assert DECISION.strip()


@pytest.mark.parametrize(
    "topic, heading",
    [
        ("the chosen option", "### Decision"),
        (
            "the release-surface facts it rests on",
            "### Release-surface facts as of this preparation",
        ),
        ("what happened to each open item", "### Disposition of the audit's open items"),
        ("which distribution channels were chosen", "### Distribution decisions"),
        ("repository metadata actions", "### Repository metadata actions"),
        ("the support/advisory path", "### Support and advisory path"),
        ("validation performed", "### Validation performed during this preparation"),
    ],
)
def test_decision_covers_every_required_topic(topic, heading):
    assert any(line.startswith(heading) for line in DECISION.splitlines()), (
        f"the release decision does not cover {topic}"
    )


def test_decision_states_one_chosen_option_and_why_the_others_were_not():
    normalized = _normalized(DECISION)
    assert "prepare a `v0.2.0` pre-1.0 github release; publish nothing yet" in normalized
    # All three options the issue put on the table are answered, not silently
    # dropped: exactly one is chosen and the others carry a reason.
    for option in ("| a — ", "| **b — ", "| c — "):
        assert option in normalized, f"the decision does not account for option {option!r}"
    assert normalized.count("| **chosen** |") == 1, "exactly one option should be marked chosen"
    assert "not chosen" in normalized


def test_decision_keeps_release_mechanics_separate_from_product_claims():
    normalized = _normalized(DECISION)
    assert (
        "it asserts nothing about product completeness, cryptographic completeness, detection "
        "coverage, security, compliance, remediation readiness, migration readiness, or quantum "
        "readiness" in normalized
    )


# --- Preparation published nothing -----------------------------------------


def test_decision_records_that_preparation_published_nothing():
    normalized = _normalized(DECISION)
    assert "preparing this decision published nothing" in normalized
    assert "changed no version literal" in normalized
    for falsehood in (
        "v0.2.0 has been released",
        "the release has been published",
        "tagged as v0.2.0",
        "published to pypi",
    ):
        assert falsehood not in normalized, f"the decision falsely claims: {falsehood!r}"


def test_version_literals_were_not_bumped_by_this_preparation():
    # Issue #125 explicitly excludes a version bump: the bump is part of the
    # separately authorized release action. If this ever fails, the drafted
    # changelog entry and the release-notes draft both stop being drafts and
    # have to be revisited rather than left standing.
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'^version\s*=\s*"([^"]+)"', pyproject, re.MULTILINE)
    assert match is not None
    assert match.group(1) == "0.1.0"
    assert __version__ == "0.1.0"


def test_release_surface_facts_match_the_issue_125_baseline():
    facts = _normalized(_section(RELEASE_TEXT, DECISION_HEADING))
    assert "the annotated `v0.1.0` tag exists" in facts
    assert "no `v0.2.0` tag has been created" in facts
    assert "| none published, from `v0.1.0` or any other tag |" in facts
    assert "| no publication of any kind |" in facts
    assert "no `v0.1.0` or `v0.2.0` version-tagged image" in facts


# --- Every audit open item has a disposition -------------------------------


def test_every_audit_open_item_has_a_recorded_disposition():
    rows = _table_rows(DECISION, r"B-\d+")
    assert {row[0] for row in rows} == {f"B-{number}" for number in range(1, 10)}
    for identifier, disposition in rows:
        assert disposition.strip(), f"{identifier} has no recorded disposition"
        assert re.search(r"resolved|maintainer action|accepted|decided", disposition.lower()), (
            f"{identifier}'s disposition says nothing actionable: {disposition!r}"
        )


def test_b1_decides_the_v0_1_0_release_question_without_disturbing_the_tag():
    [b1] = _table_rows(DECISION, r"B-1")
    disposition = _normalized(b1[1])
    assert "do not publish a `v0.1.0` github release" in disposition
    assert "kept as-is" in disposition
    assert "not deleted, moved, or replaced" in disposition


def test_b3_points_at_the_drafted_changelog_entry_and_release_notes():
    [b3] = _table_rows(DECISION, r"B-3")
    disposition = b3[1]
    assert "CHANGELOG.md" in disposition
    assert "release-notes/v0.2.0-draft.md" in disposition


# --- Deferrals stay recorded as deferrals ----------------------------------


def test_pypi_timing_is_explicitly_decided_as_deferred():
    [pypi_row] = _table_rows(DECISION, r"PyPI \(wheel/sdist\)")
    decision, rationale = _normalized(pypi_row[1]), pypi_row[2]
    assert "deferred" in decision
    assert "not part of this release" in decision
    assert rationale.strip(), "the PyPI deferral records no reason"


def test_version_tagged_container_image_is_deferred_to_commit_sha_images():
    [image_row] = _table_rows(DECISION, r"Version-tagged container image \(`:v0\.2\.0`\)")
    decision = _normalized(image_row[1])
    assert "deferred" in decision
    assert "commit-sha-tagged images remain the current container distribution artifact" in decision


def test_github_release_is_recorded_as_sufficient_for_v0_2():
    [release_row] = _table_rows(DECISION, r"GitHub Release")
    assert "sufficient for v0.2" in _normalized(release_row[1])


def test_validation_depth_work_is_acknowledged_without_becoming_a_blocker():
    normalized = _normalized(DECISION)
    assert "hg-045" in normalized
    assert "future validation-depth work, not a release blocker" in normalized


# --- Repository metadata actions are exact and non-abandoning --------------


def test_metadata_actions_fix_the_topic_typo_and_leave_the_homepage_unset():
    metadata = DECISION[DECISION.index("### Repository metadata actions") :]
    assert "--remove-topic crypto-aglity" in metadata
    assert "--add-topic crypto-agility" in metadata
    for topic in ("cryptography-inventory", "post-quantum-cryptography", "pqc", "security-tools"):
        assert f"--add-topic {topic}" in metadata, f"the metadata action omits topic {topic}"
    normalized = _normalized(metadata)
    assert "leave the homepage url unset" in normalized
    assert "placeholder" in normalized
    # The topics name a subject area; they must not be read as a capability.
    assert "none of them claims a capability" in normalized


# --- The changelog entry is a draft while the version says 0.1.0 -----------


def test_changelog_drafts_an_unreleased_0_2_0_entry():
    assert "## 0.2.0" in CHANGELOG_TEXT
    heading = _draft_entry_heading()
    assert "drafted" in heading.lower() and "unreleased" in heading.lower(), heading

    unreleased = _plain(_section(CHANGELOG_TEXT, "## Unreleased"))
    assert "a draft for a release that has not happened" in unreleased
    assert f"the declared version is still `{__version__}`" in unreleased
    assert "no `v0.2.0` tag has been created" in unreleased
    assert "no github release has been published from any tag" in unreleased
    assert "no pypi, wheel, or sdist publication has been made" in unreleased
    assert "docs/release-notes/v0.2.0-draft.md" in unreleased


def test_drafted_entry_covers_the_work_the_release_would_describe():
    normalized = _normalized(_draft_entry())
    assert "hg-028" in normalized and "hg-044" in normalized
    assert "#115 through #119" in normalized
    milestone_markers = ("openssh", "kubernetes tls secret", "bcfks", "jceks", "age", "gocryptfs")
    for milestone_work in milestone_markers:
        assert milestone_work in normalized, f"the drafted entry omits {milestone_work}"
    first_use_markers = (
        "demo/sample_target",
        "docs/examples/first-run",
        "quickstart",
        "support.md",
    )
    for first_use_work in first_use_markers:
        assert first_use_work in normalized, f"the drafted entry omits {first_use_work}"
    assert "### known limitations" in normalized
    assert "not proof of absence" in normalized
    assert "hg-045" in normalized


def test_drafted_entry_does_not_claim_it_was_released():
    entry = _normalized(_draft_entry())
    assert "drafting this entry published nothing" in entry
    for falsehood in ("v0.2.0 has been released", "released on", "tagged as v0.2.0"):
        assert falsehood not in entry, f"the drafted entry falsely claims: {falsehood!r}"


# --- The release-notes draft is usable and marked as a draft ---------------


def test_release_notes_draft_exists_and_says_it_is_unpublished():
    normalized = _normalized(RELEASE_NOTES.read_text(encoding="utf-8"))
    assert "status: draft. not published." in normalized
    assert "no `v0.2.0` tag has been created" in normalized
    assert f"the declared version is still `{__version__}`" in normalized
    assert "nothing in this file publishes anything" in normalized


@pytest.mark.parametrize(
    "topic, heading",
    [
        ("what changed", "### What changed"),
        ("how to try it", "### How to try it"),
        ("the evidence-only boundary", "### What this release does not claim"),
        ("known limitations", "### Known limitations"),
        ("support expectations", "### Support"),
    ],
)
def test_release_notes_draft_covers_every_required_section(topic, heading):
    assert heading in RELEASE_NOTES.read_text(encoding="utf-8"), (
        f"the draft release notes do not cover {topic}"
    )


def test_release_notes_draft_states_the_evidence_only_boundary():
    normalized = _normalized(RELEASE_NOTES.read_text(encoding="utf-8"))
    assert "harvestguard is **evidence only**" in normalized
    for boundary in (
        "complete or exhaustive inventory",
        "absence of a finding proves absence",
        "runtime exposure or exploitability",
        "business risk",
        "compliance or audit conclusions",
        "remediation advice or remediation priority",
        "migration readiness or quantum readiness",
        "hndl (harvest now, decrypt later) exposure",
    ):
        assert boundary in normalized, f"the draft release notes do not disclaim {boundary!r}"


def test_release_notes_draft_promises_no_support_beyond_the_stated_channels():
    normalized = _normalized(RELEASE_NOTES.read_text(encoding="utf-8"))
    assert "no service-level" in normalized
    assert "support.md" in normalized
    assert "only `main` is supported" in normalized


def test_release_notes_draft_does_not_offer_a_pypi_install_or_version_tagged_image():
    normalized = _plain(RELEASE_NOTES.read_text(encoding="utf-8"))
    assert "not published to pypi" in normalized
    assert "pip install harvestguard" not in normalized, "that would imply a PyPI release"
    assert "harvestguard:v0.2.0" not in normalized, "no version-tagged image exists"
    assert "harvestguard:latest" not in normalized


# --- Support and advisory path ---------------------------------------------


def test_support_doc_states_channels_and_bounded_expectations():
    normalized = _normalized(SUPPORT.read_text(encoding="utf-8"))
    assert "github.com/serewicz/harvestguard/issues" in normalized
    assert "best effort" in normalized
    assert (
        "no paid support tier, service-level agreement, uptime commitment, hosted service, or "
        "guaranteed response time" in normalized
    )
    assert "no support promise beyond the channels" in normalized
    assert "only `main` is supported" in normalized
    # Security reports keep going to the private channel, not to a public issue.
    assert "security.md" in normalized
    assert "not a public issue" in normalized


def test_support_doc_states_the_advisory_path_and_keeps_it_separate():
    normalized = _normalized(SUPPORT.read_text(encoding="utf-8"))
    assert (
        "harvestguard is an open-source evidence collection tool. advisory work around "
        "cryptographic inventory, pqc planning, technology diligence, and executive reporting is "
        "available separately from timothy serewicz" in normalized
    )
    assert "not a support tier for the open-source project" in normalized
    assert "does not change what the tool detects" in normalized


@pytest.mark.parametrize(
    "detector_doc",
    [
        "docs/DETECTION_CHARACTERIZATION.md",
        "docs/CLAIMS_AUDIT.md",
        "docs/CRYPTO_INVENTORY.md",
        "docs/ASSET_INVENTORY.md",
        "docs/SCAN_COVERAGE.md",
        "docs/CLI.md",
    ],
)
def test_advisory_language_stays_out_of_the_detector_and_claims_docs(detector_doc):
    lowered = (ROOT / detector_doc).read_text(encoding="utf-8").lower()
    for salesy in ("advisory work", "available separately from timothy", "tim@serewicz.com"):
        assert salesy not in lowered, f"{detector_doc} carries commercial language: {salesy!r}"


def test_readme_points_at_support_and_the_distribution_decision():
    normalized = _normalized(README_TEXT)
    assert "[support.md](support.md)" in normalized
    assert "no service-level agreement" in normalized
    assert "not published to pypi" in normalized
    assert "release-and-distribution-decision-v02-preparation" in normalized
    # The advisory mention in the README stays a pointer, not a pitch.
    readme_support = _section(README_TEXT, "## Support")
    assert len(readme_support.split()) < 120, "the README support section has grown into a pitch"
    assert "tim@serewicz.com" not in readme_support.lower()


# --- Public-use boundary check across the new surfaces --------------------


@pytest.mark.parametrize(
    "surface",
    ["SUPPORT.md", "docs/release-notes/v0.2.0-draft.md", "CHANGELOG.md", "README.md"],
)
@pytest.mark.parametrize("assertion", FORBIDDEN_ASSERTIONS)
def test_release_surfaces_assert_no_out_of_boundary_conclusion(surface, assertion):
    normalized = _normalized((ROOT / surface).read_text(encoding="utf-8"))
    assert assertion not in normalized, f"{surface} asserts {assertion!r}"


@pytest.mark.parametrize("assertion", FORBIDDEN_ASSERTIONS)
def test_the_release_decision_asserts_no_out_of_boundary_conclusion(assertion):
    assert assertion not in _normalized(DECISION), f"the release decision asserts {assertion!r}"


# --- What the new documents point at actually exists ----------------------


@pytest.mark.parametrize(
    "document",
    ["SUPPORT.md", "docs/release-notes/v0.2.0-draft.md"],
)
def test_new_document_links_and_anchors_resolve(document):
    path = ROOT / document
    for target in _local_links(path.read_text(encoding="utf-8")):
        path_part, _, fragment = target.partition("#")
        resolved = path if not path_part else (path.parent / path_part).resolve()
        assert resolved.exists(), f"{document} links to a missing path: {target}"
        if fragment:
            markdown = resolved / "README.md" if resolved.is_dir() else resolved
            assert markdown.is_file(), f"{document} cannot resolve an anchor target: {target}"
            assert fragment in _anchors(markdown), f"{document} has a broken anchor: {target}"


def test_release_decision_links_and_anchors_resolve():
    for target in _local_links(DECISION):
        path_part, _, fragment = target.partition("#")
        document = RELEASE if not path_part else (RELEASE.parent / path_part).resolve()
        assert document.exists(), f"broken link target in the release decision: {target}"
        if fragment:
            markdown = document / "README.md" if document.is_dir() else document
            assert fragment in _anchors(markdown), (
                f"broken anchor in the release decision: {target}"
            )


def test_changelog_release_links_resolve():
    for target in _local_links(CHANGELOG_TEXT):
        path_part, _, fragment = target.partition("#")
        document = CHANGELOG if not path_part else (ROOT / path_part).resolve()
        assert document.exists(), f"CHANGELOG.md links to a missing path: {target}"
        if fragment:
            markdown = document / "README.md" if document.is_dir() else document
            assert fragment in _anchors(markdown), f"CHANGELOG.md has a broken anchor: {target}"
