"""Release identity and reproducibility coverage (roadmap HG-011).

These tests protect the properties a controlled-pilot reviewer depends on:
that HarvestGuard states one version everywhere, that a shared evidence
artifact names the release that produced it, that adding version identity did
not put an envelope around the JSON contract, and that release documentation
does not claim a release that has not been cut.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

import harvestguard
from harvestguard_version import __version__, version_string
from reports import format_markdown_report, make_report_context

ROOT = Path(__file__).parent.parent
PYPROJECT = (ROOT / "pyproject.toml").read_text()
CHANGELOG = (ROOT / "CHANGELOG.md").read_text()
RELEASE = (ROOT / "docs" / "RELEASE.md").read_text()
ROADMAP = (ROOT / "docs" / "ROADMAP.md").read_text()
CRYPTO_FIXTURES = ROOT / "tests" / "fixtures" / "crypto_inventory"


# --- One version, declared in the two places that must agree ---------------


def test_pyproject_version_matches_the_runtime_version_constant():
    # setuptools reads pyproject's literal at build time and the CLI reads the
    # module constant at run time, so a drift would mean `pip show harvestguard`
    # and `harvestguard --version` disagree about the same install.
    match = re.search(r'^version\s*=\s*"([^"]+)"', PYPROJECT, re.MULTILINE)
    assert match is not None, "pyproject.toml has no [project] version literal"
    assert match.group(1) == __version__


def test_version_is_a_release_identifier_not_a_placeholder():
    assert re.fullmatch(r"\d+\.\d+\.\d+", __version__), __version__
    assert version_string() == f"harvestguard {__version__}"


# --- CLI exposes version identity without reading source files -------------


@pytest.mark.parametrize("flag", ["--version", "-V"])
def test_cli_version_flag_prints_the_version_and_exits_zero(flag, capsys):
    with pytest.raises(SystemExit) as exit_info:
        harvestguard.main([flag])

    assert exit_info.value.code == 0
    assert capsys.readouterr().out.strip() == f"harvestguard {__version__}"


def test_documented_module_invocation_reports_the_version():
    # docs/CLI.md tells an uninstalled user to run `python -m harvestguard`;
    # the version path has to work there too, not only via the console script.
    result = subprocess.run(
        [sys.executable, "-m", "harvestguard", "--version"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == f"harvestguard {__version__}"


# --- A Markdown artifact names the release that produced it ----------------


def test_markdown_report_records_the_producing_harvestguard_version():
    report = format_markdown_report([], make_report_context(target_path="/scan/root"))

    assert f"| HarvestGuard Version | {__version__} |" in report
    # The report's own generator/format version stays a separate row: it
    # describes the document shape, not the release of the tool.
    assert "| Report Generator | harvestguard-report" in report


def test_report_version_identity_survives_a_real_scan(tmp_path):
    report_path = tmp_path / "report.md"
    exit_code = harvestguard.main(
        [
            "scan",
            str(CRYPTO_FIXTURES),
            "--type",
            "crypto",
            "--markdown",
            str(report_path),
            "--quiet",
        ]
    )

    assert exit_code == 0
    assert f"| HarvestGuard Version | {__version__} |" in report_path.read_text()


# --- Version identity did not change the JSON contract ---------------------


def test_json_output_remains_a_bare_finding_array_with_no_report_envelope(tmp_path):
    findings_path = tmp_path / "findings.json"
    exit_code = harvestguard.main(
        [
            "scan",
            str(CRYPTO_FIXTURES),
            "--type",
            "crypto",
            "--json",
            str(findings_path),
            "--quiet",
        ]
    )

    payload = json.loads(findings_path.read_text())

    assert exit_code == 0
    assert isinstance(payload, list), "HG-007's JSON contract is a bare array"
    assert payload, "expected the crypto fixtures to produce findings"
    for record in payload:
        # No envelope keys smuggled in alongside the findings, and no product
        # version stamped onto a finding: provenance stays per scanner.
        assert "harvestguard_version" not in record
        assert record["schema_version"]
        assert record["provenance"]["scanner_version"]


# --- Release documentation exists and says what a pilot user needs ---------


def test_changelog_documents_the_current_version():
    assert f"## {__version__}" in CHANGELOG


@pytest.mark.parametrize(
    "topic, marker",
    [
        ("supported capabilities", "what v0.1 supports"),
        ("known limitations", "known limitations"),
        ("privacy/security expectations", "privacy and security expectations"),
        ("deferred work", "deferred to a later release"),
    ],
)
def test_release_notes_cover_the_controlled_pilot_topics(topic, marker):
    assert marker in CHANGELOG.lower(), f"CHANGELOG.md does not cover {topic}"


@pytest.mark.parametrize(
    "topic, marker",
    [
        ("source artifacts", "### source"),
        ("package artifacts", "### python package"),
        ("container artifacts", "### container artifacts"),
        ("pre-1.0 support status", "pre-1.0 status and support"),
        ("release procedure", "release procedure"),
        ("artifact version identity", "identifying the version that produced an artifact"),
    ],
)
def test_release_doc_covers_reproducibility_and_status_topics(topic, marker):
    assert marker in RELEASE.lower(), f"docs/RELEASE.md does not cover {topic}"


def test_release_doc_does_not_overstate_pinning_or_provenance():
    lowered = RELEASE.lower()
    # The repository has no lock file and no hash-pinned requirements, and the
    # container workflow signs + attests an SBOM but produces no SLSA
    # provenance attestation. Release docs must not imply otherwise.
    assert "not bit-for-bit reproducible" in lowered or "is *identified*" in lowered
    assert "does not produce a slsa provenance attestation" in lowered
    assert (ROOT / "requirements.txt").read_text().count("--hash=") == 0


# --- The release is not claimed before its dependencies close --------------


def _roadmap_entry_status(hg_id: str) -> str:
    match = re.search(rf"### {hg_id}\n.*?\n- \*\*Status:\*\* ([^\n]+)", ROADMAP, re.DOTALL)
    assert match is not None, f"could not find a Status field for {hg_id}"
    return match.group(1).strip()


def test_hg_008_009_010_are_complete():
    # These are closure-reviewed and merged; the roadmap must say so rather
    # than continuing to gate release readiness on stale dependency status.
    for hg_id in ("HG-008", "HG-009", "HG-010"):
        assert _roadmap_entry_status(hg_id) == "Complete", (
            f"{hg_id} is closure-reviewed and merged; docs/ROADMAP.md should read Complete"
        )


def test_hg_011_remains_needs_validation_during_this_pr():
    # HG-011 (this release-identity work) closes only after its own PR
    # receives independent closure review and merges -- not automatically
    # once its dependencies (HG-008/009/010) read Complete.
    assert _roadmap_entry_status("HG-011") == "Needs Validation"


def test_release_is_not_claimed_while_hg_011_itself_is_open():
    # The tag gate is HG-011's own status, not merely its dependencies: every
    # one of HG-008/009/010 can be Complete while the tag is still correctly
    # uncut, because tagging is a human decision made only once HG-011's own
    # implementation and PR close. When HG-011 itself reads Complete, this
    # test is the reminder that the release docs -- not just the roadmap --
    # must be updated to record the cut release.
    if _roadmap_entry_status("HG-011") != "Complete":
        assert "has not been cut" in RELEASE, (
            "docs/RELEASE.md claims a release while HG-011 remains open"
        )
        assert "not yet tagged" in CHANGELOG.lower()
    else:
        assert "has not been cut" not in RELEASE, (
            "HG-011 is Complete; docs/RELEASE.md and CHANGELOG.md should "
            "record the cut release rather than a candidate"
        )


def test_release_materials_do_not_claim_the_tag_already_exists():
    lowered_release = RELEASE.lower()
    lowered_changelog = CHANGELOG.lower()
    for forbidden in (
        "tag has been cut",
        "tag has been created",
        "tag has been pushed",
        "tagged as v0.1.0",
        "v0.1.0 has been released",
    ):
        assert forbidden not in lowered_release, f"docs/RELEASE.md falsely claims: {forbidden!r}"
        assert forbidden not in lowered_changelog, f"CHANGELOG.md falsely claims: {forbidden!r}"
    assert "not yet tagged" in lowered_changelog
    assert "has not been cut" in lowered_release


def test_release_candidate_language_blames_pending_human_review_not_hg_010():
    # The blocker this test guards against: release docs previously cited a
    # stale "HG-010 is still Needs Validation, pending its closure review"
    # reason for the untagged release. HG-010 is Complete now and may still
    # be *mentioned* as such, but the untagged-release reasoning itself must
    # cite HG-011's own pending independent closure review, not HG-010.
    lowered_changelog = CHANGELOG.lower()
    for stale in (
        "hg-010 (product claims and trust audit)\nis still",
        "hg-010 remains `needs validation`",
        "hg-010 is still `needs validation`",
    ):
        assert stale not in lowered_changelog, f"CHANGELOG.md still blames HG-010: {stale!r}"
    assert "hg-010" not in RELEASE.lower().split("## release readiness gate")[0]

    gate_section = RELEASE[RELEASE.index("## Release readiness gate") :]
    assert "hg-011" in gate_section.lower()
    assert (
        "human release decision" in gate_section.lower()
        or "independent closure review" in gate_section.lower()
    )
