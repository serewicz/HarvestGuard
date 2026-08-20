"""Tests for the executive validation summary (GitHub issue #133).

The summary is a plain-language account of the committed Phase 1 validation
evidence, aimed at a reader who will not open the reports or transcripts. That
audience makes two properties worth guarding: every artifact it points at must
actually exist, and the disclosures that keep it honest -- the environments
really used, the skipped generator, the single scan type, the halted pandas 3.x
run tracked in #140, and the boundary of what the evidence does not establish --
must survive later edits.

These tests read documentation only; they run no scanner, no harness, and no
subprocess.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).parent.parent
SUMMARY = ROOT / "validation" / "reports" / "executive-validation-summary.md"
SUMMARY_TEXT = SUMMARY.read_text()
NORMALIZED = " ".join(SUMMARY_TEXT.split())

VALIDATION_README = ROOT / "validation" / "README.md"
EXAMPLES_README = ROOT / "validation" / "examples" / "README.md"

LOCAL_LINK = re.compile(r"\[[^\]]+\]\((?!https?:)([^)#]+)(?:#[^)]*)?\)")


def _local_link_targets(document: Path) -> list[Path]:
    return [
        (document.parent / target).resolve()
        for target in LOCAL_LINK.findall(document.read_text())
    ]


def test_every_local_link_in_the_summary_resolves():
    missing = [str(target) for target in _local_link_targets(SUMMARY) if not target.exists()]
    assert missing == [], f"executive validation summary links to missing paths: {missing}"


def test_the_summary_links_the_source_artifacts_it_summarizes():
    linked = {target.name for target in _local_link_targets(SUMMARY)}
    for artifact in [
        "README.md",  # the examples index and the transcript sanitization guidance
        "2026-08-18-ubuntu-24.04-phase1.md",
        "2026-08-18-almalinux-9.8-phase1.md",
        "2026-08-18-almalinux-9.8-phase1.txt",
        "2026-08-18-almalinux-9.8-phase1-halted-run.txt",
    ]:
        assert artifact in linked, f"summary no longer links {artifact}"


def test_the_summary_is_discoverable_from_the_validation_docs():
    for index in [VALIDATION_README, EXAMPLES_README]:
        assert "executive-validation-summary.md" in index.read_text(), (
            f"{index.relative_to(ROOT)} no longer links the executive validation summary"
        )


def test_the_summary_answers_every_required_question():
    for heading in [
        "## 1. What was validated",
        "## 2. Where and how it was validated",
        "## 3. What evidence was produced",
        "## 4. What passed",
        "## 5. What was skipped, and why",
        "## 6. What failed or halted",
        "## 7. What remains unknown or unvalidated",
        "## 8. What should happen next",
    ]:
        assert heading in SUMMARY_TEXT, f"summary is missing the section {heading!r}"


def test_the_summary_keeps_the_evidence_layers_distinct():
    # Blending an inference or an outcome into an observed fact is the specific
    # failure mode this document exists to avoid, so the layers are named.
    for layer in [
        "Observed fact",
        "Scanner inference",
        "Validation outcome",
        "business interpretation",
        "Recommended next action",
    ]:
        assert layer in SUMMARY_TEXT, f"summary no longer names the {layer!r} evidence layer"


def test_the_summary_states_the_actual_validation_environments():
    # Ubuntu 24.04.4 in a Hyper-V VM and AlmaLinux 9.8 in an OCI container --
    # neither is Debian stable, WSL, RHEL, Rocky Linux, or CentOS Stream.
    assert "Ubuntu 24.04.4 LTS" in SUMMARY_TEXT
    assert "Hyper-V" in SUMMARY_TEXT
    assert "AlmaLinux 9.8" in SUMMARY_TEXT
    assert "OCI container" in SUMMARY_TEXT
    assert "not Debian stable, not WSL, not a container" in NORMALIZED
    assert "not RHEL, Rocky Linux, or CentOS Stream" in NORMALIZED


def test_the_summary_discloses_that_ubuntu_has_no_committed_transcript():
    assert "No transcript is committed for the Ubuntu run" in NORMALIZED


def test_the_summary_discloses_the_pandas_situation_without_concealing_it():
    assert "pandas below 3.0" in NORMALIZED
    assert "operator preparation" in NORMALIZED
    assert "pandas 3.x" in NORMALIZED
    assert "halted" in NORMALIZED.lower()
    assert "issues/140" in SUMMARY_TEXT, "the pandas 3.x defect must still point at #140"


def test_the_summary_discloses_the_skipped_generator_and_single_scan_type():
    assert "age_encrypted" in SUMMARY_TEXT
    assert "age is not installed" in SUMMARY_TEXT
    assert "--type crypto" in SUMMARY_TEXT


def test_the_summary_discloses_the_unvalidated_configurations():
    lowered = NORMALIZED.lower()
    for unvalidated in ["x86_64", "fips", "windows", "wsl", "aarch64"]:
        assert unvalidated in lowered, f"summary no longer discloses {unvalidated!r} as a boundary"


def test_the_summary_makes_no_unsupported_product_claim():
    # Each of these appears in the document only inside its explicit
    # not-established sentence, so the claim boundary is checked as asserting
    # phrasing rather than as a blanket word ban.
    lowered = NORMALIZED.lower()
    for forbidden in [
        "production ready",
        "production-ready",
        "is compliant",
        "quantum ready",
        "quantum-ready",
        "complete inventory of",
        "supports windows",
        "wsl support",
        "no cryptographic material",
        "business risk is",
        "remediation priority:",
    ]:
        assert forbidden not in lowered, f"summary unexpectedly claims {forbidden!r}"

    # The disclaimers themselves are stronger than silence and must remain.
    assert "establish nothing about" in lowered
    assert "complete real-world validation" in lowered
