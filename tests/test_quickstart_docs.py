"""Tests for the canonical README quickstart (GitHub issue #117).

The quickstart is the one documented run-review-export path a first-time user
follows: clone, install, `--summary`, `--json`, `--markdown` against
`demo/sample_target/`. These tests guard the properties that make it usable
without reading detector-contract documentation -- that the sequence is
complete, that it says where output is written, that it states the demo's
expected finding-level error record and the CLI exit semantics rather than
hiding them, and that the links and heading anchors it points at resolve.

Issue #134 turned the same section into an ordered first-time evaluation path,
so the tests below also guard the steps a reader needs before the demo makes
sense: how the CLI is installed (including the PEP 668 refusal Debian and
Ubuntu report, without recommending an override), how a missing `harvestguard`
on `PATH` is recovered, and how the validation harness is found and bounded.

The commands themselves are executed end to end by
tests/test_end_to_end_validation.py and tests/test_clean_install.py; these
tests deliberately run no subprocess.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
README = ROOT / "README.md"
README_TEXT = README.read_text()

DEMO_COMMAND = "harvestguard scan demo/sample_target --type all"


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
            r"^#{1,6}\s+(.+?)\s*$", markdown_path.read_text(), flags=re.MULTILINE
        )
    }


QUICKSTART = _section(README_TEXT, "## Quickstart")


def test_quickstart_documents_the_full_run_review_export_sequence():
    for command in (
        "git clone https://github.com/serewicz/HarvestGuard.git",
        "cd HarvestGuard",
        "python3 -m venv venv",
        "python -m pip install .",
        f"{DEMO_COMMAND} --summary",
        f"{DEMO_COMMAND} --json findings.json",
        f"{DEMO_COMMAND} --markdown report.md",
    ):
        assert command in QUICKSTART, f"quickstart is missing: {command}"


def test_quickstart_states_where_output_is_written():
    normalized = " ".join(QUICKSTART.split())
    assert "relative to the directory you run the command in" in normalized
    assert "findings.json" in normalized and "report.md" in normalized


def test_quickstart_states_json_and_markdown_are_separate_runs():
    normalized = " ".join(QUICKSTART.split())
    assert "cannot be combined" in normalized


def test_quickstart_states_exit_semantics_and_the_expected_demo_error_record():
    normalized = " ".join(QUICKSTART.split())
    # The demo scan exits 0 even though it reports one finding-level error.
    assert "exit `0`" in normalized
    assert "Exit `1`" in normalized and "exit `2`" in normalized
    assert "Errors: 1" in normalized
    assert "Malformed PEM Private Key" in normalized
    assert "Scanner execution errors: 0" in normalized


def test_quickstart_points_at_the_committed_sample_output():
    assert "docs/examples/first-run/" in QUICKSTART
    assert (ROOT / "docs" / "examples" / "first-run" / "sample-findings.json").is_file()
    assert (ROOT / "docs" / "examples" / "first-run" / "sample-report.md").is_file()


def test_quickstart_keeps_its_claims_bounded():
    normalized = " ".join(QUICKSTART.split()).lower()
    for disclaimed in (
        "exhaustive discovery",
        "runtime use",
        "exploitability",
        "business risk",
        "compliance",
        "remediation priority",
        "quantum readiness",
    ):
        assert disclaimed in normalized, f"quickstart no longer disclaims: {disclaimed}"


# --- The ordered evaluation path (issue #134) ------------------------------


EVALUATION_STEPS = [
    "### 1. Install the CLI",
    "### 2. Verify the installation",
    "### 3. Scan an authorized local path",
    "### 4. Try the safe repository demo",
    "### 5. Review sample evidence output",
    "### 6. Validate on your own Linux host",
    "### 7. Read the claims boundary",
]


def _code_blocks(markdown: str) -> list[str]:
    return re.findall(r"^```[a-z]*\n(.*?)^```", markdown, flags=re.DOTALL | re.MULTILINE)


@pytest.mark.parametrize("step", EVALUATION_STEPS)
def test_quickstart_keeps_the_ordered_evaluation_path(step):
    assert step in QUICKSTART, f"the evaluation path no longer has the step: {step}"
    # Each step is reachable from the list at the top of the section.
    assert f"(#{_anchor(step[len('### ') :])})" in QUICKSTART, f"{step} is not linked"


def test_quickstart_documents_pipx_installation_and_the_pep_668_refusal():
    normalized = " ".join(QUICKSTART.split())
    assert "pipx install harvestguard" in normalized
    assert "sudo apt install -y pipx" in normalized
    assert "error: externally-managed-environment" in normalized
    assert "pep 668" in normalized.lower()


def test_quickstart_never_recommends_overriding_the_managed_environment():
    for block in _code_blocks(QUICKSTART):
        assert "--break-system-packages" not in block, (
            "the quickstart offers a system-wide pip override as a runnable command"
        )
    normalized = " ".join(QUICKSTART.split())
    if "--break-system-packages" in normalized:
        assert "do not force a system-wide install with `--break-system-packages`" in normalized


def test_quickstart_documents_verification_and_path_recovery():
    normalized = " ".join(QUICKSTART.split())
    assert "harvestguard --version" in normalized
    assert "not on your `PATH`" in normalized
    assert "/root/.local/bin/harvestguard --version" in normalized
    assert 'export PATH="$PATH:/root/.local/bin"' in normalized
    assert "~/.local/bin/harvestguard" in normalized


def test_quickstart_documents_the_first_authorized_local_scan():
    normalized = " ".join(QUICKSTART.split())
    assert "harvestguard scan /path/to/project --type all --summary" in normalized
    assert "authorized to scan" in normalized


def test_quickstart_documents_the_linux_validation_commands():
    normalized = " ".join(QUICKSTART.split())
    for command in (
        "./validation/run-validation.sh --workspace /tmp/hg-validation",
        "./validation/run-validation.sh --dry-run --workspace /tmp/hg-validation-dry-run",
    ):
        assert command in normalized, f"the evaluation path is missing: {command}"
    assert (ROOT / "validation" / "run-validation.sh").is_file()


def test_quickstart_points_at_the_validation_and_generator_documentation():
    assert "(validation/README.md)" in QUICKSTART
    assert "(validation/generators/README.md)" in QUICKSTART


def test_quickstart_bounds_what_a_validation_run_demonstrates():
    normalized = " ".join(QUICKSTART.split())
    assert "not proof of complete format support" in normalized
    # No claim that unexercised platforms, scan types, or generators are covered.
    assert "that the run did not exercise" in normalized


def test_quickstart_keeps_absence_of_a_finding_from_reading_as_proof():
    normalized = " ".join(QUICKSTART.split()).lower()
    assert "absence of a finding is not proof of absence" in normalized


@pytest.mark.parametrize(
    "link", re.findall(r"\]\(([^)\s]+)\)", QUICKSTART) or ["<no links found>"]
)
def test_quickstart_links_and_anchors_resolve(link):
    assert link != "<no links found>"
    if link.startswith(("http://", "https://", "mailto:")):
        pytest.skip("external link; not resolved offline")

    target, _, anchor = link.partition("#")
    path = README.parent / target if target else README
    assert path.exists(), f"quickstart links to a missing path: {link}"

    if anchor:
        markdown = path / "README.md" if path.is_dir() else path
        assert markdown.is_file(), f"cannot resolve anchor target for: {link}"
        assert anchor in _anchors(markdown), f"quickstart anchor does not exist: {link}"
