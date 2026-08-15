"""Checks for the committed first-run sample output (GitHub issue #116).

`docs/examples/first-run/` publishes real CLI output so a prospective user can
see HarvestGuard's evidence shape before installing anything. Because those
files are published, they have to stay (a) parseable and consistent with the
normalized finding contract the CLI actually emits, (b) free of secrets and of
user-specific absolute paths, and (c) free of the conclusions HarvestGuard
deliberately does not draw.

The regeneration test re-runs the documented commands through
`docs/examples/first-run/generate_samples.py` and compares the host-independent
portion of live output against the committed files, so a scanner or report
change that silently invalidates the samples fails here instead of shipping.
"""

from __future__ import annotations

import importlib.util
import json
from dataclasses import fields as dataclass_fields
from pathlib import Path

import pytest

from findings import SCHEMA_VERSION, NormalizedFinding
from harvestguard_version import __version__

ROOT = Path(__file__).parent.parent
EXAMPLES_DIR = ROOT / "docs" / "examples" / "first-run"
JSON_SAMPLE = EXAMPLES_DIR / "sample-findings.json"
MARKDOWN_SAMPLE = EXAMPLES_DIR / "sample-report.md"
EXAMPLES_README = EXAMPLES_DIR / "README.md"
GENERATOR = EXAMPLES_DIR / "generate_samples.py"

DEMO_MANIFEST = ROOT / "demo" / "sample_target" / "README.md"


def _load_generator():
    """Import generate_samples.py by path -- docs/ is not an importable package."""
    spec = importlib.util.spec_from_file_location("first_run_generate_samples", GENERATOR)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def sample_findings() -> list[dict]:
    return json.loads(JSON_SAMPLE.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def sample_markdown() -> str:
    return MARKDOWN_SAMPLE.read_text(encoding="utf-8")


# --- The samples exist and are what they claim to be ----------------------


def test_sample_files_exist():
    assert JSON_SAMPLE.is_file()
    assert MARKDOWN_SAMPLE.is_file()
    assert EXAMPLES_README.is_file()
    assert GENERATOR.is_file()


def test_json_sample_parses_and_holds_the_demo_corpus_records(sample_findings):
    assert isinstance(sample_findings, list)
    # Five normalized records from three scanners, exactly as the demo
    # walkthrough in docs/CLI.md describes.
    assert len(sample_findings) == 5
    assert {f["scanner_name"] for f in sample_findings} == {
        "crypto_inventory",
        "filesystem",
        "sensitive_data_classifier",
    }
    assert all(f["location"].startswith(("demo/sample_target", "/")) for f in sample_findings)


def test_json_sample_matches_the_normalized_finding_contract(sample_findings):
    """Every record carries exactly the fields NormalizedFinding serializes."""
    expected = {f.name for f in dataclass_fields(NormalizedFinding)} | {"provenance"}
    for finding in sample_findings:
        assert set(finding) == expected, finding["location"]
        assert finding["schema_version"] == SCHEMA_VERSION
        assert finding["scanner_version"] == __version__
        # The nested provenance block still mirrors the flat fields.
        assert finding["provenance"]["scanner_name"] == finding["scanner_name"]
        assert finding["provenance"]["rule_id"] == finding["rule_id"]


def test_markdown_sample_is_recognizable_harvestguard_evidence_output(sample_markdown):
    assert sample_markdown.startswith("# HarvestGuard Scan Report")
    for section in (
        "## Executive Summary",
        "## Scan Information",
        "## Scope",
        "## Detailed Findings",
        "## Known Limitations",
    ):
        assert section in sample_markdown
    assert f"| HarvestGuard Version | {__version__} |" in sample_markdown
    assert "| Target Path | demo/sample_target |" in sample_markdown


def test_markdown_sample_states_its_coverage_limitations(sample_markdown):
    assert "absence of a finding is not proof of absence" in sample_markdown.lower()
    assert "observed evidence, not business risk conclusions" in sample_markdown.lower()
    assert "categories and counts only" in sample_markdown.lower()


# --- Privacy: nothing published here may leak fixture or user material ----


def test_samples_contain_no_secret_or_key_material():
    forbidden = (
        # The demo key's published passphrase, and the fixture's fake secret
        # value: HarvestGuard reports categories and counts, never values.
        "harvestguard-demo",
        "FAKE-DEMO-PASSWORD-VALUE-0000000000",
        "-----BEGIN",
        "PRIVATE KEY-----",
    )
    for path in (JSON_SAMPLE, MARKDOWN_SAMPLE):
        text = path.read_text(encoding="utf-8")
        for needle in forbidden:
            assert needle not in text, f"{path.name} leaks {needle!r}"


def test_samples_contain_no_encoded_fixture_material():
    """No base64 body line from either demo .pem reaches the samples."""
    published = "\n".join(
        p.read_text(encoding="utf-8") for p in (JSON_SAMPLE, MARKDOWN_SAMPLE)
    )
    for fixture in sorted((ROOT / "demo" / "sample_target" / "crypto").glob("*.pem")):
        body = [
            line.strip()
            for line in fixture.read_text(encoding="utf-8").splitlines()
            if len(line.strip()) >= 40 and "-----" not in line and " " not in line.strip()
        ]
        assert body, f"expected encoded lines in {fixture.name}"
        for line in body:
            assert line not in published, f"{fixture.name} material leaked into the samples"


def test_samples_contain_no_user_specific_absolute_paths():
    for path in (JSON_SAMPLE, MARKDOWN_SAMPLE):
        text = path.read_text(encoding="utf-8")
        assert str(ROOT) not in text
        for prefix in ("/home/", "/Users/", "/root/", "C:\\"):
            assert prefix not in text, f"{path.name} contains an absolute path ({prefix})"


BANNED_CONCLUSION_TERMS = (
    "risk score",
    "hndl",
    "remediat",
    "recommend",
    "quantum-safe",
    "compliant",
    "readiness",
)


def test_json_sample_draws_no_conclusions_harvestguard_does_not_make():
    """Evidence only: no risk score, HNDL rating, or remediation advice."""
    text = JSON_SAMPLE.read_text(encoding="utf-8").lower()
    for needle in BANNED_CONCLUSION_TERMS:
        assert needle not in text, f"{JSON_SAMPLE.name} contains {needle!r}"


def test_markdown_findings_draw_no_conclusions_harvestguard_does_not_make(sample_markdown):
    """The evidence records themselves stay free of interpretation.

    The report's own *Known Limitations* section names these terms on purpose
    (to disclaim them), so the ban applies to the findings, not to the whole
    document -- and the disclaimer itself is asserted below.
    """
    body = sample_markdown.lower()
    detailed = body.split("## detailed findings", 1)[1].split("## errors and warnings", 1)[0]
    for needle in BANNED_CONCLUSION_TERMS:
        assert needle not in detailed, f"{MARKDOWN_SAMPLE.name} findings contain {needle!r}"
    assert "does not infer business risk" in body
    assert (
        "no risk scores, executive priority, remediation recommendations, or ownership "
        "inference are included" in body
    )


# --- Provenance: a reader can identify input, command, and version --------


def test_examples_readme_documents_input_command_and_version():
    readme = EXAMPLES_README.read_text(encoding="utf-8")
    assert "demo/sample_target" in readme
    assert "harvestguard scan demo/sample_target --type all" in readme
    assert "--json" in readme and "--markdown" in readme
    assert f"harvestguard {__version__}" in readme
    assert "generate_samples.py" in readme
    # The samples are illustrative output, not a claim about anyone's estate.
    # Compare against a line-wrap-insensitive copy: these are prose sentences.
    lowered = " ".join(readme.lower().split())
    assert "not a certification" in lowered
    assert "a statement of exhaustive coverage" in lowered
    assert "absence of a finding is not proof of absence" in lowered
    # Volatile-value handling is documented rather than silent.
    for placeholder in ("00000000-0000-0000-0000-000000000000", "1970-01-01T00:00:00+00:00"):
        assert placeholder in readme


def test_documented_placeholders_are_the_ones_actually_used(sample_findings, sample_markdown):
    generator = _load_generator()
    for finding in sample_findings:
        assert finding["scan_id"] == generator.PLACEHOLDER_SCAN_ID
        assert finding["observed_at"] == generator.PLACEHOLDER_TIMESTAMP
        assert finding["provenance"]["collected_at"] == generator.PLACEHOLDER_TIMESTAMP
    assert f"| Scan ID | {generator.PLACEHOLDER_SCAN_ID} |" in sample_markdown
    assert f"| Duration | {generator.PLACEHOLDER_DURATION} |" in sample_markdown


def test_demo_manifest_still_describes_the_corpus_the_samples_came_from():
    """The samples are only reproducible while the demo corpus is unchanged."""
    manifest = DEMO_MANIFEST.read_text(encoding="utf-8")
    for name in ("leaked_config.env", "demo_tls_certificate.pem", "demo_encrypted_private_key.pem"):
        assert name in manifest
        assert list((ROOT / "demo" / "sample_target").rglob(name))


def test_markdown_normalization_covers_observed_at_cells_that_differ_from_scan_time():
    """A finding's timestamp and the report's Scan Time can differ by a second.

    Normalizing by column rather than by matching the scan-time literal keeps
    the committed sample stable in that case, and still leaves a parsed
    certificate `Expiration` -- a different column -- untouched.
    """
    generator = _load_generator()
    report = "\n".join(
        [
            "| Field | Value |",
            "| --- | --- |",
            "| Scan Time | 2026-08-15T04:37:34+00:00 |",
            "",
            "| Location | Observed At | Expiration |",
            "| --- | --- | --- |",
            "| demo/sample_target/x.pem | 2026-08-15T04:37:33+00:00 | 2126-07-22T03:50:24+00:00 |",
            "",
        ]
    )
    normalized = generator.normalize_markdown(report)
    assert "2026-08-15" not in normalized
    assert normalized.count(generator.PLACEHOLDER_TIMESTAMP) == 2
    assert "2126-07-22T03:50:24+00:00" in normalized


# --- Regeneration: the committed samples still match live CLI output ------


def _host_independent(findings: list[dict]) -> list[dict]:
    """Drop the one record whose content legitimately varies by host.

    The aggregate filesystem context record reports volume-level encryption
    status for the mount the corpus sits on, which is platform-dependent by
    design (docs/CLI.md, "What varies by host").
    """
    return [f for f in findings if f["source_type"] != "local_filesystem"]


def _host_independent_lines(markdown: str) -> list[str]:
    """Drop every Markdown line whose presence or content is a deterministic
    function of the platform's aggregate filesystem context record, rather
    than of the demo corpus itself.

    On a supported platform where volume-level encryption status cannot be
    determined (docs/CLI.md, "What varies by host"), the aggregate context
    finding's `rule_id` becomes `volume_status:unknown` and it gains a
    recorded limitation. That single host-dependent fact ripples through
    several places in the rendered report beyond the detailed-findings row
    already filtered here:

    - the `| Coverage |` Scan Information row switches from
      "Bounded by configured scan scope" to "Not complete";
    - a "Coverage was not complete: ..." paragraph is inserted before
      "## Scan Information", bracketed by a blank line on each side that
      collapses back to the single blank line the no-coverage-statement
      report has once the paragraph itself is dropped;
    - "## Errors and Warnings" gains an "N finding(s) record limitations..."
      bullet and a nested "`volume_status:...`" count line.

    None of this hides the host-dependent evidence itself: the aggregate
    context *finding* -- and its one detailed-findings row -- stays in the
    compared output on every platform, unfiltered and unnormalized. Only this
    deterministically *derived* report text, which is truthful on each
    platform but not identical across them, is left unasserted here.
    """
    lines = markdown.splitlines()
    kept: list[str] = []
    drop_next_if_blank = False
    for line in lines:
        if drop_next_if_blank:
            drop_next_if_blank = False
            if line == "":
                continue
        if "Volume-level encryption status" in line or "for mount" in line:
            continue
        if line.startswith("| Coverage |"):
            continue
        if line.startswith("Coverage was not complete:"):
            drop_next_if_blank = True
            continue
        if "finding(s) record limitations on what could be observed or traversed" in line:
            continue
        if line.startswith("  - `volume_status:"):
            continue
        kept.append(line)
    return kept


def test_host_independent_lines_normalizes_unknown_volume_status_secondary_text():
    """`_host_independent_lines` must reduce a report generated on a platform
    where volume status is Unknown to the same lines as a report generated on
    a platform where it is concretely observed -- not merely swap the
    detailed-findings row, but also the Coverage field, the "Coverage was not
    complete" paragraph, and the Errors and Warnings limitation bullets that
    a recorded limitation on the aggregate context finding adds.

    Both fragments below are otherwise-identical minimal reports; only the
    text `reports.py`/`scanner/filesystem.py` actually produce for a known
    versus an Unknown volume status differs between them, so this test fails
    again if a future secondary difference is left unaccounted for.
    """
    known_status = "\n".join(
        [
            "# HarvestGuard Scan Report",
            "",
            "## Executive Summary",
            "",
            "HarvestGuard inspected 4 regular file(s).",
            "",
            "The report summarizes observed evidence only. It does not infer business risk.",
            "",
            "## Scan Information",
            "",
            "| Field | Value |",
            "| --- | --- |",
            "| Excluded Paths | None |",
            "| Coverage | Bounded by configured scan scope |",
            "",
            "## Detailed Findings",
            "",
            "### volume",
            "",
            "| Location | Confidence | Observed Evidence |",
            "| --- | --- | --- |",
            "| / | Medium | Volume-level encryption status observed for mount /: "
            "Unencrypted (the platform reported the volume is not encrypted). "
            "4 regular file(s) represented. |",
            "",
            "## Errors and Warnings",
            "",
            "- Finding-level errors are listed in Detailed Findings.",
            "",
            "## Known Limitations",
            "",
        ]
    )
    unknown_status = "\n".join(
        [
            "# HarvestGuard Scan Report",
            "",
            "## Executive Summary",
            "",
            "HarvestGuard inspected 4 regular file(s).",
            "",
            "The report summarizes observed evidence only. It does not infer business risk.",
            "",
            "Coverage was not complete: this scan recorded 1 finding(s) with recorded "
            "limitations. Absence of a finding is not evidence that an asset was inspected "
            "and found clean; see Errors and Warnings and each finding's `limitations` field.",
            "",
            "## Scan Information",
            "",
            "| Field | Value |",
            "| --- | --- |",
            "| Excluded Paths | None |",
            "| Coverage | Not complete |",
            "",
            "## Detailed Findings",
            "",
            "### volume",
            "",
            "| Location | Confidence | Observed Evidence |",
            "| --- | --- | --- |",
            "| / | Low | Volume-level encryption status could not be determined for mount "
            "/; it is recorded as Unknown, which is not an observation that the volume is "
            "unencrypted. 4 regular file(s) represented. |",
            "",
            "## Errors and Warnings",
            "",
            "- Finding-level errors are listed in Detailed Findings.",
            "- 1 finding(s) record limitations on what could be observed or traversed; each "
            "is listed with its limitations in Detailed Findings. Coverage limitations by "
            "type:",
            "  - `volume_status:unknown`: 1",
            "",
            "## Known Limitations",
            "",
        ]
    )

    normalized_known = _host_independent_lines(known_status)
    normalized_unknown = _host_independent_lines(unknown_status)

    assert normalized_known == normalized_unknown
    # And the fix must not have collapsed the two inputs down to nothing --
    # this asserts on genuinely differing input, not a vacuous filter.
    assert known_status != unknown_status
    assert normalized_unknown  # non-empty: real structure survived the filter


def test_regenerating_the_samples_reproduces_the_committed_files(sample_findings, sample_markdown):
    generator = _load_generator()
    live_json, live_markdown = generator.generate()

    live_findings = json.loads(live_json)
    assert _host_independent(live_findings) == _host_independent(sample_findings)

    # The host-dependent record must still be present and structurally intact,
    # even though its values are not asserted.
    live_context = [f for f in live_findings if f["source_type"] == "local_filesystem"]
    assert len(live_context) == 1
    assert live_context[0]["asset_type"] == "volume"
    assert live_context[0]["technical_metadata"]["Files Represented By This Context"] == 4

    assert _host_independent_lines(live_markdown) == _host_independent_lines(sample_markdown)
