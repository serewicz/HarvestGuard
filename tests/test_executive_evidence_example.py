"""Checks for the executive-readable evidence example (GitHub issue #118).

`docs/examples/executive-evidence-example.md` translates one committed demo
finding for an executive reader. Because it is published prose *about* machine
output, two things can silently rot: the technical fields it quotes can drift
away from the committed sample they came from, and the four layers it separates
(observed fact, scanner inference, business interpretation, human action) can
blur back together into a single claim. Both are checked here.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
EXAMPLE = ROOT / "docs" / "examples" / "executive-evidence-example.md"
JSON_SAMPLE = ROOT / "docs" / "examples" / "first-run" / "sample-findings.json"
MARKDOWN_SAMPLE = ROOT / "docs" / "examples" / "first-run" / "sample-report.md"
DELIVERABLES = ROOT / "docs" / "EXECUTIVE_DELIVERABLES.md"

SELECTED_FINDING_ID = "487b32de02b9c6c99c5c504604848195346df5a7c2e33e511bc1baf1a8519fff"

LAYER_HEADINGS = (
    "## Layer 1 — Observed fact",
    "## Layer 2 — Scanner inference",
    "## Layer 3 — Business interpretation *(human reviewer — not HarvestGuard)*",
    "## Layer 4 — Recommended human action *(human reviewer — not HarvestGuard)*",
)

READER_QUESTIONS = (
    "**What was found?**",
    "**Where was it found?**",
    "**How was it found?**",
    "**Why might it matter?**",
    "**What should happen next?**",
)


@pytest.fixture(scope="module")
def example() -> str:
    return EXAMPLE.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def selected_finding() -> dict:
    findings = json.loads(JSON_SAMPLE.read_text(encoding="utf-8"))
    matches = [f for f in findings if f["finding_id"] == SELECTED_FINDING_ID]
    assert len(matches) == 1, "the example's finding is no longer in the committed sample"
    return matches[0]


def _section(example: str, heading: str) -> str:
    """The body of one layer, up to the next `## ` heading."""
    assert heading in example, heading
    body = example.split(heading, 1)[1]
    return body.split("\n## ", 1)[0]


def _flat(text: str) -> str:
    """Line-wrap-insensitive copy: these assertions are about prose, not layout."""
    return " ".join(text.split())


# --- The example exists, is discoverable, and its links resolve -----------


def test_example_exists_and_is_linked_for_discoverability():
    assert EXAMPLE.is_file()
    assert "examples/executive-evidence-example.md" in DELIVERABLES.read_text(encoding="utf-8")


def test_relative_links_resolve(example):
    targets = re.findall(r"\]\(([^)]+)\)", example)
    assert targets
    for target in targets:
        assert not target.startswith(("http://", "https://")), target
        path, _, anchor = target.partition("#")
        if not path:
            continue  # same-document anchor
        resolved = (EXAMPLE.parent / path).resolve()
        assert resolved.exists(), f"broken link: {target}"
        if anchor:
            headings = {
                re.sub(r"[^a-z0-9 -]", "", line.lstrip("# ").lower()).replace(" ", "-")
                for line in resolved.read_text(encoding="utf-8").splitlines()
                if line.startswith("#")
            }
            assert anchor in headings, f"broken anchor: {target}"


# --- Traceability: every technical field matches the committed sample -----


def test_the_example_names_the_committed_finding_it_translates(example, selected_finding):
    assert SELECTED_FINDING_ID in example
    assert "sample-findings.json" in example
    assert "sample-report.md" in example
    # The same record is visible in the committed Markdown report, which is
    # what a reader following the link back will actually see.
    assert selected_finding["location"] in MARKDOWN_SAMPLE.read_text(encoding="utf-8")


def _quoted_field_table(example: str) -> dict[str, str]:
    rows = {}
    for line in _section(example, LAYER_HEADINGS[0]).splitlines():
        if not line.startswith("| `"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        rows[cells[0]] = cells[1]
    return rows


def test_every_quoted_technical_field_matches_the_committed_sample(example, selected_finding):
    table = _quoted_field_table(example)
    metadata = selected_finding["technical_metadata"]

    expected = {
        "`location`": f"`{selected_finding['location']}`",
        "`asset_type`": f"`{selected_finding['asset_type']}`",
        "`evidence`": f"`{selected_finding['evidence']}`",
        "`confidence`": f"`{selected_finding['confidence']}`",
        # One row quotes the scanner's name and version together.
        "`scanner_name` / `scanner_version`": (
            f"`{selected_finding['scanner_name']}` / `{selected_finding['scanner_version']}`"
        ),
        "`technical_metadata.Algorithm`": f"`{metadata['Algorithm']}`",
        "`technical_metadata.Key Size`": f"`{metadata['Key Size']}`",
        "`technical_metadata.Signature Algorithm`": f"`{metadata['Signature Algorithm']}`",
        "`technical_metadata.Expiration`": f"`{metadata['Expiration']}`",
        "`technical_metadata.Issuer`": f"`{metadata['Issuer']}`",
        "`technical_metadata.Subject`": f"`{metadata['Subject']}`",
        "`technical_metadata.Fingerprint`": f"`{metadata['Fingerprint']}`",
        "`schema_version`": f"`{selected_finding['schema_version']}`",
    }
    for key, value in expected.items():
        assert key in table, f"{key} is no longer quoted in the example"
        assert table[key] == value, f"{key} drifted from the committed sample"

    # Fields the example describes as absent must really be absent.
    assert selected_finding["rule_id"] is None
    assert "`null`" in table["`rule_id`"]
    for empty in ("unknowns", "limitations", "errors"):
        assert selected_finding[empty] == [], empty
    assert "empty" in table["`unknowns` / `limitations` / `errors`"]


def test_the_example_preserves_the_findings_empty_limitations_honestly(example):
    """An empty `limitations` list is reported as such, not as "no limits"."""
    observed = _flat(_section(example, LAYER_HEADINGS[0]))
    assert "This record's own `limitations` list is empty" in observed
    assert "not a statement that nothing limits it" in observed
    assert "absence of a finding is not proof of absence" in observed.lower()


# --- Claims separation: four layers, kept apart ---------------------------


def test_the_four_layers_are_visibly_separate_and_ordered(example):
    positions = []
    for heading in LAYER_HEADINGS:
        assert example.count(heading) == 1, f"{heading} appears {example.count(heading)} times"
        positions.append(example.index(heading))
    assert positions == sorted(positions)


def test_all_five_reader_questions_are_answered(example):
    for question in READER_QUESTIONS:
        assert example.count(question) == 1, question

    # And each is answered in the layer it belongs to.
    observed = _section(example, LAYER_HEADINGS[0])
    for question in READER_QUESTIONS[:3]:
        assert question in observed, question
    assert READER_QUESTIONS[3] in _section(example, LAYER_HEADINGS[2])
    assert READER_QUESTIONS[4] in _section(example, LAYER_HEADINGS[3])


def test_scanner_inference_is_reported_as_none_rather_than_invented(example):
    inference = _section(example, LAYER_HEADINGS[1])
    assert inference.strip().startswith("**None.**")
    assert "nothing is invented to fill it" in inference


def test_observation_is_not_restated_as_inference_or_advice(example):
    """The observed-fact layer stays free of interpretation and advice."""
    observed = _flat(_section(example, LAYER_HEADINGS[0]).lower())
    for banned in ("recommend", "should", "priorit", "risk score", "hndl", "readiness"):
        assert banned not in observed, f"the observed-fact layer contains {banned!r}"


def test_why_might_it_matter_is_conditional_rather_than_asserted(example):
    interpretation = _flat(_section(example, LAYER_HEADINGS[2]))
    assert "*if* a certificate with this profile were confirmed" in interpretation.lower()
    assert "Each of those is conditional on facts this scan did not establish" in interpretation
    assert (
        "did not observe deployment, runtime use, trust configuration, ownership, or business "
        "importance" in interpretation
    )
    assert "asserts no impact, no exposure, and no compliance or readiness conclusion" in (
        interpretation
    )


def test_interpretation_and_action_are_attributed_to_human_review(example):
    for heading in LAYER_HEADINGS[2:]:
        assert "*(human reviewer — not HarvestGuard)*" in heading
    interpretation = _flat(_section(example, LAYER_HEADINGS[2]))
    assert "is a reviewer's" in interpretation
    assert "not produced by the scanner" in interpretation


def test_next_steps_request_bounded_human_verification(example):
    action = _flat(_section(example, LAYER_HEADINGS[3]))
    assert "Bounded verification and context gathering by qualified people" in action
    assert "Ask the system owners" in action
    assert "not actions HarvestGuard takes or recommends" in action
    assert "belongs to qualified reviewers" in action


def test_traceability_table_attributes_only_the_evidence_layer_to_harvestguard(example):
    trace = _flat(example.split("## Traceability", 1)[1])
    assert "| Scanner inference | None produced" in trace
    assert "| Business interpretation | Human reviewer" in trace
    assert "| Recommended human action | Human reviewer |" in trace
    assert "Only the first row comes from HarvestGuard" in trace


# --- Privacy: fictional material only, no secret or key material ----------


def test_the_example_declares_itself_fictional_sample_material(example):
    lowered = _flat(example.lower())
    assert "**this is fictional sample material.**" in lowered
    assert "no real company, system, certificate, key, or sensitive value is described" in lowered
    assert (
        "nothing here is a risk score, compliance result, readiness determination, or "
        "remediation recommendation from harvestguard" in lowered
    )


def test_the_example_contains_no_secret_or_key_material(example):
    for needle in (
        "harvestguard-demo",  # the demo key's published passphrase
        "FAKE-DEMO-PASSWORD-VALUE-0000000000",
        "-----BEGIN",
        "PRIVATE KEY-----",
    ):
        assert needle not in example, f"the example leaks {needle!r}"

    for fixture in sorted((ROOT / "demo" / "sample_target" / "crypto").glob("*.pem")):
        for line in fixture.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if len(stripped) >= 40 and "-----" not in stripped and " " not in stripped:
                assert stripped not in example, f"{fixture.name} material leaked into the example"
