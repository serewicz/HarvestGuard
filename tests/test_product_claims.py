"""Regression coverage for docs/CLAIMS_AUDIT.md (roadmap HG-010).

These tests protect durable, high-risk claim boundaries -- the ones that
would materially mislead a CTO/CISO evaluating HarvestGuard -- rather than
freezing entire documents as prose. Not every sentence in every reviewed
document has a corresponding assertion here.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

import harvestguard
from dashboard.visualizations import (
    HNDL_EXPOSURE_LABEL,
    NO_CODE_FINDINGS_MESSAGE,
    NO_SENSITIVE_DATA_MESSAGE,
    RISK_SCORE_LABEL,
)
from reports import format_markdown_report, make_report_context

ROOT = Path(__file__).parent.parent
README = (ROOT / "README.md").read_text()
PYPROJECT = (ROOT / "pyproject.toml").read_text()
ROADMAP = (ROOT / "docs" / "ROADMAP.md").read_text()
TERMINOLOGY = (ROOT / "docs" / "TERMINOLOGY.md").read_text()
DETECTION_CHARACTERIZATION = (ROOT / "docs" / "DETECTION_CHARACTERIZATION.md").read_text()
EXECUTIVE_DELIVERABLES = (ROOT / "docs" / "EXECUTIVE_DELIVERABLES.md").read_text()
ASSET_INVENTORY = (ROOT / "docs" / "ASSET_INVENTORY.md").read_text()


# --- Product identity: no longer a bare "quantum risk scanner" claim ------


def test_readme_does_not_identify_as_a_bare_quantum_risk_scanner():
    assert "quantum risk scanner" not in README.lower()


def test_pyproject_description_does_not_claim_quantum_risk_scanning():
    assert "quantum risk scanner" not in PYPROJECT.lower()


def test_pyproject_version_was_not_bumped_by_this_audit():
    # HG-011 owns release/versioning; HG-010 must only touch claims wording.
    match = re.search(r'^version\s*=\s*"([^"]+)"', PYPROJECT, re.MULTILINE)
    assert match is not None
    assert match.group(1) == "0.1.0"


# --- Network/TLS and binary/runtime analysis are not claimed as shipped ---


def test_network_tls_discovery_is_not_presented_as_implemented():
    for text, name in [(README, "README"), (ROADMAP, "ROADMAP")]:
        assert "no network-level crypto" in text.lower() or "not yet built" in text.lower(), (
            f"{name} should still disclaim network/TLS discovery as not implemented"
        )


def test_binary_runtime_analysis_is_not_presented_as_implemented():
    assert "not binary analysis" in DETECTION_CHARACTERIZATION.lower()
    assert "compiled binaries" in DETECTION_CHARACTERIZATION.lower()


# --- Code analysis is truthfully Python-source-only ------------------------


def test_every_active_code_analysis_rule_declares_python_only():
    rules_path = ROOT / "code_analysis" / "rules" / "crypto.yaml"
    rules = yaml.safe_load(rules_path.read_text())["rules"]
    assert rules, "expected at least one vendored rule"
    for rule in rules:
        assert rule["languages"] == ["python"], (
            f"rule {rule.get('id')!r} claims languages {rule['languages']!r}; "
            "if a non-Python language is ever added, the Python-only claim in "
            "README/CLI.md/DETECTION_CHARACTERIZATION.md must be updated too"
        )


def test_readme_states_code_analysis_targets_python_source_only():
    assert "python source only" in README.lower() or "python source" in README.lower()


# --- HNDL / Risk Score remain labeled heuristic and Needs Validation ------


def test_dashboard_labels_hndl_and_risk_score_as_needs_validation():
    assert "needs validation" in HNDL_EXPOSURE_LABEL.lower()
    assert "needs validation" in RISK_SCORE_LABEL.lower()


def test_terminology_marks_hndl_and_risk_score_needs_validation():
    hndl_section = TERMINOLOGY[TERMINOLOGY.index("HNDL exposure (Harvest Now") :]
    assert "**Needs Validation**" in hndl_section[:600]
    risk_section = TERMINOLOGY[TERMINOLOGY.index("**Risk score**") :]
    assert "**Needs Validation**" in risk_section[:600]


def test_normalized_finding_schema_has_no_risk_or_hndl_field():
    # Risk Score / HNDL Exposure are dashboard-only inferences (analyzer/risk.py).
    # findings.py and finding_adapters.py legitimately *mention* "risk" in prose
    # only to disclaim it (e.g. "excludes ... quantum risk ..."), so this checks
    # the actual dataclass field names, not a blanket word ban.
    import dataclasses

    from findings import NormalizedFinding

    field_names = {f.name.lower() for f in dataclasses.fields(NormalizedFinding)}
    for forbidden in ("risk", "risk_score", "hndl", "hndl_exposure", "exposure"):
        assert forbidden not in field_names, (
            f"NormalizedFinding unexpectedly has a {forbidden!r} field"
        )


def test_cli_never_imports_the_risk_analyzer():
    # harvestguard.py is the CLI's evidence-only entry point; analyzer/risk.py
    # (the heuristic Risk Score / HNDL Exposure engine) is wired into the
    # Streamlit dashboard (main.py) only.
    text = (ROOT / "harvestguard.py").read_text()
    assert "analyzer" not in text.lower()
    assert "analyze_risks" not in text


# --- Evidence reports make no remediation/compliance/quantum claims -------


def test_markdown_report_makes_no_assessment_layer_claims():
    context = make_report_context(
        target_path="/scan/root",
        started_at=None,
        duration_seconds=0.1,
        excluded_paths=[],
        scanner_errors=[],
    )
    report = format_markdown_report([], context).lower()

    # Positive/asserting phrasing that would indicate the report is *making*
    # one of these assessment-layer claims, not just disclaiming it. Chosen
    # to not collide with the report's own disclaiming sentence, which
    # legitimately contains words like "risk" and "remediation".
    for forbidden in [
        "recommended remediation:",
        "compliant with",
        "is quantum-ready",
        "quantum readiness:",
        "business impact:",
        "estimated impact",
    ]:
        assert forbidden not in report, f"report unexpectedly contains {forbidden!r}"

    # The report explicitly disclaims these, which is different from -- and
    # stronger than -- simply never mentioning them.
    assert "not business risk conclusions" in report
    assert "no risk scores, executive priority, remediation recommendations" in report


def test_code_analysis_asymmetry_caveat_only_appears_when_code_analysis_ran():
    # Corrects a hunk from the salvaged diff: an unconditional code-analysis
    # caveat would violate the pre-existing invariant (test_reports.py,
    # test_cli.py) that a single-scanner report never mentions a scanner it
    # did not run.
    ran_code_analysis = make_report_context(
        target_path="/scan/root",
        started_at=None,
        duration_seconds=0.1,
        excluded_paths=[],
        scanner_errors=[],
        scanners=["code analysis"],
    )
    filesystem_only = make_report_context(
        target_path="/scan/root",
        started_at=None,
        duration_seconds=0.1,
        excluded_paths=[],
        scanner_errors=[],
        scanners=["filesystem"],
    )

    with_code_analysis = format_markdown_report([], ran_code_analysis)
    without_code_analysis = format_markdown_report([], filesystem_only)

    assert "diagnostic goes only to the scan's standard error stream" in with_code_analysis
    assert "diagnostic goes only to the scan's standard error stream" not in without_code_analysis
    assert "code analysis" not in without_code_analysis.lower()


# --- Dashboard empty-result wording does not assert proven absence --------


def test_dashboard_empty_result_messages_do_not_claim_proven_absence():
    for message in [NO_SENSITIVE_DATA_MESSAGE, NO_CODE_FINDINGS_MESSAGE]:
        lowered = message.lower()
        assert "detected" not in lowered or "matched" in lowered
        assert "no" in lowered  # still a negative result message, just scoped


def test_dashboard_does_not_use_success_styling_for_empty_scanner_results():
    source = (ROOT / "dashboard" / "visualizations.py").read_text()
    sensitive_fn = source[source.index("def display_sensitive_data_dashboard") :]
    sensitive_fn = sensitive_fn[: sensitive_fn.index("def display_code_analysis_dashboard")]
    assert "st.success" not in sensitive_fn

    code_fn = source[source.index("def display_code_analysis_dashboard") :]
    assert "st.success" not in code_fn


# --- Default --max-depth 3 bounded-scope claim -----------------------------


def test_cli_default_max_depth_is_three():
    parser = harvestguard.build_parser()
    args = parser.parse_args(["scan", "."])
    assert args.max_depth == 3


def test_readme_and_cli_docs_state_the_default_depth_is_bounded_not_unlimited():
    assert "defaults to `3`" in README or "defaults to 3" in README.lower()
    cli_doc = (ROOT / "docs" / "CLI.md").read_text().lower()
    assert "defaults to `3`" in cli_doc


# --- Sensitive-data raw values remain category/count only -----------------


def test_readme_states_sensitive_data_is_category_count_only_never_raw_values():
    normalized = " ".join(README.lower().split())
    assert "category and count only, never the matched values" in normalized


# --- Provider metadata language does not imply independent verification ---


def test_asset_inventory_frames_cloud_evidence_as_reported_not_verified():
    provider_markers = ("ServerSideEncryption", "CMEK", "customer-managed encryption scope")
    provider_lines = [
        line for line in ASSET_INVENTORY.splitlines() if any(m in line for m in provider_markers)
    ]
    for provider_line in provider_lines:
        assert "verified" not in provider_line.lower()
        assert "proven" not in provider_line.lower()


def test_readme_states_provider_metadata_is_not_independent_proof():
    normalized = " ".join(README.lower().split())
    assert "not independent proof of the underlying cryptographic implementation" in normalized


# --- Installed CLI / Streamlit dashboard boundary is preserved ------------


def test_readme_states_dashboard_is_a_separate_operating_path():
    lowered = README.lower()
    assert "separate operating path" in lowered
    assert "not** part of the installed" in README or "not part of the installed" in lowered


# --- Technology Due Diligence Evidence Package is not claimed as shipped --


def test_executive_deliverables_states_the_package_is_a_reporting_target_not_shipped():
    lowered = EXECUTIVE_DELIVERABLES.lower()
    assert "not shipped output" in lowered or "reporting target" in lowered


# --- Roadmap status reconciliation -----------------------------------------


def _roadmap_entry_status(hg_id: str) -> str:
    match = re.search(rf"### {hg_id}\n.*?\n- \*\*Status:\*\* ([^\n]+)", ROADMAP, re.DOTALL)
    assert match is not None, f"could not find a Status field for {hg_id}"
    return match.group(1).strip()


def test_roadmap_hg_009_is_complete():
    assert _roadmap_entry_status("HG-009") == "Complete"


def test_roadmap_hg_010_is_not_prematurely_marked_complete():
    # HG-010 closes only after merge and an independent closure review --
    # finishing this recovery is not, by itself, grounds to mark it Complete.
    assert _roadmap_entry_status("HG-010") != "Complete"
