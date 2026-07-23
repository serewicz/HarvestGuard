"""Tests for HG-002's evidence-versus-inference distinction in the
Streamlit dashboard's user-facing language.

docs/TERMINOLOGY.md is canonical: Risk Score and HNDL Exposure are
inference-layer heuristics marked "Needs Validation", and a reader must
always be able to tell which layer a label belongs to. These tests pin the
visible labels/help text and prove the display code actually uses them --
without rendering Streamlit.
"""

from __future__ import annotations

import inspect

from dashboard.visualizations import (
    HNDL_EXPOSURE_HELP,
    HNDL_EXPOSURE_LABEL,
    RESULTS_TABLE_HELP,
    RISK_SCORE_HELP,
    RISK_SCORE_LABEL,
    display_risk_dashboard,
)


def test_risk_score_label_is_visibly_inferred_and_needs_validation():
    assert "inferred" in RISK_SCORE_LABEL
    assert "heuristic" in RISK_SCORE_LABEL
    assert "Needs Validation" in RISK_SCORE_LABEL


def test_risk_score_help_denies_measured_fact_status():
    # TERMINOLOGY.md: "an ordering aid, not a measured fact".
    assert "ordering aid" in RISK_SCORE_HELP
    assert "not a measured fact" in RISK_SCORE_HELP
    assert "Needs Validation" in RISK_SCORE_HELP


def test_hndl_exposure_label_is_visibly_inferred_and_needs_validation():
    assert "inferred" in HNDL_EXPOSURE_LABEL
    assert "Needs Validation" in HNDL_EXPOSURE_LABEL


def test_hndl_exposure_help_matches_canonical_definition():
    # TERMINOLOGY.md: "a heuristic bucket (High/Medium/Low) derived from
    # encryption status and path signals, not a measured probability".
    assert "Harvest Now, Decrypt Later" in HNDL_EXPOSURE_HELP
    assert "derived from encryption status and path signals" in HNDL_EXPOSURE_HELP
    assert "not a measured probability" in HNDL_EXPOSURE_HELP
    assert "Needs Validation" in HNDL_EXPOSURE_HELP


def test_results_table_help_separates_evidence_from_inference():
    assert "observed evidence" in RESULTS_TABLE_HELP
    assert "inferred" in RESULTS_TABLE_HELP
    assert "not observed facts" in RESULTS_TABLE_HELP


def test_display_risk_dashboard_actually_renders_the_labeled_language():
    # The constants must be wired into the display function, not merely
    # defined -- otherwise the UI still shows unlabeled headings.
    source = inspect.getsource(display_risk_dashboard)
    for name in (
        "HNDL_EXPOSURE_LABEL",
        "HNDL_EXPOSURE_HELP",
        "RISK_SCORE_LABEL",
        "RISK_SCORE_HELP",
        "RESULTS_TABLE_HELP",
    ):
        assert name in source
    # And the old unlabeled subheaders are gone.
    assert '"Risk Scores"' not in source
    assert '"Risk Distribution"' not in source
