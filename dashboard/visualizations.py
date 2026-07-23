import pandas as pd
import plotly.express as px
import streamlit as st

# User-facing labels and help text for the inference-layer fields. The
# vocabulary is docs/TERMINOLOGY.md's (HG-002), used verbatim: Risk Score and
# HNDL Exposure are inferred heuristics marked "Needs Validation" there, and a
# reader must always be able to tell inference apart from observed evidence.
HNDL_EXPOSURE_LABEL = "HNDL Exposure (inferred — Needs Validation)"
HNDL_EXPOSURE_HELP = (
    "Inferred Harvest Now, Decrypt Later exposure: a heuristic High/Medium/Low "
    "bucket derived from encryption status and path signals, not a measured "
    "probability. Needs Validation."
)
RISK_SCORE_LABEL = "Risk Scores (inferred heuristic — Needs Validation)"
RISK_SCORE_HELP = (
    "Heuristic 0–100 ordering aid derived from observed evidence such as "
    "encryption status and path signals. An inference, not a measured fact, "
    "probability, or business-impact figure. Needs Validation."
)
RESULTS_TABLE_HELP = (
    "Location, Encryption, and scan metadata columns are observed evidence "
    "collected by the scanner. The Risk Score and HNDL Exposure columns are "
    "inferred heuristic assessments derived from that evidence (Needs "
    "Validation), not observed facts."
)


def display_risk_dashboard(df: pd.DataFrame):
    if df.empty:
        st.warning("No data to display")
        return

    col1, col2 = st.columns(2)
    with col1:
        st.subheader(HNDL_EXPOSURE_LABEL)
        fig = px.pie(df, names="HNDL Exposure", title="HNDL Exposure")
        st.plotly_chart(fig, use_container_width=True)
        st.caption(HNDL_EXPOSURE_HELP)
    with col2:
        st.subheader(RISK_SCORE_LABEL)
        st.bar_chart(df.set_index("Location")["Risk Score"])
        st.caption(RISK_SCORE_HELP)

    st.subheader("Detailed Results")
    st.dataframe(df, use_container_width=True)
    st.caption(RESULTS_TABLE_HELP)


def display_sensitive_data_dashboard(df: pd.DataFrame):
    if df.empty:
        st.success("No sensitive data patterns detected in scanned files.")
        return

    st.subheader(f"Sensitive Data Findings — {len(df)} file(s) flagged")

    category_counts = df["Categories"].str.split(", ").explode().value_counts()
    st.bar_chart(category_counts)

    st.subheader("Flagged Files")
    st.dataframe(df, use_container_width=True)


def display_code_analysis_dashboard(df: pd.DataFrame):
    if df.empty:
        st.success("No weak/legacy crypto library usage detected.")
        return

    st.subheader(f"Crypto Code Analysis Findings — {len(df)} finding(s)")

    rule_counts = df["Rule"].value_counts()
    st.bar_chart(rule_counts)

    st.subheader("Findings")
    st.dataframe(df, use_container_width=True)
