import pandas as pd
import plotly.express as px
import streamlit as st


def display_risk_dashboard(df: pd.DataFrame):
    if df.empty:
        st.warning("No data to display")
        return

    col1, col2 = st.columns(2)
    with col1:
        st.subheader("Risk Distribution")
        fig = px.pie(df, names="HNDL Exposure", title="HNDL Exposure")
        st.plotly_chart(fig, use_container_width=True)
    with col2:
        st.subheader("Risk Scores")
        st.bar_chart(df.set_index("Location")["Risk Score"])

    st.subheader("Detailed Results")
    st.dataframe(df, use_container_width=True)


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
