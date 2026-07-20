import streamlit as st

from analyzer.risk import analyze_risks
from classifier.scanner import scan_filesystem_for_sensitive_data
from dashboard.visualizations import display_risk_dashboard, display_sensitive_data_dashboard
from scanner.cloud import scan_s3_bucket
from scanner.filesystem import scan_filesystem

SENSITIVE_DATA_SCAN = "Local Filesystem — Sensitive Data (PII/Secrets)"

st.set_page_config(page_title="HarvestGuard", layout="wide")
st.title("🌾 HarvestGuard")
st.markdown("**Open-source cryptographic inventory and quantum risk scanner**")

st.sidebar.header("Scan Configuration")
scan_type = st.sidebar.selectbox(
    "Scan Target", ["Local Filesystem", "AWS S3 Bucket", SENSITIVE_DATA_SCAN]
)
target = st.sidebar.text_input("Path / Bucket Name", value="/Users")

if st.sidebar.button("Run Scan", type="primary"):
    with st.spinner("Scanning and analyzing..."):
        if scan_type == "Local Filesystem":
            df = scan_filesystem(target, max_depth=2)
        elif scan_type == "AWS S3 Bucket":
            df = scan_s3_bucket(target)
        else:
            df = scan_filesystem_for_sensitive_data(target, max_depth=2)

        if scan_type == SENSITIVE_DATA_SCAN:
            if not df.empty:
                st.success(f"Scan Complete - {len(df)} file(s) flagged")
            display_sensitive_data_dashboard(df)
        elif not df.empty:
            df = analyze_risks(df)
            st.success(f"Scan Complete - {len(df)} items analyzed")
            display_risk_dashboard(df)
        else:
            st.warning("No items found or permission issue.")

st.info("Sprint 3 Complete - Risk analysis + visualizations added.")
