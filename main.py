import streamlit as st
import pandas as pd
from scanner.filesystem import scan_filesystem
from scanner.cloud import scan_s3_bucket
from analyzer.risk import analyze_risks
from dashboard.visualizations import display_risk_dashboard

st.set_page_config(page_title="HarvestGuard", layout="wide")
st.title("🌾 HarvestGuard")
st.markdown("**Open-source cryptographic inventory and quantum risk scanner**")

st.sidebar.header("Scan Configuration")
scan_type = st.sidebar.selectbox("Scan Target", ["Local Filesystem", "AWS S3 Bucket"])
target = st.sidebar.text_input("Path / Bucket Name", value="/Users")

if st.sidebar.button("Run Scan", type="primary"):
    with st.spinner("Scanning and analyzing..."):
        if scan_type == "Local Filesystem":
            df = scan_filesystem(target, max_depth=2)
        else:
            df = scan_s3_bucket(target)
        
        if not df.empty:
            df = analyze_risks(df)
            st.success(f"Scan Complete - {len(df)} items analyzed")
            display_risk_dashboard(df)
        else:
            st.warning("No items found or permission issue.")

st.info("Sprint 3 Complete - Risk analysis + visualizations added.")
