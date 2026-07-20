import streamlit as st
import pandas as pd
from scanner.filesystem import scan_filesystem
from scanner.cloud import scan_s3_bucket

st.set_page_config(page_title="HarvestGuard", layout="wide")
st.title("🌾 HarvestGuard")
st.markdown("**Open-source cryptographic inventory and quantum risk scanner**")

st.sidebar.header("Scan Configuration")
scan_type = st.sidebar.selectbox("Scan Target", ["Local Filesystem", "AWS S3 Bucket"])
target = st.sidebar.text_input("Path / Bucket Name", "/Users" if scan_type == "Local Filesystem" else "your-bucket-name")

if st.sidebar.button("Run Scan", type="primary"):
    with st.spinner("Scanning..."):
        if scan_type == "Local Filesystem":
            df = scan_filesystem(target, max_depth=2)
        else:
            df = scan_s3_bucket(target)
        
        if not df.empty:
            st.success(f"Found {len(df)} items")
            st.dataframe(df, use_container_width=True)
            
            # Simple risk summary
            risk_counts = df['Risk'].value_counts()
            st.bar_chart(risk_counts)
        else:
            st.warning("No items found or access issue.")

st.info("Sprint 2 - Basic scanner added. Real encryption detection & risk engine coming in Sprint 3.")
