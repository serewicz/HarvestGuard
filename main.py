import streamlit as st
import pandas as pd

st.set_page_config(page_title="HarvestGuard", layout="wide")
st.title("🌾 HarvestGuard")
st.markdown("**Open-source cryptographic inventory and quantum risk scanner**")
st.caption("Built by Timothy Serewicz • Executive Technology Advisor & Fractional CTO")

# Sidebar
st.sidebar.header("Scan Configuration")
scan_type = st.sidebar.selectbox("Scan Target", ["Local Filesystem", "AWS S3 Bucket", "Network (Zeek)"])
path = st.sidebar.text_input("Path / Bucket", "/data" if scan_type == "Local Filesystem" else "my-bucket")

if st.sidebar.button("Run Scan", type="primary"):
    with st.spinner("Scanning... (simulated for POC)"):
        # Placeholder results
        data = {
            "Location": ["/data/sensitive.db", "s3://bucket/contracts.pdf"],
            "Encryption": ["None", "AES-256"],
            "Strength": ["Critical", "Strong"],
            "Owner": ["unknown", "finance-team"],
            "Risk Score": [85, 15],
            "HNDL Exposure": ["High", "Low"]
        }
        df = pd.DataFrame(data)
        
        st.success("Scan Complete!")
        st.dataframe(df, use_container_width=True)
        
        col1, col2 = st.columns(2)
        with col1:
            st.plotly_chart(__import__("plotly").express.pie(df, names="Strength", title="Encryption Strength"))
        with col2:
            st.metric("Overall Risk", "Medium", "42%")

st.info("This is the POC dashboard. Next sprints will add real scanning logic.")
