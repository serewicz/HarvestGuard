import streamlit as st
import plotly.express as px
import pandas as pd

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
