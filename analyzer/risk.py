import pandas as pd


def calculate_risk_score(row):
    """Simple risk scoring for POC - expand with real logic later."""
    score = 50  # Base
    if row.get("Encryption") in ["Unknown / Unencrypted", "None"]:
        score += 40
    if "Sensitive" in str(row.get("Location", "")):
        score += 20
    return min(100, score)


def analyze_risks(df: pd.DataFrame):
    if df.empty:
        return df
    df["Risk Score"] = df.apply(calculate_risk_score, axis=1)
    df["HNDL Exposure"] = df["Risk Score"].apply(
        lambda x: "High" if x > 70 else "Medium" if x > 40 else "Low"
    )
    return df
