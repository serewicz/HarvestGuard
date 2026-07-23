import pandas as pd

# Risk Score and HNDL Exposure are inference, not observed evidence: a heuristic
# ordering aid derived from encryption status and path signals, not a measured
# fact, probability, or business-impact figure. This early proof-of-concept
# scoring is marked `Needs Validation` in docs/TERMINOLOGY.md; UI and reports
# must not present it as certainty. See docs/DECISIONS/ADR-005 and
# docs/TERMINOLOGY.md for the evidence-versus-inference boundary.

# Values scanners use to signal "confirmed unencrypted" across sources
# (filesystem scans emit "Unencrypted"; S3 emits "None"; legacy POC value
# kept for compatibility).
_UNENCRYPTED_VALUES = {"Unknown / Unencrypted", "None", "Unencrypted"}


def calculate_risk_score(row):
    """Heuristic (inferred) risk ordering aid, not a measured fact.

    Proof-of-concept scoring; `Needs Validation` per docs/TERMINOLOGY.md.
    """
    score = 50  # Base
    if row.get("Encryption") in _UNENCRYPTED_VALUES:
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
