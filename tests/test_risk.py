import pandas as pd

from analyzer.risk import analyze_risks, calculate_risk_score


def test_calculate_risk_score_base_case():
    row = {"Encryption": "AES-256", "Location": "/data/file.txt"}
    assert calculate_risk_score(row) == 50


def test_calculate_risk_score_unencrypted():
    row = {"Encryption": "None", "Location": "/data/file.txt"}
    assert calculate_risk_score(row) == 90


def test_calculate_risk_score_sensitive_path_is_capped_at_100():
    row = {"Encryption": "Unknown / Unencrypted", "Location": "/data/Sensitive/customers.csv"}
    # 50 base + 40 (unencrypted) + 20 (sensitive path) = 110, capped at 100
    assert calculate_risk_score(row) == 100


def test_analyze_risks_empty_dataframe_passthrough():
    df = pd.DataFrame()
    result = analyze_risks(df)
    assert result.empty


def test_analyze_risks_adds_expected_columns():
    df = pd.DataFrame(
        [
            {"Location": "/data/plain.txt", "Encryption": "None"},
            {"Location": "/data/enc.txt", "Encryption": "AES-256"},
        ]
    )
    result = analyze_risks(df)

    assert "Risk Score" in result.columns
    assert "HNDL Exposure" in result.columns
    # Unencrypted row should score higher than the encrypted one
    unencrypted_score = result.loc[result["Location"] == "/data/plain.txt", "Risk Score"].iloc[0]
    encrypted_score = result.loc[result["Location"] == "/data/enc.txt", "Risk Score"].iloc[0]
    assert unencrypted_score > encrypted_score


def test_analyze_risks_hndl_exposure_buckets():
    df = pd.DataFrame([{"Location": "/x", "Encryption": "None"}])
    result = analyze_risks(df)
    assert result["HNDL Exposure"].iloc[0] == "High"
