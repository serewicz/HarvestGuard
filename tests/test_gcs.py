from unittest.mock import MagicMock, patch

from google.api_core.exceptions import GoogleAPIError
from google.auth.exceptions import DefaultCredentialsError

from scanner.gcs import scan_gcs_bucket


def _make_blob(name, size, updated, kms_key_name=None):
    blob = MagicMock()
    blob.name = name
    blob.size = size
    blob.updated = updated
    blob.kms_key_name = kms_key_name
    return blob


@patch("scanner.gcs.storage.Client")
def test_scan_gcs_bucket_flags_cmek_as_low_risk(mock_client_cls):
    mock_client_cls.return_value.list_blobs.return_value = [
        _make_blob(
            "secrets.csv", 100, "2026-01-01", kms_key_name="projects/p/keyRings/r/cryptoKeys/k"
        ),
    ]

    df = scan_gcs_bucket("my-bucket")

    assert len(df) == 1
    assert df.iloc[0]["Location"] == "gs://my-bucket/secrets.csv"
    assert df.iloc[0]["Encryption"] == "CMEK"
    assert df.iloc[0]["Risk"] == "Low"


@patch("scanner.gcs.storage.Client")
def test_scan_gcs_bucket_flags_default_encryption_as_medium_risk(mock_client_cls):
    mock_client_cls.return_value.list_blobs.return_value = [
        _make_blob("data.csv", 50, "2026-01-01")
    ]

    df = scan_gcs_bucket("my-bucket")

    assert df.iloc[0]["Encryption"] == "Google-managed"
    assert df.iloc[0]["Risk"] == "Medium"


@patch("scanner.gcs.storage.Client")
def test_scan_gcs_bucket_empty_when_no_blobs(mock_client_cls):
    mock_client_cls.return_value.list_blobs.return_value = []

    df = scan_gcs_bucket("my-bucket")

    assert df.empty


@patch("scanner.gcs.storage.Client")
def test_scan_gcs_bucket_handles_api_error_gracefully(mock_client_cls):
    mock_client_cls.return_value.list_blobs.side_effect = GoogleAPIError("boom")

    df = scan_gcs_bucket("my-bucket")

    assert df.empty


@patch("scanner.gcs.storage.Client")
def test_scan_gcs_bucket_handles_missing_credentials_gracefully(mock_client_cls):
    # storage.Client() resolves credentials at construction time, so an auth
    # failure surfaces as DefaultCredentialsError from the constructor itself,
    # not from list_blobs() -- this must not crash the caller (e.g. the
    # Streamlit app) with an uncaught exception.
    mock_client_cls.side_effect = DefaultCredentialsError("no credentials found")

    df = scan_gcs_bucket("my-bucket")

    assert df.empty
