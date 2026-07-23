from unittest.mock import MagicMock, patch

import pytest
from azure.core.exceptions import AzureError

from scanner.azure_blob import scan_azure_container, scan_azure_container_findings
from scanner.errors import CloudScanError


def _make_blob(name, size, last_modified, encryption_scope=None):
    blob = MagicMock()
    blob.name = name
    blob.size = size
    blob.last_modified = last_modified
    blob.encryption_scope = encryption_scope
    return blob


@patch("scanner.azure_blob.DefaultAzureCredential")
@patch("scanner.azure_blob.BlobServiceClient")
def test_scan_azure_container_flags_customer_managed_scope_as_low_risk(
    mock_service_cls, _mock_cred
):
    container_client = mock_service_cls.return_value.get_container_client.return_value
    container_client.list_blobs.return_value = [
        _make_blob("secrets.csv", 100, "2026-01-01", encryption_scope="my-cmk-scope"),
    ]

    df = scan_azure_container("https://acct.blob.core.windows.net", "my-container")

    assert len(df) == 1
    assert df.iloc[0]["Location"] == "https://acct.blob.core.windows.net/my-container/secrets.csv"
    assert df.iloc[0]["Encryption"] == "Customer-managed (scope: my-cmk-scope)"
    assert df.iloc[0]["Risk"] == "Low"


@patch("scanner.azure_blob.DefaultAzureCredential")
@patch("scanner.azure_blob.BlobServiceClient")
def test_scan_azure_container_flags_default_encryption_as_medium_risk(mock_service_cls, _mock_cred):
    container_client = mock_service_cls.return_value.get_container_client.return_value
    container_client.list_blobs.return_value = [_make_blob("data.csv", 50, "2026-01-01")]

    df = scan_azure_container("https://acct.blob.core.windows.net", "my-container")

    assert df.iloc[0]["Encryption"] == "Microsoft-managed"
    assert df.iloc[0]["Risk"] == "Medium"


@patch("scanner.azure_blob.DefaultAzureCredential")
@patch("scanner.azure_blob.BlobServiceClient")
def test_scan_azure_container_empty_when_no_blobs(mock_service_cls, _mock_cred):
    container_client = mock_service_cls.return_value.get_container_client.return_value
    container_client.list_blobs.return_value = []

    df = scan_azure_container("https://acct.blob.core.windows.net", "my-container")

    assert df.empty


@patch("scanner.azure_blob.DefaultAzureCredential")
@patch("scanner.azure_blob.BlobServiceClient")
def test_scan_azure_container_handles_api_error_gracefully(mock_service_cls, _mock_cred):
    mock_service_cls.side_effect = AzureError("boom")

    df = scan_azure_container("https://acct.blob.core.windows.net", "my-container")

    assert df.empty


@patch("scanner.azure_blob.DefaultAzureCredential")
@patch("scanner.azure_blob.BlobServiceClient")
def test_scan_azure_container_records_scan_error_when_collector_supplied(
    mock_service_cls, _mock_cred, capsys
):
    mock_service_cls.side_effect = AzureError("boom")

    errors: list[str] = []
    df = scan_azure_container("https://acct.blob.core.windows.net", "my-container", errors=errors)

    assert df.empty
    assert capsys.readouterr().out == ""
    assert errors and "Error scanning Azure Blob" in errors[0]


@patch("scanner.azure_blob.DefaultAzureCredential")
@patch("scanner.azure_blob.BlobServiceClient")
def test_scan_azure_container_findings_raises_on_swallowed_scan_error(mock_service_cls, _mock_cred):
    mock_service_cls.side_effect = AzureError("boom")

    with pytest.raises(CloudScanError):
        scan_azure_container_findings("https://acct.blob.core.windows.net", "my-container")


@patch("scanner.azure_blob.DefaultAzureCredential")
@patch("scanner.azure_blob.BlobServiceClient")
def test_scan_azure_container_findings_returns_findings_on_success(mock_service_cls, _mock_cred):
    container_client = mock_service_cls.return_value.get_container_client.return_value
    container_client.list_blobs.return_value = [_make_blob("data.csv", 50, "2026-01-01")]

    findings = scan_azure_container_findings("https://acct.blob.core.windows.net", "my-container")

    assert len(findings) == 1
    assert findings[0].location == "https://acct.blob.core.windows.net/my-container/data.csv"
