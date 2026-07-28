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


@patch("scanner.azure_blob.DefaultAzureCredential")
@patch("scanner.azure_blob.BlobServiceClient")
def test_scan_azure_container_processes_every_yielded_blob_exactly_once(
    mock_service_cls, _mock_cred
):
    # azure-storage-blob returns an ItemPaged iterator from list_blobs and
    # fetches later provider pages transparently as iteration advances, so
    # HarvestGuard does not track continuation markers itself. A generator that
    # yields more blobs than one provider page would hold stands in for that:
    # the scanner must process every blob the iterator produces, exactly once.
    def blobs_across_pages():
        for index in range(5):
            yield _make_blob(f"page{index // 2}/obj{index}.csv", index, "2026-01-01")

    container_client = mock_service_cls.return_value.get_container_client.return_value
    container_client.list_blobs.return_value = blobs_across_pages()

    findings = scan_azure_container_findings(
        "https://acct.blob.core.windows.net", "my-container"
    )
    locations = [finding.location for finding in findings]

    assert len(locations) == len(set(locations)) == 5
    assert locations[0] == "https://acct.blob.core.windows.net/my-container/page0/obj0.csv"
    assert locations[-1] == "https://acct.blob.core.windows.net/my-container/page2/obj4.csv"
    assert len({finding.finding_id for finding in findings}) == 5


@patch("scanner.azure_blob.DefaultAzureCredential")
@patch("scanner.azure_blob.BlobServiceClient")
def test_scan_azure_container_passes_prefix_as_name_starts_with(mock_service_cls, _mock_cred):
    container_client = mock_service_cls.return_value.get_container_client.return_value
    container_client.list_blobs.return_value = [_make_blob("logs/data.csv", 50, "2026-01-01")]

    scan_azure_container(
        "https://acct.blob.core.windows.net", "my-container", prefix="logs/"
    )

    assert container_client.list_blobs.call_args.kwargs["name_starts_with"] == "logs/"
    mock_service_cls.return_value.get_container_client.assert_called_with("my-container")


def _mixed_result_blobs():
    """Yield one good blob, then fail partway through iteration."""
    yield _make_blob("good.csv", 10, "2026-01-01")
    raise AzureError("boom")


@patch("scanner.azure_blob.DefaultAzureCredential")
@patch("scanner.azure_blob.BlobServiceClient")
def test_mixed_result_scan_keeps_partial_findings_on_the_exception(mock_service_cls, _mock_cred):
    # A failure partway through blob iteration is still a failure -- but the
    # finding collected before the failure must ride along on the exception,
    # not be discarded with it.
    container_client = mock_service_cls.return_value.get_container_client.return_value
    container_client.list_blobs.return_value = _mixed_result_blobs()

    with pytest.raises(CloudScanError) as exc_info:
        scan_azure_container_findings("https://acct.blob.core.windows.net", "my-container")

    partial = exc_info.value.partial_findings
    assert len(partial) == 1
    assert partial[0].location == "https://acct.blob.core.windows.net/my-container/good.csv"
    assert "boom" in str(exc_info.value)


@patch("scanner.azure_blob.DefaultAzureCredential")
@patch("scanner.azure_blob.BlobServiceClient")
def test_cli_azure_partial_failure_keeps_partials_and_exits_nonzero(
    mock_service_cls, _mock_cred, capsys
):
    # End-to-end through the CLI (only the Azure SDK stubbed): the blob observed
    # before the iterator failed appears in parseable JSON stdout, and the
    # failure still produces the scanner-error exit code.
    import json

    import harvestguard

    container_client = mock_service_cls.return_value.get_container_client.return_value
    container_client.list_blobs.return_value = _mixed_result_blobs()

    exit_code = harvestguard.main(
        ["scan", "acct/my-container", "--type", "azure", "--json", "--quiet"]
    )

    captured = capsys.readouterr()
    assert exit_code == harvestguard.EXIT_SCAN_ERROR
    payload = json.loads(captured.out)  # stdout stays machine-readable
    assert [item["location"] for item in payload] == [
        "https://acct.blob.core.windows.net/my-container/good.csv"
    ]
