from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError, NoCredentialsError

from scanner.cloud import scan_s3_bucket, scan_s3_bucket_findings
from scanner.errors import CloudScanError


def _s3_client_with_objects():
    client = MagicMock()
    client.list_objects_v2.return_value = {
        "Contents": [{"Key": "data.txt", "Size": 10, "LastModified": "2026-01-01"}]
    }
    client.head_object.return_value = {"ServerSideEncryption": "AES256"}
    return client


@patch("scanner.cloud.boto3.client")
def test_scan_s3_bucket_reports_encrypted_object_as_low_risk(mock_client):
    mock_client.return_value = _s3_client_with_objects()

    df = scan_s3_bucket("my-bucket")

    assert len(df) == 1
    assert df.iloc[0]["Location"] == "s3://my-bucket/data.txt"
    assert df.iloc[0]["Encryption"] == "AES256"
    assert df.iloc[0]["Risk"] == "Low"


@patch("scanner.cloud.boto3.client")
def test_scan_s3_bucket_reports_unencrypted_object_as_high_risk(mock_client):
    client = MagicMock()
    client.list_objects_v2.return_value = {
        "Contents": [{"Key": "plain.txt", "Size": 5, "LastModified": "2026-01-01"}]
    }
    client.head_object.return_value = {}
    mock_client.return_value = client

    df = scan_s3_bucket("my-bucket")

    assert df.iloc[0]["Encryption"] == "None"
    assert df.iloc[0]["Risk"] == "High"


@patch("scanner.cloud.boto3.client")
def test_scan_s3_bucket_swallows_scan_error_and_returns_empty(mock_client, capsys):
    client = MagicMock()
    client.list_objects_v2.side_effect = NoCredentialsError()
    mock_client.return_value = client

    df = scan_s3_bucket("my-bucket")

    # Dashboard-facing behavior is preserved: empty DataFrame, message printed.
    assert df.empty
    assert "Error scanning S3" in capsys.readouterr().out


@patch("scanner.cloud.boto3.client")
def test_scan_s3_bucket_records_scan_error_when_collector_supplied(mock_client, capsys):
    client = MagicMock()
    client.list_objects_v2.side_effect = NoCredentialsError()
    mock_client.return_value = client

    errors: list[str] = []
    df = scan_s3_bucket("my-bucket", errors=errors)

    # When a caller collects errors, nothing is printed (stdout stays clean
    # for structured output) and the failure is recorded instead.
    assert df.empty
    assert capsys.readouterr().out == ""
    assert errors and "Error scanning S3" in errors[0]


@patch("scanner.cloud.boto3.client")
def test_scan_s3_bucket_findings_raises_on_swallowed_scan_error(mock_client):
    client = MagicMock()
    client.list_objects_v2.side_effect = NoCredentialsError()
    mock_client.return_value = client

    with pytest.raises(CloudScanError):
        scan_s3_bucket_findings("my-bucket")


@patch("scanner.cloud.boto3.client")
def test_scan_s3_bucket_findings_returns_findings_on_success(mock_client):
    mock_client.return_value = _s3_client_with_objects()

    findings = scan_s3_bucket_findings("my-bucket")

    assert len(findings) == 1
    assert findings[0].location == "s3://my-bucket/data.txt"


@patch("scanner.cloud.boto3.client")
def test_scan_s3_bucket_records_per_object_client_error(mock_client):
    # A per-object head_object failure (e.g. AccessDenied) is a coverage gap:
    # the object is skipped from results, but the failure is recorded so a
    # caller can tell an incomplete scan from an empty bucket.
    client = MagicMock()
    client.list_objects_v2.return_value = {
        "Contents": [{"Key": "data.txt", "Size": 10, "LastModified": "2026-01-01"}]
    }
    client.head_object.side_effect = ClientError({"Error": {"Code": "AccessDenied"}}, "HeadObject")
    mock_client.return_value = client

    errors: list[str] = []
    df = scan_s3_bucket("my-bucket", errors=errors)

    assert df.empty
    assert errors and "s3://my-bucket/data.txt" in errors[0]


@patch("scanner.cloud.boto3.client")
def test_scan_s3_bucket_paginates_all_pages(mock_client):
    # list_objects_v2 caps each response at 1,000 keys and signals more with
    # IsTruncated/NextContinuationToken. The scanner must follow every page,
    # otherwise a large bucket is silently reported as complete after page one.
    client = MagicMock()
    client.list_objects_v2.side_effect = [
        {
            "Contents": [{"Key": "page1.txt", "Size": 10, "LastModified": "2026-01-01"}],
            "IsTruncated": True,
            "NextContinuationToken": "token-1",
        },
        {
            "Contents": [{"Key": "page2.txt", "Size": 20, "LastModified": "2026-01-02"}],
            "IsTruncated": False,
        },
    ]
    client.head_object.return_value = {"ServerSideEncryption": "AES256"}
    mock_client.return_value = client

    df = scan_s3_bucket("my-bucket")

    assert client.list_objects_v2.call_count == 2
    # The second call must forward the continuation token from the first page.
    assert client.list_objects_v2.call_args_list[1].kwargs["ContinuationToken"] == "token-1"
    assert list(df["Location"]) == [
        "s3://my-bucket/page1.txt",
        "s3://my-bucket/page2.txt",
    ]


@patch("scanner.cloud.boto3.client")
def test_scan_s3_bucket_findings_raises_on_per_object_client_error(mock_client):
    # The findings wrapper must not return empty/exit clean when head_object
    # coverage failed: it propagates the coverage gap as a CloudScanError.
    client = MagicMock()
    client.list_objects_v2.return_value = {
        "Contents": [{"Key": "data.txt", "Size": 10, "LastModified": "2026-01-01"}]
    }
    client.head_object.side_effect = ClientError({"Error": {"Code": "AccessDenied"}}, "HeadObject")
    mock_client.return_value = client

    with pytest.raises(CloudScanError):
        scan_s3_bucket_findings("my-bucket")
