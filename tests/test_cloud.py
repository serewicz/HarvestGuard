"""Tests for scanner/cloud.py's S3 head_object error handling.

These exercise the REAL per-object ClientError path inside
_collect_s3_objects (boto3 is stubbed at the client boundary, not the
scanner function), distinguishing genuinely-absent objects -- skipped --
from provider/auth/execution failures, which must propagate so the CLI
exits nonzero instead of reporting an incomplete scan as success.
"""

from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError

import harvestguard
from scanner.cloud import scan_s3_bucket, scan_s3_bucket_findings


def _client_error(code: str, operation: str = "HeadObject") -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": f"fake {code}"}}, operation)


def _listing(*keys: str) -> dict:
    return {
        "Contents": [
            {"Key": key, "Size": 10, "LastModified": "2026-01-01"} for key in keys
        ]
    }


def _head_ok(**_kwargs) -> dict:
    return {"ServerSideEncryption": "AES256"}


@patch("scanner.cloud.boto3.client")
def test_absent_object_during_head_is_skipped_not_fatal(mock_client_cls):
    # A key deleted between list_objects_v2 and head_object is an absent
    # object, not an execution failure: skip it, keep the rest, don't raise.
    s3 = MagicMock()
    s3.list_objects_v2.return_value = _listing("gone.csv", "still-here.csv")
    s3.head_object.side_effect = [_client_error("404"), _head_ok()]
    mock_client_cls.return_value = s3

    findings = scan_s3_bucket_findings("acme-bucket")

    assert len(findings) == 1
    assert findings[0].location == "s3://acme-bucket/still-here.csv"


@pytest.mark.parametrize(
    "code", ["ExpiredToken", "AccessDenied", "InvalidAccessKeyId", "SlowDown"]
)
@patch("scanner.cloud.boto3.client")
def test_auth_and_execution_failures_during_head_propagate(mock_client_cls, code):
    s3 = MagicMock()
    s3.list_objects_v2.return_value = _listing("data.csv")
    s3.head_object.side_effect = _client_error(code)
    mock_client_cls.return_value = s3

    with pytest.raises(ClientError):
        scan_s3_bucket_findings("acme-bucket")


@patch("scanner.cloud.boto3.client")
def test_client_error_without_a_code_propagates(mock_client_cls):
    # Fail closed: an unrecognizable error shape must not be treated as a
    # skippable absent object.
    s3 = MagicMock()
    s3.list_objects_v2.return_value = _listing("data.csv")
    s3.head_object.side_effect = ClientError({"Error": {}}, "HeadObject")
    mock_client_cls.return_value = s3

    with pytest.raises(ClientError):
        scan_s3_bucket_findings("acme-bucket")


@patch("scanner.cloud.boto3.client")
def test_cli_exits_nonzero_when_head_object_hits_an_auth_failure(
    mock_client_cls, capsys, monkeypatch
):
    # End-to-end through the real scanner (only boto3 is stubbed): the
    # head_object auth failure must reach the CLI's scanner-error path and
    # produce a nonzero exit with clean JSON on stdout -- this is the exact
    # incomplete-scan-reported-as-success defect from the Codex review.
    import json

    s3 = MagicMock()
    s3.list_objects_v2.return_value = _listing("a.csv", "b.csv")
    s3.head_object.side_effect = [_head_ok(), _client_error("ExpiredToken")]
    mock_client_cls.return_value = s3

    exit_code = harvestguard.main(["scan", "acme-bucket", "--type", "s3", "--json"])

    captured = capsys.readouterr()
    assert exit_code == harvestguard.EXIT_SCANNER_ERROR
    json.loads(captured.out)  # stdout stays machine-readable
    assert "ExpiredToken" in captured.err


@patch("scanner.cloud.boto3.client")
def test_successful_scan_behavior_is_unchanged(mock_client_cls):
    s3 = MagicMock()
    s3.list_objects_v2.return_value = _listing("enc.csv")
    s3.head_object.return_value = _head_ok()
    mock_client_cls.return_value = s3

    findings = scan_s3_bucket_findings("acme-bucket")

    assert len(findings) == 1
    assert findings[0].location == "s3://acme-bucket/enc.csv"


@patch("scanner.cloud.boto3.client")
def test_dashboard_wrapper_still_swallows_failures_to_stderr(mock_client_cls, capsys):
    # scan_s3_bucket (the Streamlit view) keeps its documented behavior:
    # failures become an empty DataFrame + stderr message, never stdout.
    s3 = MagicMock()
    s3.list_objects_v2.return_value = _listing("data.csv")
    s3.head_object.side_effect = _client_error("AccessDenied")
    mock_client_cls.return_value = s3

    df = scan_s3_bucket("acme-bucket")

    captured = capsys.readouterr()
    assert df.empty
    assert captured.out == ""
    assert "Error scanning S3" in captured.err
