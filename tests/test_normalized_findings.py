from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

import code_analysis.scanner as code_scanner
import scanner.azure_blob as azure_scanner
import scanner.cloud as s3_scanner
import scanner.gcs as gcs_scanner
from classifier.scanner import scan_filesystem_for_sensitive_data_findings
from finding_adapters import (
    normalize_azure_blob_df,
    normalize_code_analysis_df,
    normalize_crypto_inventory_df,
    normalize_filesystem_df,
    normalize_gcs_df,
    normalize_s3_df,
)
from findings import NormalizedFinding, findings_to_dicts
from scanner.crypto_inventory import scan_crypto_inventory_findings
from scanner.filesystem import scan_filesystem_findings

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "crypto_inventory"


def test_normalized_finding_serializes_to_json_compatible_dict():
    finding = NormalizedFinding(
        scan_id="scan-1",
        source_type="local_filesystem",
        asset_type="file",
        location="/tmp/example.pem",
        scanner_name="test_scanner",
        scanner_version="0.1.0",
        observed_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        evidence="PEM marker observed",
        confidence="High",
        errors=["partial parse"],
        technical_metadata={"Key Size": 2048.0, "Empty": float("nan")},
    )

    payload = finding.to_dict()

    assert payload["schema_version"] == "1.0.0"
    assert payload["scan_id"] == "scan-1"
    assert payload["asset_name"] == "example.pem"
    assert payload["technical_metadata"]["Key Size"] == 2048
    assert payload["technical_metadata"]["Empty"] is None
    assert payload["errors"] == ["partial parse"]
    json.dumps(payload)


def test_normalized_findings_do_not_include_assessment_fields():
    df = pd.DataFrame(
        [{
            "Location": "/tmp/plain.txt",
            "Size": 12,
            "Modified": datetime(2026, 1, 1),
            "Encryption": "Unencrypted",
            "Confidence": "Medium",
            "Confidence Rationale": "Volume-level fallback used.",
            "UID": 501,
            "Owner Name": "tim",
            "GID": 20,
            "Group Name": "staff",
            "Mode Octal": "0644",
            "Permissions": "-rw-r--r--",
            "ACL Present": False,
            "Rule ID": "volume_status:unencrypted",
            "Verification Rationale": "Volume-level status applied.",
            "Repeatable": True,
            "Collection Method": "stat + leading-byte signature scan with volume-level fallback",
            "Collection Source": "test-host",
            "Collected At": datetime(2026, 1, 1),
            "Unknowns": ["File-level encryption status cannot be established conclusively."],
            "Limitations": [],
            # Assessment data a scanner must not leak into the evidence layer.
            "Risk": "High",
        }]
    )

    finding = normalize_filesystem_df(df)[0].to_dict()

    assert "risk" not in finding
    assert "Risk" not in finding
    assert "Risk" not in finding["technical_metadata"]
    assert "Risk" not in finding["ownership_signals"]
    assert finding["technical_metadata"]["Encryption"] == "Unencrypted"
    assert finding["ownership_signals"] == {
        "uid": 501,
        "owner_name": "tim",
        "gid": 20,
        "group_name": "staff",
        "mode_octal": "0644",
        "permissions": "-rw-r--r--",
        "acl_present": False,
    }


def test_filesystem_scanner_can_return_normalized_findings(tmp_path, monkeypatch):
    import scanner.filesystem as fs_module

    monkeypatch.setattr(fs_module, "_detect_volume_encryption", lambda mount: "Unencrypted")
    (tmp_path / "plain.txt").write_text("hello")

    findings = scan_filesystem_findings(str(tmp_path), scan_id="scan-fs")

    assert len(findings) == 1
    payload = findings[0].to_dict()
    assert payload["scan_id"] == "scan-fs"
    assert payload["source_type"] == "local_filesystem"
    assert payload["asset_type"] == "file"
    assert payload["technical_metadata"]["Encryption"] == "Unencrypted"
    assert payload["confidence"] == "Medium"


def test_crypto_inventory_scanner_can_return_normalized_findings():
    findings = scan_crypto_inventory_findings(str(FIXTURE_DIR / "encrypted_key.pem"))

    assert len(findings) == 1
    payload = findings[0].to_dict()
    assert payload["source_type"] == "crypto_inventory"
    assert payload["asset_type"] == "Encrypted PEM Private Key"
    assert payload["technical_metadata"]["Key Size"] is None
    assert any("requires a passphrase" in error for error in payload["errors"])


def test_sensitive_data_classifier_can_return_normalized_findings(tmp_path):
    (tmp_path / "customers.csv").write_text("name,email\nJane,jane@example.com\n")

    findings = scan_filesystem_for_sensitive_data_findings(str(tmp_path))

    assert len(findings) == 1
    payload = findings[0].to_dict()
    assert payload["source_type"] == "local_sensitive_data"
    assert payload["technical_metadata"]["Categories"] == "Email"
    assert payload["technical_metadata"]["Total Matches"] == 1


def test_cloud_scanner_adapters_preserve_provider_metadata():
    modified = datetime(2026, 1, 1, tzinfo=timezone.utc)
    s3 = normalize_s3_df(
        pd.DataFrame([{
            "Location": "s3://bucket/key.txt",
            "Size": 1,
            "Modified": modified,
            "Encryption": "AES256",
            "Risk": "Low",
        }])
    )[0].to_dict()
    gcs = normalize_gcs_df(
        pd.DataFrame([{
            "Location": "gs://bucket/key.txt",
            "Size": 1,
            "Modified": modified,
            "Encryption": "CMEK",
            "Risk": "Low",
        }])
    )[0].to_dict()
    azure = normalize_azure_blob_df(
        pd.DataFrame([{
            "Location": "https://acct.blob.core.windows.net/container/key.txt",
            "Size": 1,
            "Modified": modified,
            "Encryption": "Microsoft-managed",
            "Risk": "Medium",
        }])
    )[0].to_dict()

    assert s3["source_type"] == "aws_s3"
    assert s3["technical_metadata"]["Encryption"] == "AES256"
    assert gcs["source_type"] == "gcs"
    assert gcs["technical_metadata"]["Encryption"] == "CMEK"
    assert azure["source_type"] == "azure_blob"
    assert azure["technical_metadata"]["Encryption"] == "Microsoft-managed"
    assert "Risk" not in s3["technical_metadata"]


def test_code_analysis_adapter_preserves_rule_evidence_without_risk():
    findings = normalize_code_analysis_df(
        pd.DataFrame([{
            "Location": "/repo/app.py:3",
            "Rule": "weak-hash-md5",
            "Message": "MD5 is weak",
            "Risk": "High",
        }])
    )

    payload = findings[0].to_dict()

    assert payload["source_type"] == "code_analysis"
    assert payload["technical_metadata"] == {
        "Rule": "weak-hash-md5",
        "Message": "MD5 is weak",
    }
    assert "Risk" not in payload["technical_metadata"]


def test_cloud_scanner_wrappers_can_return_normalized_findings(monkeypatch):
    df = pd.DataFrame([{
        "Location": "s3://bucket/key.txt",
        "Size": 1,
        "Modified": datetime(2026, 1, 1, tzinfo=timezone.utc),
        "Encryption": "AES256",
        "Risk": "Low",
    }])
    monkeypatch.setattr(s3_scanner, "scan_s3_bucket", lambda bucket, prefix="": df)
    monkeypatch.setattr(gcs_scanner, "scan_gcs_bucket", lambda bucket, prefix="": df)
    monkeypatch.setattr(
        azure_scanner,
        "scan_azure_container",
        lambda account_url, container_name, prefix="": df,
    )

    assert s3_scanner.scan_s3_bucket_findings("bucket")[0].source_type == "aws_s3"
    assert gcs_scanner.scan_gcs_bucket_findings("bucket")[0].source_type == "gcs"
    assert (
        azure_scanner.scan_azure_container_findings("https://acct.blob.core.windows.net", "c")[
            0
        ].source_type
        == "azure_blob"
    )


def test_code_analysis_wrapper_can_return_normalized_findings(monkeypatch):
    monkeypatch.setattr(
        code_scanner,
        "scan_source_for_crypto_usage",
        lambda path: pd.DataFrame([{
            "Location": "/repo/app.py:3",
            "Rule": "weak-hash-md5",
            "Message": "MD5 is weak",
            "Risk": "High",
        }]),
    )

    findings = code_scanner.scan_source_for_crypto_usage_findings("/repo")

    assert findings[0].source_type == "code_analysis"
    assert findings_to_dicts(findings)[0]["technical_metadata"]["Rule"] == "weak-hash-md5"


def test_crypto_inventory_adapter_preserves_scanner_specific_metadata():
    df = pd.DataFrame([{
        "Asset Type": "PEM Certificate",
        "Location": "/tmp/cert.pem",
        "Algorithm": "RSA",
        "Key Size": 2048,
        "Signature Algorithm": "sha256",
        "Expiration": "2027-01-01T00:00:00+00:00",
        "Issuer": "CN=issuer",
        "Subject": "CN=subject",
        "Fingerprint": "abc123",
        "Evidence": "PEM Certificate parsed successfully",
        "Confidence": "High",
        "Errors": "",
        "Scanner": "crypto_inventory",
        "Scanner Version": "0.1.0",
        "Observed At": "2026-01-01T00:00:00+00:00",
    }])

    finding = normalize_crypto_inventory_df(df)[0].to_dict()

    assert finding["asset_type"] == "PEM Certificate"
    assert finding["technical_metadata"]["Algorithm"] == "RSA"
    assert finding["technical_metadata"]["Fingerprint"] == "abc123"
    assert finding["errors"] == []
