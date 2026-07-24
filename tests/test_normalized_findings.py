from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd
import pytest

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


def test_sensitive_data_observed_at_is_collection_time_not_file_mtime(tmp_path):
    # Regression: observed_at must be the scan's collection time, not the
    # file's own modification time. A file whose mtime is years in the past
    # must still yield a recent collection timestamp, with the mtime kept
    # only as asset metadata. See ASSET_INVENTORY.md.
    target = tmp_path / "customers.csv"
    target.write_text("name,email\nJane,jane@example.com\n")
    old_mtime = datetime(2000, 1, 1, tzinfo=timezone.utc).timestamp()
    os.utime(target, (old_mtime, old_mtime))

    # observed_at is normalized to whole-second resolution, so widen the
    # window by a second on each side to stay robust to truncation.
    before = datetime.now(timezone.utc) - timedelta(seconds=1)
    findings = scan_filesystem_for_sensitive_data_findings(str(tmp_path))
    after = datetime.now(timezone.utc) + timedelta(seconds=1)

    payload = findings[0].to_dict()
    observed_at = datetime.fromisoformat(payload["observed_at"])
    assert before <= observed_at <= after
    assert observed_at.year != 2000
    # The file's own mtime is preserved as asset metadata, not as observed_at.
    assert payload["technical_metadata"]["Modified"] is not None


def test_sensitive_data_normalized_finding_never_contains_raw_matched_values(tmp_path):
    # Contract: the sensitive-data classifier emits category names and counts
    # only. Raw matched values must never reach evidence, technical_metadata,
    # or the serialized JSON -- a scan result must not itself leak the
    # sensitive data it found. Secret-shaped values are assembled at runtime
    # (never committed as source literals) so this test file trips no secret
    # scanner; see tests/test_classifier.py's _fake_* helpers for the same
    # technique. This exercises the real classifier -> adapter -> serialization
    # path, not a mock of it.
    email = "jane.doe@example.com"
    slack_token = "-".join(["xoxb", "FAKE0000000000", "TESTONLYNOTREAL"])
    aws_key = "AKIA" + "FAKE0000FAKE0000"
    raw_values = [email, slack_token, aws_key]

    (tmp_path / "leaked.env").write_text(
        f"CONTACT_EMAIL={email}\nSLACK_TOKEN={slack_token}\naws_access_key_id = {aws_key}\n"
    )

    findings = scan_filesystem_for_sensitive_data_findings(str(tmp_path))

    assert len(findings) == 1
    payload = findings[0].to_dict()
    serialized = json.dumps(payload)
    for raw in raw_values:
        assert raw not in serialized, f"raw matched value leaked into normalized finding: {raw!r}"
    # The finding is still evidence: category names and a total count survive,
    # so downstream consumers know what was observed without the raw values.
    assert "Email" in payload["technical_metadata"]["Categories"]
    assert payload["technical_metadata"]["Total Matches"] >= 3


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


def test_cloud_adapters_use_collection_time_for_observed_at_not_source_modified():
    # Acceptance criteria (S3, GCS, Azure Blob): the object/blob's own
    # modification time is a property of the asset and must stay in
    # technical_metadata; observed_at is HarvestGuard's collection time, passed
    # in by the scan wrapper. The two must not be conflated even when the
    # source was last modified years before the scan.
    source_modified = datetime(2001, 2, 3, 4, 5, 6, tzinfo=timezone.utc)
    collected_at = datetime(2026, 7, 24, 12, 0, 0, tzinfo=timezone.utc)

    adapters = {
        normalize_s3_df: "s3://bucket/key.txt",
        normalize_gcs_df: "gs://bucket/key.txt",
        normalize_azure_blob_df: "https://acct.blob.core.windows.net/container/key.txt",
    }
    for adapter, location in adapters.items():
        df = pd.DataFrame([{
            "Location": location,
            "Size": 1,
            "Modified": source_modified,
            "Encryption": "None",
        }])

        payload = adapter(df, observed_at=collected_at)[0].to_dict()

        assert payload["observed_at"] == "2026-07-24T12:00:00+00:00"
        # The source modified time is preserved as asset metadata, distinct
        # from observed_at -- never substituted for it.
        assert payload["technical_metadata"]["Modified"] == "2001-02-03T04:05:06+00:00"
        assert payload["observed_at"] != payload["technical_metadata"]["Modified"]


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
    monkeypatch.setattr(s3_scanner, "scan_s3_bucket", lambda bucket, prefix="", errors=None: df)
    monkeypatch.setattr(gcs_scanner, "scan_gcs_bucket", lambda bucket, prefix="", errors=None: df)
    monkeypatch.setattr(
        azure_scanner,
        "scan_azure_container",
        lambda account_url, container_name, prefix="", errors=None: df,
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


# --- finding_id: canonical identity -----------------------------------------


def _finding(**overrides):
    base = dict(
        source_type="local_filesystem",
        asset_type="file",
        location="/tmp/example.pem",
        scanner_name="filesystem",
        scanner_version="0.1.0",
        evidence="Encryption status observed: File-level (OpenSSL)",
        confidence="High",
        rule_id="file_signature:file_level_openssl",
    )
    base.update(overrides)
    return NormalizedFinding(**base)


def test_finding_id_stable_across_equivalent_construction():
    assert _finding().finding_id == _finding().finding_id


def test_finding_id_unaffected_by_scan_id():
    assert _finding(scan_id="scan-a").finding_id == _finding(scan_id="scan-b").finding_id


def test_finding_id_unaffected_by_observed_at():
    a = _finding(observed_at=datetime(2026, 1, 1, tzinfo=timezone.utc))
    b = _finding(observed_at=datetime(2099, 1, 1, tzinfo=timezone.utc))
    assert a.finding_id == b.finding_id


def test_finding_id_unaffected_by_collection_source():
    a = _finding(collection_source="host-a")
    b = _finding(collection_source="host-b")
    assert a.finding_id == b.finding_id


def test_finding_id_unaffected_by_confidence_and_rationale():
    a = _finding(confidence="High", confidence_rationale="a")
    b = _finding(confidence="Low", confidence_rationale="b")
    assert a.finding_id == b.finding_id


def test_finding_id_unaffected_by_ownership_signals():
    a = _finding(ownership_signals={"uid": 501, "mode_octal": "0644"})
    b = _finding(ownership_signals={"uid": 0, "mode_octal": "0600"})
    assert a.finding_id == b.finding_id


def test_finding_id_unaffected_by_unknowns_and_limitations():
    a = _finding(unknowns=["x"], limitations=["permission denied"])
    b = _finding(unknowns=[], limitations=[])
    assert a.finding_id == b.finding_id


def test_finding_id_unaffected_by_technical_metadata():
    a = _finding(technical_metadata={"Size": 12, "Modified": "2026-01-01T00:00:00+00:00"})
    b = _finding(technical_metadata={"Size": 999, "Modified": "2099-01-01T00:00:00+00:00"})
    assert a.finding_id == b.finding_id


def test_finding_id_differs_for_different_rule_id():
    a = _finding(rule_id="file_signature:file_level_openssl")
    b = _finding(rule_id="volume_status:unencrypted")
    assert a.finding_id != b.finding_id


def test_finding_id_unaffected_by_evidence_wording():
    # Human-readable wording changes must not churn ids -- evidence is the
    # prose description, rule_id is the machine-stable observation type.
    a = _finding(evidence="Encryption status observed: File-level (OpenSSL)")
    b = _finding(evidence="Totally different human-readable phrasing of the same finding")
    assert a.finding_id == b.finding_id


def test_finding_id_unaffected_by_schema_version():
    # Schema-format changes must not churn logical Finding ids.
    a = _finding(schema_version="1.0.0")
    b = _finding(schema_version="2.0.0")
    assert a.finding_id == b.finding_id


def test_finding_id_differs_for_different_location():
    a = _finding(location="/tmp/one.pem")
    b = _finding(location="/tmp/two.pem")
    assert a.finding_id != b.finding_id


def test_finding_id_differs_for_different_identity_key():
    a = _finding(identity_key="fingerprint-a")
    b = _finding(identity_key="fingerprint-b")
    assert a.finding_id != b.finding_id


def test_finding_id_differs_when_identity_key_present_vs_absent():
    a = _finding(identity_key=None)
    b = _finding(identity_key="fingerprint-a")
    assert a.finding_id != b.finding_id


def test_finding_id_stable_for_same_identity_key_across_equivalent_scans():
    early = datetime(2026, 1, 1, tzinfo=timezone.utc)
    late = datetime(2099, 6, 1, tzinfo=timezone.utc)
    a = _finding(identity_key="fingerprint-a", observed_at=early)
    b = _finding(identity_key="fingerprint-a", observed_at=late)
    assert a.finding_id == b.finding_id


def test_finding_id_unaffected_by_identity_key_is_not_a_business_field():
    # identity_key must not leak into user-facing fields -- it's a pure
    # technical discriminator, not a recommendation/business concept.
    finding = _finding(identity_key="deadbeef")
    payload = finding.to_dict()
    assert payload["identity_key"] == "deadbeef"
    assert "recommendation" not in payload
    assert "business" not in json.dumps(payload).lower()


# --- recursive immutability --------------------------------------------------


def test_technical_metadata_nested_structures_are_immutable():
    finding = _finding(technical_metadata={"nested": {"a": [1, 2, 3]}})

    with pytest.raises(TypeError):
        finding.technical_metadata["nested"] = "mutated"
    with pytest.raises(TypeError):
        finding.technical_metadata["nested"]["a"] = "mutated"
    with pytest.raises(TypeError):
        finding.technical_metadata["nested"]["a"][0] = 99


def test_ownership_signals_nested_structures_are_immutable():
    finding = _finding(ownership_signals={"uid": 501, "mode_octal": "0644"})

    with pytest.raises(TypeError):
        finding.ownership_signals["uid"] = 0


def test_unknowns_limitations_errors_cannot_be_mutated_in_place():
    finding = _finding(
        unknowns=["a"], limitations=["b"], errors=["c"],
    )

    with pytest.raises(AttributeError):
        finding.unknowns.append("d")
    with pytest.raises(AttributeError):
        finding.limitations.append("d")
    with pytest.raises(AttributeError):
        finding.errors.append("d")


def _self_signed_cert_pem(common_name: str) -> bytes:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime(2026, 1, 1, tzinfo=timezone.utc))
        .not_valid_after(datetime(2030, 1, 1, tzinfo=timezone.utc))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


def test_pkcs12_bundle_with_multiple_certificates_has_unique_finding_ids():
    # Regression test for a confirmed collision: bundle.p12 has a container
    # certificate and an additional certificate with identical evidence text
    # ("PKCS#12 ... certificate parsed"), the same location, asset_type, and
    # scanner_name, and no rule_id -- only the fingerprint-derived
    # identity_key distinguishes them.
    findings = scan_crypto_inventory_findings(str(FIXTURE_DIR / "bundle.p12"))
    cert_findings = [f for f in findings if f.asset_type == "PKCS#12 Certificate"]

    assert len(cert_findings) == 2
    assert cert_findings[0].identity_key is not None
    assert cert_findings[0].identity_key != cert_findings[1].identity_key
    assert len({f.finding_id for f in findings}) == len(findings)


def test_pem_file_with_multiple_certificates_has_unique_finding_ids(tmp_path):
    bundle = tmp_path / "chain.pem"
    bundle.write_bytes(
        _self_signed_cert_pem("cert-a.harvestguard.test")
        + _self_signed_cert_pem("cert-b.harvestguard.test")
    )

    findings = scan_crypto_inventory_findings(str(bundle))
    cert_findings = [f for f in findings if f.asset_type == "PEM Certificate"]

    assert len(cert_findings) == 2
    # Both certs share source_type/asset_type/location/scanner_name/rule_id;
    # only identity_key (the fingerprint) disambiguates them.
    assert cert_findings[0].rule_id == cert_findings[1].rule_id is None
    assert cert_findings[0].identity_key != cert_findings[1].identity_key
    assert cert_findings[0].finding_id != cert_findings[1].finding_id


def test_pem_multi_certificate_finding_ids_stable_across_equivalent_scans(tmp_path):
    bundle = tmp_path / "chain.pem"
    bundle.write_bytes(
        _self_signed_cert_pem("cert-a.harvestguard.test")
        + _self_signed_cert_pem("cert-b.harvestguard.test")
    )

    first = {f.identity_key: f.finding_id for f in scan_crypto_inventory_findings(str(bundle))}
    second = {f.identity_key: f.finding_id for f in scan_crypto_inventory_findings(str(bundle))}

    assert first == second


def test_code_analysis_same_line_multiple_rules_have_unique_finding_ids(monkeypatch):
    # Regression test for a confirmed collision: a single line can match two
    # independent semgrep rules (DES.new(key, DES.MODE_ECB) matches both
    # weak-cipher-des and weak-cipher-ecb-mode), producing identical
    # source_type/asset_type/location/scanner_name with no rule_id set.
    df = pd.DataFrame([
        {"Location": "/repo/cipher.py:3", "Rule": "weak-cipher-des", "Message": "DES is weak"},
        {"Location": "/repo/cipher.py:3", "Rule": "weak-cipher-ecb-mode", "Message": "ECB is weak"},
    ])

    findings = normalize_code_analysis_df(df)

    assert findings[0].location == findings[1].location
    assert findings[0].rule_id != findings[1].rule_id
    assert findings[0].finding_id != findings[1].finding_id


def test_frozen_structures_still_serialize_to_plain_json_types():
    finding = _finding(
        technical_metadata={"nested": {"a": [1, 2, 3]}},
        ownership_signals={"uid": 501},
        unknowns=["u1"],
        limitations=["l1"],
        errors=["e1"],
    )

    payload = finding.to_dict()

    assert payload["technical_metadata"] == {"nested": {"a": [1, 2, 3]}}
    assert isinstance(payload["technical_metadata"]["nested"]["a"], list)
    assert payload["ownership_signals"] == {"uid": 501}
    assert payload["unknowns"] == ["u1"]
    assert isinstance(payload["unknowns"], list)
    json.dumps(payload)  # must not raise


# --- typed Provenance ---------------------------------------------------------


def test_provenance_property_mirrors_flat_fields_without_changing_constructor():
    finding = _finding(
        collection_method="stat + signature scan",
        collection_source="/tmp",
        rule_id="file_signature:file_level_openssl",
        repeatable=True,
        verification_rationale="Signature matched.",
    )

    provenance = finding.provenance

    assert provenance.scanner_name == finding.scanner_name
    assert provenance.scanner_version == finding.scanner_version
    assert provenance.collection_method == finding.collection_method
    assert provenance.source == finding.collection_source
    assert provenance.rule_id == finding.rule_id
    assert provenance.repeatable == finding.repeatable
    assert provenance.verification_rationale == finding.verification_rationale

    payload = finding.to_dict()
    assert payload["provenance"] == provenance.to_dict()
    # Flat keys remain for existing callers alongside the new nested view.
    assert payload["collection_method"] == finding.collection_method
    assert payload["rule_id"] == finding.rule_id
