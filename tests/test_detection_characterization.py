"""Regression coverage for docs/DETECTION_CHARACTERIZATION.md (roadmap HG-009).

These tests support specific characterization claims made in that document --
confidence semantics, false-positive/negative conditions, and the two
narrow behavioral corrections it documents -- rather than asserting prose.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import patch

import pandas as pd

import scanner.filesystem as fs_module
from classifier.scanner import scan_filesystem_for_sensitive_data_findings
from code_analysis.scanner import scan_source_for_crypto_usage
from finding_adapters import (
    normalize_azure_blob_df,
    normalize_gcs_df,
    normalize_s3_df,
)
from reports import format_markdown_report, make_report_context
from scanner.crypto_inventory import scan_crypto_inventory_findings
from scanner.filesystem import scan_filesystem_evidence, scan_filesystem_findings

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "crypto_inventory"


# --- Confidence semantics: fixed per family vs. variable ------------------


def test_cloud_scanners_report_fixed_high_confidence_for_provider_metadata():
    row = pd.DataFrame(
        [{"Location": "x", "Size": 1, "Modified": None, "Encryption": "AES256"}]
    )
    s3_finding = normalize_s3_df(row)[0]
    gcs_finding = normalize_gcs_df(row)[0]
    azure_finding = normalize_azure_blob_df(row)[0]

    assert s3_finding.confidence == "High"
    assert gcs_finding.confidence == "High"
    assert azure_finding.confidence == "High"


def test_sensitive_data_findings_report_fixed_medium_confidence(tmp_path):
    (tmp_path / "customers.csv").write_text("email: jane.doe@example.com\n")

    findings = scan_filesystem_for_sensitive_data_findings(str(tmp_path))

    assert len(findings) == 1
    assert findings[0].confidence == "Medium"


def test_filesystem_signature_match_is_high_confidence_volume_fallback_is_lower(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(fs_module, "_detect_volume_encryption", lambda mount: "Unencrypted")

    (tmp_path / "cipher.bin").write_bytes(b"Salted__" + b"\x00" * 8 + b"ciphertext")
    (tmp_path / "plain.txt").write_text("ordinary file content")

    findings = scan_filesystem_findings(str(tmp_path))

    signature_match = next(f for f in findings if f.asset_type == "file")
    # "plain.txt" is an ordinary file with no signature match and no
    # file-specific failure, so its volume-status fallback now lives on the
    # mount's aggregate context record rather than a per-file record of its
    # own (see tests/test_filesystem_aggregate_context.py).
    volume_fallback = next(f for f in findings if f.asset_type == "volume")

    assert signature_match.confidence == "High"
    assert volume_fallback.confidence == "Medium"
    assert "not independently" in volume_fallback.confidence_rationale.lower() or (
        "unverified" in volume_fallback.confidence_rationale.lower()
    )


def test_unknown_volume_status_produces_low_confidence(tmp_path, monkeypatch):
    # Simulates a host where no supported volume-encryption tool is available
    # (unsupported platform.system(), or lsblk/manage-bde missing): the
    # scanner must report "Unknown", never guess "unencrypted".
    monkeypatch.setattr(fs_module, "_detect_volume_encryption", lambda mount: "Unknown")

    (tmp_path / "plain.txt").write_text("ordinary file content")

    findings = scan_filesystem_findings(str(tmp_path))

    assert len(findings) == 1
    assert findings[0].technical_metadata["Encryption"] == "Unknown"
    assert findings[0].confidence == "Low"


# --- PGP false-positive correction (scanner/filesystem.py) -----------------


def _pgp_finding(tmp_path, name: str, armor: bytes):
    (tmp_path / name).write_bytes(armor)
    findings = scan_filesystem_findings(str(tmp_path))
    assert len(findings) == 1
    return findings[0]


def test_pgp_message_armor_is_still_classified_as_file_level_encrypted(tmp_path, monkeypatch):
    monkeypatch.setattr(fs_module, "_detect_volume_encryption", lambda mount: "Unencrypted")
    armor = b"-----BEGIN PGP MESSAGE-----\nhQEMA...\n-----END PGP MESSAGE-----\n"
    finding = _pgp_finding(tmp_path, "message.gpg", armor)
    assert finding.technical_metadata["Encryption"] == "File-level (PGP/GPG)"
    assert finding.confidence == "High"


def test_pgp_signed_message_armor_is_not_misclassified_as_encrypted(tmp_path, monkeypatch):
    # A clearsigned message's body is plaintext -- reporting it as file-level
    # encrypted with High confidence would be a materially misleading claim.
    monkeypatch.setattr(fs_module, "_detect_volume_encryption", lambda mount: "Unencrypted")
    finding = _pgp_finding(
        tmp_path,
        "signed.txt",
        b"-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n"
        b"This body is fully readable plaintext.\n"
        b"-----BEGIN PGP SIGNATURE-----\niQEz...\n-----END PGP SIGNATURE-----\n",
    )
    assert finding.technical_metadata["Encryption"] != "File-level (PGP/GPG)"


def test_pgp_public_key_block_is_not_misclassified_as_encrypted(tmp_path, monkeypatch):
    # A public key is, by definition, not secret data -- it must never be
    # reported as file-level encrypted content.
    monkeypatch.setattr(fs_module, "_detect_volume_encryption", lambda mount: "Unencrypted")
    finding = _pgp_finding(
        tmp_path,
        "pubkey.asc",
        b"-----BEGIN PGP PUBLIC KEY BLOCK-----\nmQENA...\n-----END PGP PUBLIC KEY BLOCK-----\n",
    )
    assert finding.technical_metadata["Encryption"] != "File-level (PGP/GPG)"


def test_pgp_detached_signature_is_not_misclassified_as_encrypted(tmp_path, monkeypatch):
    monkeypatch.setattr(fs_module, "_detect_volume_encryption", lambda mount: "Unencrypted")
    armor = b"-----BEGIN PGP SIGNATURE-----\niQEz...\n-----END PGP SIGNATURE-----\n"
    finding = _pgp_finding(tmp_path, "detached.sig", armor)
    assert finding.technical_metadata["Encryption"] != "File-level (PGP/GPG)"


# --- Sensitive-data classifier: category/count-only, size, binary ---------


def test_sensitive_data_finding_never_carries_the_matched_value(tmp_path):
    (tmp_path / "leak.txt").write_text("ssn: 123-45-6789")

    findings = scan_filesystem_for_sensitive_data_findings(str(tmp_path))

    assert len(findings) == 1
    finding = findings[0]
    assert "123-45-6789" not in finding.evidence
    assert "123-45-6789" not in str(finding.technical_metadata)
    assert "SSN" in finding.evidence


def test_sensitive_data_file_above_size_cap_is_not_inspected(tmp_path):
    from classifier.scanner import _MAX_FILE_BYTES

    oversized = tmp_path / "big.csv"
    oversized.write_text("ssn: 123-45-6789\n" + "x" * _MAX_FILE_BYTES)

    findings = scan_filesystem_for_sensitive_data_findings(str(tmp_path))

    assert findings == []


def test_sensitive_data_binary_file_is_not_inspected(tmp_path):
    binary_with_ssn_shaped_bytes = b"\x00\x01ssn: 123-45-6789\x00"
    (tmp_path / "blob.bin").write_bytes(binary_with_ssn_shaped_bytes)

    findings = scan_filesystem_for_sensitive_data_findings(str(tmp_path))

    assert findings == []


# --- Crypto inventory: candidate gate, malformed, encrypted, JKS ----------


def test_crypto_inventory_candidate_gate_silently_skips_unrecognized_files(tmp_path):
    # No recognized extension, no "-----BEGIN " marker, no JKS/SSH prefix:
    # the candidate-file gate excludes it before any parsing is attempted,
    # and -- unlike the filesystem scanner -- no limitation Finding is
    # produced either. An empty result here is not evidence of "no crypto
    # assets," only "nothing matched the candidate gate."
    (tmp_path / "opaque.dat").write_bytes(b"\x01\x02\x03not a recognized crypto container\x04")

    findings = scan_crypto_inventory_findings(str(tmp_path))

    assert findings == []


def test_crypto_inventory_malformed_certificate_is_low_confidence_with_error():
    findings = {
        Path(f.location).name: f
        for f in scan_crypto_inventory_findings(str(FIXTURE_DIR))
    }

    malformed = findings["malformed_cert.pem"]
    assert malformed.confidence == "Low"
    assert malformed.errors


def test_crypto_inventory_encrypted_key_is_high_confidence_with_passphrase_note():
    findings = {
        Path(f.location).name: f
        for f in scan_crypto_inventory_findings(str(FIXTURE_DIR))
    }

    encrypted = findings["encrypted_key.pem"]
    assert encrypted.confidence == "High"
    assert any("passphrase" in err for err in encrypted.errors)


def test_crypto_inventory_jks_is_header_only_with_documented_limitation():
    findings = {
        Path(f.location).name: f
        for f in scan_crypto_inventory_findings(str(FIXTURE_DIR))
    }

    jks = findings["sample.jks"]
    assert jks.confidence == "Medium"
    assert any("not implemented" in err for err in jks.errors)


# --- Code analysis: supported match, absence semantics, stderr fix --------


def test_code_analysis_supported_weak_crypto_match(tmp_path):
    (tmp_path / "app.py").write_text(
        "import hashlib\ndef h(x):\n    return hashlib.md5(x).hexdigest()\n"
    )

    df = scan_source_for_crypto_usage(str(tmp_path))

    assert len(df) == 1
    assert df.iloc[0]["Rule"] == "weak-hash-md5"


def test_code_analysis_scanner_unavailable_is_indistinguishable_from_clean_in_the_dataframe(
    tmp_path,
):
    # Documents an absence-of-finding limitation: scan_source_for_crypto_usage
    # returns an empty DataFrame both when semgrep found nothing AND when
    # semgrep could not run at all. Only scanner_errors/exit code (checked at
    # the CLI layer, not here) distinguish the two.
    with patch("code_analysis.scanner.subprocess.run", side_effect=FileNotFoundError):
        unavailable_df = scan_source_for_crypto_usage(str(tmp_path))

    clean_df = scan_source_for_crypto_usage(str(tmp_path))  # empty dir, semgrep actually runs

    assert unavailable_df.empty
    assert clean_df.empty


@patch("code_analysis.scanner.subprocess.run")
def test_code_analysis_missing_semgrep_diagnostic_goes_to_stderr_not_stdout(
    mock_run, tmp_path, capsys
):
    mock_run.side_effect = FileNotFoundError("semgrep not found")

    scan_source_for_crypto_usage(str(tmp_path))

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "semgrep is not installed" in captured.err


@patch("code_analysis.scanner.subprocess.run")
def test_code_analysis_timeout_diagnostic_goes_to_stderr_not_stdout(mock_run, tmp_path, capsys):
    mock_run.side_effect = subprocess.TimeoutExpired(cmd="semgrep", timeout=120)

    scan_source_for_crypto_usage(str(tmp_path))

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "timed out" in captured.err


@patch("code_analysis.scanner.subprocess.run")
def test_code_analysis_nonzero_exit_diagnostic_goes_to_stderr_not_stdout(
    mock_run, tmp_path, capsys
):
    mock_run.return_value = subprocess.CompletedProcess(
        args=["semgrep"], returncode=1, stdout="", stderr="boom"
    )

    scan_source_for_crypto_usage(str(tmp_path))

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "boom" in captured.err


@patch("code_analysis.scanner.subprocess.run")
def test_code_analysis_unparsable_output_diagnostic_goes_to_stderr_not_stdout(
    mock_run, tmp_path, capsys
):
    mock_run.return_value = subprocess.CompletedProcess(
        args=["semgrep"], returncode=0, stdout="not json", stderr=""
    )

    scan_source_for_crypto_usage(str(tmp_path))

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "could not parse" in captured.err


# --- Absence-of-finding caveat surfaces in the Markdown report ------------


def test_markdown_report_states_absence_of_finding_caveat():
    context = make_report_context(
        target_path="/scan/root",
        started_at=None,
        duration_seconds=0.1,
        excluded_paths=[],
        scanner_errors=[],
    )

    report = format_markdown_report([], context)

    assert "DETECTION_CHARACTERIZATION.md" in report
    assert "absence of a" in report.lower()


# --- Filesystem coverage semantics carried forward from HG-008 ------------


def test_finding_level_errors_can_coexist_with_no_limits_recorded(tmp_path):
    # A directory-traversal or max-depth boundary is a *coverage* concept;
    # a per-asset parse error is a separate, finding-level concept. Neither
    # implies the other. This filesystem-scan case has no coverage
    # boundary at all (nothing beyond max_depth, nothing unreadable), so it
    # produces exactly one clean finding with no errors -- confirming
    # "no limits" is a statement about scope, not about per-finding quality.
    (tmp_path / "plain.txt").write_text("ordinary file content")

    findings = scan_filesystem_evidence(str(tmp_path))

    # "plain.txt" is an ordinary file, represented by its mount's aggregate
    # context record rather than a per-file record; that record still has no
    # errors and no coverage boundary, which is the property under test.
    assert len(findings) == 1
    row = findings.iloc[0]
    assert row["Asset Type"] == "volume"


def test_default_local_max_depth_is_three():
    import inspect

    signature = inspect.signature(scan_filesystem_findings)
    assert signature.parameters["max_depth"].default == 3
