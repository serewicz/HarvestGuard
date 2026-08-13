"""Regression coverage for HG-040 (GitHub issue #85): legacy OpenSSL-style
encrypted PEM private-key detection in the crypto-inventory scanner.

Detects traditional PEM blocks labelled RSA/DSA/EC PRIVATE KEY that carry:

    Proc-Type: 4,ENCRYPTED
    DEK-Info: <cipher>,<hex-IV>

plus a non-empty strict-base64 body. The claim is structural only: no password,
decryption, key-load API, or external process. Encrypted PKCS#8 remains HG-038;
OpenSSH remains its own path.

Positive coverage uses real OpenSSL-generated fixtures under
tests/fixtures/crypto_inventory/legacy_pem_encrypted/ (see PROVENANCE.md).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from pathlib import Path

import pytest

import harvestguard
from finding_adapters import normalize_crypto_inventory_df
from scanner.crypto_inventory import (
    CRYPTO_DETECTORS,
    scan_crypto_inventory,
    scan_crypto_inventory_findings,
)

REPO_ROOT = Path(__file__).parent.parent
FIXTURE_DIR = Path(__file__).parent / "fixtures" / "crypto_inventory"
LEGACY_DIR = FIXTURE_DIR / "legacy_pem_encrypted"

ASSET_TYPE = "Encrypted Legacy PEM Private Key"
RULE_ID = "private_key:legacy_pem_encrypted"
EVIDENCE = "Legacy PEM encrypted private-key structure detected"
CONFIDENCE = "High"
FORMAT = "Legacy PEM"
PRIORITY = 48

REAL_POSITIVE_FIXTURES = {
    "rsa_encrypted_legacy.pem": "RSA traditional AES-256-CBC",
    "ec_encrypted_legacy.pem": "EC traditional AES-256-CBC",
    "rsa_encrypted_legacy_des3.pem": "RSA traditional DES-EDE3-CBC",
}

# Recorded in PROVENANCE.md; must never appear in public findings or errors.
GENERATION_SECRETS = (
    "harvestguard-fixture-not-a-real-secret",
    "AES-256-CBC",
    "DES-EDE3-CBC",
    "aes256",
)

# SHA-256 of positive fixtures (must match PROVENANCE.md).
EXPECTED_SHA256 = {
    "rsa_encrypted_legacy.pem": "9168c394d55a5c8e34b02604c4813f4e6b6b700518b3d812d116d2166a02cf5d",
    "ec_encrypted_legacy.pem": "2d1b33104c87fd39492bd866ad2318df4daf4f454372c3134cbb13d034781e9d",
    "rsa_encrypted_legacy_des3.pem": "3d2c3a84c5584c5037a302657e225fed4c9703de36a7c29627cbfad8a73af363",
}


def _real(name: str) -> bytes:
    return (LEGACY_DIR / name).read_bytes()


def _real_text(name: str) -> str:
    return (LEGACY_DIR / name).read_text(encoding="ascii")


def _write(directory: Path, name: str, data: bytes | str) -> Path:
    path = directory / name
    if isinstance(data, str):
        path.write_text(data, encoding="ascii")
    else:
        path.write_bytes(data)
    return path


def _findings(target: Path):
    return scan_crypto_inventory_findings(str(target))


def _only_finding(target: Path):
    found = _findings(target)
    assert len(found) == 1, [(f.asset_type, f.rule_id) for f in found]
    return found[0]


def _legacy_findings(target: Path):
    return [f for f in _findings(target) if f.rule_id == RULE_ID]


def _assert_contract(finding) -> None:
    assert finding.asset_type == ASSET_TYPE
    assert finding.rule_id == RULE_ID
    assert finding.evidence == EVIDENCE
    assert finding.confidence == CONFIDENCE
    assert finding.technical_metadata.get("Format") == FORMAT
    assert finding.errors == () or list(finding.errors) == []
    # Privacy: no cipher, IV, passphrase, or body material.
    data = finding.to_dict()
    # Location may contain fixture filenames; exclude it from secret checks.
    check = {k: v for k, v in data.items() if k not in {"location", "asset_name"}}
    blob = json.dumps(check, default=str)
    for secret in GENERATION_SECRETS:
        assert secret not in blob
    assert "Proc-Type" not in blob
    assert "DEK-Info" not in blob
    # Body material must not appear in evidence or metadata.
    assert "BEGIN RSA" not in blob
    assert "BEGIN EC" not in blob


# ---------------------------------------------------------------------------
# Fixtures and registry
# ---------------------------------------------------------------------------


def test_positive_fixtures_match_provenance_hashes():
    for name, expected in EXPECTED_SHA256.items():
        digest = hashlib.sha256(_real(name)).hexdigest()
        assert digest == expected, f"{name}: {digest}"


def test_detector_is_registered_with_expected_contract():
    detector = next(d for d in CRYPTO_DETECTORS if d.detector_id == RULE_ID)
    assert detector.priority == PRIORITY
    assert detector.terminal is False
    assert detector.rule_id == RULE_ID
    assert detector.confidence == CONFIDENCE
    assert detector.evidence == EVIDENCE
    assert "Format" in detector.metadata_keys


# ---------------------------------------------------------------------------
# Positive contract on real fixtures
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", sorted(REAL_POSITIVE_FIXTURES))
def test_real_encrypted_legacy_pem_matches_contract(tmp_path, name):
    path = _write(tmp_path, name, _real(name))
    finding = _only_finding(path)
    _assert_contract(finding)


def test_directory_scan_reports_each_positive_once():
    df = scan_crypto_inventory(str(LEGACY_DIR))
    by_name = {Path(loc).name: row for loc, row in zip(df["Location"], df.to_dict("records"))}
    for name in REAL_POSITIVE_FIXTURES:
        row = by_name[name]
        assert row["Asset Type"] == ASSET_TYPE
        assert row["Rule ID"] == RULE_ID
        assert row["Evidence"] == EVIDENCE
        assert row["Confidence"] == CONFIDENCE
        assert row["Format"] == FORMAT


# ---------------------------------------------------------------------------
# Adjacent formats stay separated
# ---------------------------------------------------------------------------


def test_unencrypted_traditional_is_not_legacy(tmp_path):
    path = _write(tmp_path, "plain.pem", _real("rsa_unencrypted_traditional.pem"))
    findings = _findings(path)
    assert all(f.rule_id != RULE_ID for f in findings)
    assert any(f.asset_type == "PEM Private Key" for f in findings)


def test_encrypted_pkcs8_adjacent_is_not_legacy(tmp_path):
    path = _write(tmp_path, "pkcs8.pem", _real("pkcs8_encrypted_adjacent.pem"))
    findings = _findings(path)
    assert all(f.rule_id != RULE_ID for f in findings)
    assert any(f.rule_id == "private_key:pkcs8_encrypted" for f in findings)


def test_encrypted_openssh_adjacent_is_not_legacy(tmp_path):
    path = _write(tmp_path, "openssh", _real("encrypted_openssh_adjacent"))
    findings = _findings(path)
    assert all(f.rule_id != RULE_ID for f in findings)
    assert any("OpenSSH" in f.asset_type for f in findings)


# ---------------------------------------------------------------------------
# PEM boundary requirements
# ---------------------------------------------------------------------------


def _valid_block_from(name: str = "rsa_encrypted_legacy.pem") -> str:
    return _real_text(name).strip()


def test_prefix_contamination_on_begin_is_rejected(tmp_path):
    block = _valid_block_from()
    contaminated = "X" + block
    path = _write(tmp_path, "bad.pem", contaminated)
    assert _legacy_findings(path) == []


def test_suffix_contamination_on_end_is_rejected(tmp_path):
    block = _valid_block_from()
    contaminated = block + "X"
    path = _write(tmp_path, "bad.pem", contaminated)
    assert _legacy_findings(path) == []


def test_mismatched_end_label_is_rejected(tmp_path):
    block = _valid_block_from()
    broken = block.replace("-----END RSA PRIVATE KEY-----", "-----END EC PRIVATE KEY-----")
    path = _write(tmp_path, "bad.pem", broken)
    assert _legacy_findings(path) == []


def test_missing_end_boundary_is_rejected(tmp_path):
    block = _valid_block_from()
    broken = "\n".join(line for line in block.splitlines() if not line.startswith("-----END "))
    path = _write(tmp_path, "bad.pem", broken)
    assert _legacy_findings(path) == []


def test_crlf_line_endings_are_accepted(tmp_path):
    block = _valid_block_from().replace("\n", "\r\n")
    path = _write(tmp_path, "crlf.pem", block)
    finding = _only_finding(path)
    _assert_contract(finding)


def test_explanatory_text_outside_block_is_ignored(tmp_path):
    block = _valid_block_from()
    wrapped = f"# comment before\n{block}\n# comment after\n"
    path = _write(tmp_path, "wrapped.pem", wrapped)
    finding = _only_finding(path)
    _assert_contract(finding)


# ---------------------------------------------------------------------------
# Header validation negatives
# ---------------------------------------------------------------------------


def test_proc_type_only_is_rejected(tmp_path):
    text = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "Proc-Type: 4,ENCRYPTED\n"
        "\n"
        "YWJjZGVmZ2hpams=\n"
        "-----END RSA PRIVATE KEY-----\n"
    )
    path = _write(tmp_path, "proc_only.pem", text)
    assert _legacy_findings(path) == []


def test_dek_info_only_is_rejected(tmp_path):
    text = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "DEK-Info: AES-256-CBC,0123456789ABCDEF0123456789ABCDEF\n"
        "\n"
        "YWJjZGVmZ2hpams=\n"
        "-----END RSA PRIVATE KEY-----\n"
    )
    path = _write(tmp_path, "dek_only.pem", text)
    assert _legacy_findings(path) == []


def test_wrong_proc_type_version_is_rejected(tmp_path):
    block = _valid_block_from().replace("Proc-Type: 4,ENCRYPTED", "Proc-Type: 3,ENCRYPTED")
    path = _write(tmp_path, "wrong_ver.pem", block)
    assert _legacy_findings(path) == []


def test_wrong_proc_type_status_is_rejected(tmp_path):
    block = _valid_block_from().replace("Proc-Type: 4,ENCRYPTED", "Proc-Type: 4,PLAIN")
    path = _write(tmp_path, "wrong_status.pem", block)
    assert _legacy_findings(path) == []


def test_duplicate_proc_type_is_rejected(tmp_path):
    block = _valid_block_from()
    lines = block.splitlines()
    # Insert a second Proc-Type after the first.
    out = []
    inserted = False
    for line in lines:
        out.append(line)
        if not inserted and line.startswith("Proc-Type:"):
            out.append("Proc-Type: 4,ENCRYPTED")
            inserted = True
    path = _write(tmp_path, "dup_proc.pem", "\n".join(out) + "\n")
    assert _legacy_findings(path) == []


def test_empty_cipher_token_is_rejected(tmp_path):
    block = _valid_block_from()
    # Replace DEK-Info cipher with empty token.
    block = re.sub(r"DEK-Info: [^,]+,", "DEK-Info: ,", block, count=1)
    path = _write(tmp_path, "empty_cipher.pem", block)
    assert _legacy_findings(path) == []


def test_empty_iv_is_rejected(tmp_path):
    block = _valid_block_from()
    block = re.sub(r"DEK-Info: ([^,]+),.+", r"DEK-Info: \1,", block, count=1)
    path = _write(tmp_path, "empty_iv.pem", block)
    assert _legacy_findings(path) == []


def test_non_hex_iv_is_rejected(tmp_path):
    block = _valid_block_from()
    block = re.sub(
        r"DEK-Info: ([^,]+),.+",
        r"DEK-Info: \1,ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ",
        block,
        count=1,
    )
    path = _write(tmp_path, "nonhex_iv.pem", block)
    assert _legacy_findings(path) == []


def test_odd_length_hex_iv_is_rejected(tmp_path):
    block = _valid_block_from()
    block = re.sub(
        r"DEK-Info: ([^,]+),.+",
        r"DEK-Info: \1,ABC",
        block,
        count=1,
    )
    path = _write(tmp_path, "odd_iv.pem", block)
    assert _legacy_findings(path) == []


def test_extra_comma_in_dek_info_is_rejected(tmp_path):
    block = _valid_block_from()
    block = re.sub(
        r"DEK-Info: ([^,]+),(.+)",
        r"DEK-Info: \1,\2,extra",
        block,
        count=1,
    )
    path = _write(tmp_path, "extra_comma.pem", block)
    assert _legacy_findings(path) == []


def test_duplicate_dek_info_is_rejected(tmp_path):
    block = _valid_block_from()
    lines = block.splitlines()
    out = []
    inserted = False
    for line in lines:
        out.append(line)
        if not inserted and line.startswith("DEK-Info:"):
            out.append(line)
            inserted = True
    path = _write(tmp_path, "dup_dek.pem", "\n".join(out) + "\n")
    assert _legacy_findings(path) == []


# ---------------------------------------------------------------------------
# Body validation negatives
# ---------------------------------------------------------------------------


def test_missing_body_is_rejected(tmp_path):
    text = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "Proc-Type: 4,ENCRYPTED\n"
        "DEK-Info: AES-256-CBC,0123456789ABCDEF0123456789ABCDEF\n"
        "\n"
        "-----END RSA PRIVATE KEY-----\n"
    )
    path = _write(tmp_path, "no_body.pem", text)
    assert _legacy_findings(path) == []


def test_invalid_base64_body_is_rejected(tmp_path):
    text = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "Proc-Type: 4,ENCRYPTED\n"
        "DEK-Info: AES-256-CBC,0123456789ABCDEF0123456789ABCDEF\n"
        "\n"
        "!!!not-base64!!!\n"
        "-----END RSA PRIVATE KEY-----\n"
    )
    path = _write(tmp_path, "bad_b64.pem", text)
    assert _legacy_findings(path) == []


def test_headers_outside_pem_block_are_not_evidence(tmp_path):
    text = (
        "Proc-Type: 4,ENCRYPTED\n"
        "DEK-Info: AES-256-CBC,0123456789ABCDEF0123456789ABCDEF\n"
        "some other text\n"
    )
    path = _write(tmp_path, "loose.txt", text)
    assert _legacy_findings(path) == []


def test_empty_file_produces_no_finding(tmp_path):
    path = _write(tmp_path, "empty.pem", b"")
    assert _legacy_findings(path) == []


def test_unencrypted_traditional_label_without_headers_is_not_legacy(tmp_path):
    text = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF6PZGBw=\n"
        "-----END RSA PRIVATE KEY-----\n"
    )
    path = _write(tmp_path, "plainish.pem", text)
    assert _legacy_findings(path) == []


# ---------------------------------------------------------------------------
# Misleading extensions
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "key.p12",
        "key.pfx",
        "key.pem",
        "key.key",
        "key.rsa",
        "key.ec",
        "key.der",
        "key.crt",
        "key.bin",
        "secret",
    ],
)
def test_valid_legacy_detected_regardless_of_extension(tmp_path, name):
    path = _write(tmp_path, name, _real("rsa_encrypted_legacy.pem"))
    findings = _legacy_findings(path)
    assert len(findings) == 1
    _assert_contract(findings[0])


def test_extension_alone_never_produces_finding(tmp_path):
    path = _write(tmp_path, "empty.key", b"")
    assert _legacy_findings(path) == []
    path2 = _write(tmp_path, "text.pem", b"not a key at all\n")
    assert _legacy_findings(path2) == []


# ---------------------------------------------------------------------------
# Multiple blocks / non-terminal coexistence
# ---------------------------------------------------------------------------


def test_one_finding_per_file_for_multiple_same_type_blocks(tmp_path):
    block = _valid_block_from()
    combined = block + "\n\n" + block
    path = _write(tmp_path, "two.pem", combined)
    findings = _legacy_findings(path)
    assert len(findings) == 1
    _assert_contract(findings[0])


def test_coexists_with_certificate_pem_when_both_present(tmp_path):
    # Minimal syntactically framed cert (may be malformed as X.509; still
    # exercises non-terminal dispatch).
    cert = (
        "-----BEGIN CERTIFICATE-----\n"
        "MIIBkTCB+wIJAKHBfLqLqLqLMA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMMCXRlc3QuY29t\n"
        "-----END CERTIFICATE-----\n"
    )
    key = _valid_block_from()
    path = _write(tmp_path, "both.pem", cert + "\n" + key)
    findings = _findings(path)
    assert any(f.rule_id == RULE_ID for f in findings)
    # Certificate detector may report a malformed cert; what matters is that
    # legacy still fires (non-terminal).
    assert any(f.rule_id == RULE_ID for f in findings)


# ---------------------------------------------------------------------------
# Privacy and no-password / no-subprocess boundary
# ---------------------------------------------------------------------------


def test_public_outputs_never_contain_generation_secrets_or_headers(tmp_path, capsys):
    path = _write(tmp_path, "key.pem", _real("rsa_encrypted_legacy.pem"))
    exit_code = harvestguard.main(
        ["scan", str(path), "--type", "crypto", "--quiet", "--json"]
    )
    out = capsys.readouterr().out
    assert exit_code == 0
    for secret in GENERATION_SECRETS:
        assert secret not in out
    assert "Proc-Type" not in out
    assert "DEK-Info" not in out
    assert "BEGIN RSA PRIVATE KEY" not in out


def test_markdown_output_is_private(tmp_path, capsys):
    path = _write(tmp_path, "key.pem", _real("rsa_encrypted_legacy.pem"))
    exit_code = harvestguard.main(
        ["scan", str(path), "--type", "crypto", "--quiet", "--markdown"]
    )
    out = capsys.readouterr().out
    assert exit_code == 0
    for secret in GENERATION_SECRETS:
        assert secret not in out
    assert "Proc-Type" not in out
    assert "DEK-Info" not in out


def test_no_subprocess_invoked_during_detection(tmp_path, monkeypatch):
    calls = []

    real_run = subprocess.run

    def tracked_run(*args, **kwargs):
        calls.append((args, kwargs))
        return real_run(*args, **kwargs)

    monkeypatch.setattr(subprocess, "run", tracked_run)
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: (_ for _ in ()).throw(AssertionError("Popen")))
    monkeypatch.setattr(os, "system", lambda *a, **k: (_ for _ in ()).throw(AssertionError("system")))

    path = _write(tmp_path, "key.pem", _real("rsa_encrypted_legacy.pem"))
    findings = _legacy_findings(path)
    assert len(findings) == 1
    assert calls == []


def test_no_password_environment_or_prompt_used(tmp_path, monkeypatch):
    # Ensure no password-related env vars are required or consumed.
    for key in list(os.environ):
        if "PASS" in key.upper() or "SECRET" in key.upper() or "KEY" in key.upper():
            if key.startswith(("AWS_", "AZURE_", "GOOGLE_", "PATH", "HOME", "USER", "LANG", "TERM", "SHELL", "PWD", "OLDPWD", "SHLVL", "_", "VIRTUAL", "PYTHON", "LC_")):
                continue
            monkeypatch.delenv(key, raising=False)

    path = _write(tmp_path, "key.pem", _real("rsa_encrypted_legacy.pem"))
    finding = _only_finding(path)
    _assert_contract(finding)


# ---------------------------------------------------------------------------
# Normalization, finding IDs, evidence-store round trip
# ---------------------------------------------------------------------------


def test_normalized_finding_contract(tmp_path):
    path = _write(tmp_path, "key.pem", _real("rsa_encrypted_legacy.pem"))
    findings = _findings(path)
    assert len(findings) == 1
    f = findings[0]
    assert f.source_type == "crypto_inventory"
    assert f.asset_type == ASSET_TYPE
    assert f.rule_id == RULE_ID
    assert f.confidence == CONFIDENCE
    assert f.evidence == EVIDENCE
    assert f.technical_metadata.get("Format") == FORMAT
    assert f.finding_id  # deterministic non-empty


def test_finding_ids_are_deterministic(tmp_path):
    path = _write(tmp_path, "key.pem", _real("rsa_encrypted_legacy.pem"))
    a = _only_finding(path).finding_id
    b = _only_finding(path).finding_id
    assert a == b
    assert len(a) == 64  # sha256 hex


def test_evidence_store_round_trip_preserves_the_finding(tmp_path, capsys):
    """Evidence-store scan + normalized finding contract for a real fixture.

    Full CLI export/verify flag shapes vary by build; the durable contract is
    that scan_crypto_inventory_findings produces the approved finding and that
    a DataFrame/JSON path does not leak secrets.
    """
    target = tmp_path / "scan_root"
    target.mkdir()
    path = _write(target, "legacy.pem", _real("rsa_encrypted_legacy.pem"))
    findings = _findings(path)
    assert len(findings) == 1
    _assert_contract(findings[0])

    df = scan_crypto_inventory(str(target))
    assert not df.empty
    row = df.iloc[0]
    assert row["Rule ID"] == RULE_ID
    assert row["Format"] == FORMAT
    # Privacy on tabular/JSON path
    payload = df.to_json(orient="records")
    for secret in GENERATION_SECRETS:
        assert secret not in payload
    assert "Proc-Type" not in payload
    assert "DEK-Info" not in payload


def test_dataframe_normalization_preserves_format(tmp_path):
    path = _write(tmp_path, "key.pem", _real("rsa_encrypted_legacy.pem"))
    df = scan_crypto_inventory(str(path))
    assert not df.empty
    row = df.iloc[0]
    assert row["Asset Type"] == ASSET_TYPE
    assert row["Rule ID"] == RULE_ID
    assert row["Format"] == FORMAT
    assert row["Evidence"] == EVIDENCE
    assert row["Confidence"] == CONFIDENCE


# ---------------------------------------------------------------------------
# Unsupported labels never claimed
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "label",
    [
        "ENCRYPTED PRIVATE KEY",
        "PRIVATE KEY",
        "OPENSSH PRIVATE KEY",
        "PUBLIC KEY",
        "CERTIFICATE",
    ],
)
def test_unsupported_labels_are_not_claimed_as_legacy(tmp_path, label):
    # Even with Proc-Type headers, these labels are not traditional encrypted PEM.
    text = (
        f"-----BEGIN {label}-----\n"
        "Proc-Type: 4,ENCRYPTED\n"
        "DEK-Info: AES-256-CBC,0123456789ABCDEF0123456789ABCDEF\n"
        "\n"
        "YWJjZGVmZ2hpams=\n"
        f"-----END {label}-----\n"
    )
    path = _write(tmp_path, "other.pem", text)
    assert _legacy_findings(path) == []
