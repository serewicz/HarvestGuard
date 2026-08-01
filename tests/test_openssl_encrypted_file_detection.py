"""Regression coverage for HG-030 (GitHub issue #66): OpenSSL `Salted__`
encrypted-file detection in the crypto-inventory scanner, deduplication
against the filesystem scanner's existing signature evidence under
`--type all`, and the additive "Crypto files inspected" accounting line.

Complements tests/test_crypto_inventory.py (existing PEM/DER/PKCS#12/JKS/SSH
coverage, left unmodified) and tests/test_filesystem_findings.py (the
filesystem scanner's own, unchanged `file_signature:file_level_openssl`
evidence for the same signature).
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import harvestguard
from finding_adapters import normalize_crypto_inventory_df
from harvestguard import _deduplicate_openssl_encrypted_file_findings
from scanner.crypto_inventory import (
    scan_crypto_inventory,
    scan_crypto_inventory_findings,
)
from scanner.filesystem import scan_filesystem_findings

SALTED_HEADER = b"Salted__"


def _salted_bytes(payload: bytes = b"\x00" * 24) -> bytes:
    return SALTED_HEADER + payload


# --- 1. Exact positive fixture / 8. exact finding contract -----------------


def test_salted_file_produces_encrypted_file_finding_with_exact_contract(tmp_path):
    (tmp_path / "secret.enc").write_bytes(_salted_bytes())

    findings = scan_crypto_inventory_findings(str(tmp_path))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.asset_type == "Encrypted File"
    assert finding.rule_id == "encrypted_file:openssl"
    assert finding.confidence == "High"
    assert finding.source_type == "crypto_inventory"
    assert "Salted__" in finding.evidence
    # Evidence-only: no decryption/strength/business claim.
    for forbidden in ("decrypt", "password", "strong", "weak", "risk", "remediat"):
        assert forbidden not in finding.evidence.lower()


# --- 2. Detection regardless of extension -----------------------------------


def test_salted_file_detected_regardless_of_extension(tmp_path):
    for name in ("secret.enc", "secret.bin", "secret", "secret.dat"):
        (tmp_path / name).write_bytes(_salted_bytes())

    findings = scan_crypto_inventory_findings(str(tmp_path))
    names = {Path(f.location).name for f in findings}

    assert names == {"secret.enc", "secret.bin", "secret", "secret.dat"}
    assert all(f.asset_type == "Encrypted File" for f in findings)


# --- 3/4. Misleading-extension precedence over .p12/.pfx/DER branches ------


def test_salted_file_with_p12_extension_is_not_malformed_pkcs12(tmp_path):
    (tmp_path / "misleading.p12").write_bytes(_salted_bytes())

    findings = scan_crypto_inventory_findings(str(tmp_path))

    assert len(findings) == 1
    assert findings[0].asset_type == "Encrypted File"
    assert findings[0].rule_id == "encrypted_file:openssl"
    assert "Malformed" not in findings[0].asset_type


def test_salted_file_with_der_extension_is_not_malformed_der(tmp_path):
    (tmp_path / "misleading.der").write_bytes(_salted_bytes())

    findings = scan_crypto_inventory_findings(str(tmp_path))

    assert len(findings) == 1
    assert findings[0].asset_type == "Encrypted File"
    assert findings[0].rule_id == "encrypted_file:openssl"
    assert "Malformed" not in findings[0].asset_type


def test_salted_file_with_pfx_extension_is_not_malformed_pkcs12(tmp_path):
    (tmp_path / "misleading.pfx").write_bytes(_salted_bytes())

    findings = scan_crypto_inventory_findings(str(tmp_path))

    assert len(findings) == 1
    assert findings[0].asset_type == "Encrypted File"


# --- 5. Near-match negative --------------------------------------------------


def test_near_match_signature_is_not_detected(tmp_path):
    # One byte short of the real 8-byte signature.
    (tmp_path / "nearmiss1.bin").write_bytes(b"Salted_" + b"\x00" * 24)
    # Wrong case.
    (tmp_path / "nearmiss2.bin").write_bytes(b"salted__" + b"\x00" * 24)

    findings = scan_crypto_inventory_findings(str(tmp_path))

    assert findings == []


def test_signature_with_extra_trailing_byte_is_still_a_true_positive(tmp_path):
    # "Salted___" (9 bytes) still *starts with* the real 8-byte signature --
    # the 9th byte is just the start of the salt/ciphertext, not part of the
    # signature, so this is a genuine match, not a near-miss.
    (tmp_path / "trailing.bin").write_bytes(b"Salted___" + b"\x00" * 24)

    findings = scan_crypto_inventory_findings(str(tmp_path))

    assert len(findings) == 1
    assert findings[0].asset_type == "Encrypted File"


# --- 6. Signature at nonzero offset negative --------------------------------


def test_signature_not_at_offset_zero_is_not_detected(tmp_path):
    (tmp_path / "offset.bin").write_bytes(b"XX" + _salted_bytes())

    findings = scan_crypto_inventory_findings(str(tmp_path))

    assert findings == []


# --- 7. Empty/small file safety ---------------------------------------------


def test_empty_and_small_files_are_handled_safely(tmp_path):
    (tmp_path / "empty.bin").write_bytes(b"")
    (tmp_path / "tiny.bin").write_bytes(b"Salt")  # shorter than the signature

    # Must not raise for any of these; must also not falsely detect them.
    findings = scan_crypto_inventory_findings(str(tmp_path))

    assert findings == []


def test_exact_signature_with_no_trailing_payload_is_still_detected(tmp_path):
    # A file that is *exactly* the 8-byte signature and nothing else.
    (tmp_path / "bare.bin").write_bytes(SALTED_HEADER)

    findings = scan_crypto_inventory_findings(str(tmp_path))

    assert len(findings) == 1
    assert findings[0].asset_type == "Encrypted File"


# --- 9/10. Standalone filesystem-only and crypto-only behavior -------------


def test_filesystem_only_scan_still_reports_file_signature_openssl(tmp_path):
    (tmp_path / "secret.enc").write_bytes(_salted_bytes())

    findings = scan_filesystem_findings(str(tmp_path))
    file_findings = [f for f in findings if f.asset_type == "file"]

    assert len(file_findings) == 1
    assert file_findings[0].rule_id == "file_signature:file_level_openssl"
    assert file_findings[0].confidence == "High"


def test_crypto_only_scan_reports_encrypted_file_openssl(tmp_path):
    (tmp_path / "secret.enc").write_bytes(_salted_bytes())

    findings = scan_crypto_inventory_findings(str(tmp_path))

    assert len(findings) == 1
    assert findings[0].rule_id == "encrypted_file:openssl"


# --- 11/12. --type all: exactly one record, crypto wins, order-independent -


def test_dedup_keeps_exactly_one_crypto_inventory_finding_and_is_order_independent(
    tmp_path,
):
    (tmp_path / "secret.enc").write_bytes(_salted_bytes())
    (tmp_path / "misleading.p12").write_bytes(_salted_bytes(b"\x01" * 24))

    fs_findings = scan_filesystem_findings(str(tmp_path))
    crypto_findings = scan_crypto_inventory_findings(str(tmp_path))

    forward = _deduplicate_openssl_encrypted_file_findings(fs_findings + crypto_findings)
    reverse = _deduplicate_openssl_encrypted_file_findings(crypto_findings + fs_findings)

    for combined, label in ((forward, "forward"), (reverse, "reverse")):
        openssl_related = [
            f
            for f in combined
            if f.location.endswith(("secret.enc", "misleading.p12"))
        ]
        assert len(openssl_related) == 2, label
        assert all(f.source_type == "crypto_inventory" for f in openssl_related), label
        assert all(f.rule_id == "encrypted_file:openssl" for f in openssl_related), label
        # The filesystem scanner's own record for these two files must not
        # survive the combined output.
        assert not any(
            f.source_type == "local_filesystem"
            and f.rule_id == "file_signature:file_level_openssl"
            for f in openssl_related
        ), label


def test_dedup_is_a_noop_when_only_one_scanner_ran(tmp_path):
    (tmp_path / "secret.enc").write_bytes(_salted_bytes())

    fs_only = scan_filesystem_findings(str(tmp_path))
    crypto_only = scan_crypto_inventory_findings(str(tmp_path))

    assert _deduplicate_openssl_encrypted_file_findings(fs_only) == fs_only
    assert _deduplicate_openssl_encrypted_file_findings(crypto_only) == crypto_only


def test_cli_type_all_reports_the_openssl_finding_exactly_once(tmp_path, capsys):
    (tmp_path / "secret.enc").write_bytes(_salted_bytes())

    exit_code = harvestguard.main(
        ["scan", str(tmp_path), "--type", "all", "--json", "--quiet"]
    )

    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    openssl_records = [r for r in payload if r.get("rule_id") == "encrypted_file:openssl"]
    filesystem_openssl_records = [
        r for r in payload if r.get("rule_id") == "file_signature:file_level_openssl"
    ]
    assert len(openssl_records) == 1
    assert openssl_records[0]["source_type"] == "crypto_inventory"
    assert openssl_records[0]["asset_type"] == "Encrypted File"
    assert filesystem_openssl_records == []


# --- 13/14. Exact known fixture crypto-inspected count, additive only ------


def test_crypto_files_inspected_count_matches_known_fixture(tmp_path):
    for i in range(5):
        (tmp_path / f"ordinary_{i}.txt").write_text("not encrypted")
    (tmp_path / "secret.enc").write_bytes(_salted_bytes())

    stats: dict[str, int] = {}
    scan_crypto_inventory(str(tmp_path), stats=stats)

    assert stats["files_inspected"] == 6


def test_crypto_files_inspected_line_appears_only_when_crypto_scanner_ran(
    tmp_path, capsys
):
    (tmp_path / "secret.enc").write_bytes(_salted_bytes())
    (tmp_path / "plain.txt").write_text("hello")

    exit_code = harvestguard.main(
        ["scan", str(tmp_path), "--type", "crypto", "--summary", "--quiet"]
    )
    crypto_output = capsys.readouterr().out
    assert exit_code == 0
    assert "Crypto files inspected: 2" in crypto_output

    exit_code = harvestguard.main(
        ["scan", str(tmp_path), "--type", "filesystem", "--summary", "--quiet"]
    )
    filesystem_output = capsys.readouterr().out
    assert exit_code == 0
    assert "Crypto files inspected" not in filesystem_output


# --- 15. Files scanned remains unchanged ------------------------------------


def test_files_scanned_remains_zero_for_pure_crypto_only_scan(tmp_path, capsys):
    (tmp_path / "secret.enc").write_bytes(_salted_bytes())

    exit_code = harvestguard.main(
        ["scan", str(tmp_path), "--type", "crypto", "--summary", "--quiet"]
    )

    output = capsys.readouterr().out
    assert exit_code == 0
    assert "Files scanned: 0" in output
    assert "Crypto files inspected: 1" in output


# --- 16. JSON remains a bare array -------------------------------------------


def test_crypto_only_json_output_is_a_bare_array(tmp_path, capsys):
    (tmp_path / "secret.enc").write_bytes(_salted_bytes())

    exit_code = harvestguard.main(
        ["scan", str(tmp_path), "--type", "crypto", "--json", "--quiet"]
    )

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert isinstance(payload, list)
    assert len(payload) == 1
    assert payload[0]["rule_id"] == "encrypted_file:openssl"


# --- 17. Markdown includes evidence and crypto inspection accounting -------


def test_markdown_report_includes_evidence_and_crypto_accounting(tmp_path, capsys):
    (tmp_path / "secret.enc").write_bytes(_salted_bytes())

    exit_code = harvestguard.main(
        ["scan", str(tmp_path), "--type", "crypto", "--markdown", "--quiet"]
    )

    report = capsys.readouterr().out
    assert exit_code == 0
    assert "Encrypted File" in report
    assert "| Crypto Files Inspected | 1 |" in report
    assert "Observed OpenSSL Salted__ encrypted file." in report


# --- 18. No plaintext or raw encrypted bytes appear -------------------------


def test_no_raw_encrypted_bytes_or_plaintext_in_json_or_markdown(tmp_path, capsys):
    marker = os.urandom(16)
    (tmp_path / "secret.enc").write_bytes(SALTED_HEADER + marker)

    harvestguard.main(["scan", str(tmp_path), "--type", "crypto", "--json", "--quiet"])
    json_output = capsys.readouterr().out
    harvestguard.main(["scan", str(tmp_path), "--type", "crypto", "--markdown", "--quiet"])
    markdown_output = capsys.readouterr().out

    assert marker.hex() not in json_output
    assert marker.hex() not in markdown_output
    assert marker not in json_output.encode("utf-8", errors="ignore")
    assert marker not in markdown_output.encode("utf-8", errors="ignore")


# --- rule_id plumbing through the normalization adapter ---------------------


def test_rule_id_survives_normalization_for_openssl_finding(tmp_path):
    (tmp_path / "secret.enc").write_bytes(_salted_bytes())

    df = scan_crypto_inventory(str(tmp_path))
    findings = normalize_crypto_inventory_df(df)

    assert len(findings) == 1
    assert findings[0].rule_id == "encrypted_file:openssl"


def test_rule_id_is_none_for_other_crypto_inventory_asset_types(tmp_path):
    # A PEM certificate has no named detection rule; rule_id must stay
    # unset for it, not silently inherit the OpenSSL rule_id or crash.
    fixture_dir = Path(__file__).parent / "fixtures" / "crypto_inventory"
    (tmp_path / "cert.pem").write_bytes((fixture_dir / "rsa_cert.pem").read_bytes())

    findings = scan_crypto_inventory_findings(str(tmp_path))

    assert len(findings) == 1
    assert findings[0].asset_type == "PEM Certificate"
    assert findings[0].rule_id is None
