"""Regression coverage for HG-032 (GitHub issue #72): gocryptfs
encrypted-filesystem cipher-root detection in the crypto-inventory scanner.

Complements tests/test_crypto_inventory.py (PEM/DER/PKCS#12/JKS/SSH,
unmodified), tests/test_openssl_encrypted_file_detection.py (HG-030), and
tests/test_openpgp_encrypted_file_detection.py (HG-031) -- the same shape of
coverage for a third, structurally distinct encrypted-container signal: a
*directory*-level marker pair rather than a file-content signature.

All fixtures are synthetic and generated in-process; no real gocryptfs
config, key material, or binary is used or committed.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import harvestguard
from finding_adapters import normalize_crypto_inventory_df
from harvestguard import _deduplicate_encrypted_file_findings
from scanner.crypto_inventory import (
    scan_crypto_inventory,
    scan_crypto_inventory_findings,
)
from scanner.filesystem import scan_filesystem_findings

RULE_ID = "encrypted_filesystem:gocryptfs"


def _gocryptfs_conf(
    version: int = 2,
    feature_flags: list[str] | None = None,
    plaintextnames: bool = False,
    encrypted_key: str = "ZmFrZWtleWZha2VrZXlmYWtla2V5ZmFrZWtleQ==",
    scrypt_object: dict | None = "default",
    include_all_fields: bool = True,
) -> bytes:
    """A synthetic gocryptfs.conf: real field names and shapes (Version,
    FeatureFlags, EncryptedKey, ScryptObject), fabricated values -- no real
    key material, salt, or passphrase-derived content anywhere."""
    flags = list(feature_flags) if feature_flags is not None else ["GCMIV128", "HKDF"]
    if plaintextnames:
        flags.append("PlaintextNames")
    config: dict = {
        "Creator": "gocryptfs v2.4.0",
        "Version": version,
        "FeatureFlags": flags,
    }
    if include_all_fields:
        config["EncryptedKey"] = encrypted_key
        config["ScryptObject"] = (
            {"Salt": "c2FsdHNhbHQ=", "N": 65536, "R": 8, "P": 1, "KeyLen": 32}
            if scrypt_object == "default"
            else scrypt_object
        )
    return json.dumps(config).encode("ascii")


def _make_root(
    root: Path,
    conf: bytes | None = "default",
    diriv: bytes | None = "default",
    ciphertext_files: int = 0,
) -> Path:
    """A directory with the given root markers (or None to omit one), plus
    ``ciphertext_files`` opaque, random-named files standing in for real
    gocryptfs ciphertext."""
    root.mkdir(parents=True, exist_ok=True)
    if conf is not None:
        (root / "gocryptfs.conf").write_bytes(_gocryptfs_conf() if conf == "default" else conf)
    if diriv is not None:
        (root / "gocryptfs.diriv").write_bytes(os.urandom(16) if diriv == "default" else diriv)
    for index in range(ciphertext_files):
        # Base64-alphabet-shaped names, like real gocryptfs ciphertext names.
        (root / f"AbCd{index}EfGh==").write_bytes(os.urandom(32))
    return root


def _gocryptfs_findings(findings):
    return [f for f in findings if f.rule_id == RULE_ID]


# --- 1-5. Minimal valid root, explicit version, required fields ------------


def test_valid_forward_mode_root_produces_one_finding(tmp_path):
    root = _make_root(tmp_path / "vault")

    findings = scan_crypto_inventory_findings(str(tmp_path))

    gocryptfs = _gocryptfs_findings(findings)
    assert len(gocryptfs) == 1
    assert gocryptfs[0].location == str(root)


def test_supported_config_version_is_recorded(tmp_path):
    _make_root(tmp_path / "vault", conf=_gocryptfs_conf(version=2))

    finding = _gocryptfs_findings(scan_crypto_inventory_findings(str(tmp_path)))[0]

    assert finding.technical_metadata["Config Version"] == 2
    assert finding.technical_metadata["Format"] == "gocryptfs"
    assert finding.technical_metadata["Mode"] == "forward"


def test_required_stable_config_field_missing_produces_no_finding(tmp_path):
    for field in ("Version", "FeatureFlags", "EncryptedKey", "ScryptObject"):
        config = json.loads(_gocryptfs_conf())
        del config[field]
        target = tmp_path / f"missing-{field}"
        _make_root(target, conf=json.dumps(config).encode("ascii"))

    assert scan_crypto_inventory_findings(str(tmp_path)) == []


def test_root_level_conf_and_diriv_directly_in_root_are_required(tmp_path):
    # A conf/diriv pair one level too deep (not directly in the candidate
    # root) does not qualify that outer directory as a cipher root.
    outer = tmp_path / "outer"
    outer.mkdir()
    _make_root(outer / "actual_root")

    findings = _gocryptfs_findings(scan_crypto_inventory_findings(str(tmp_path)))

    assert len(findings) == 1
    assert findings[0].location == str(outer / "actual_root")
    assert findings[0].location != str(outer)


# --- 6-10. Missing markers, empty/malformed config, unsupported version ----


def test_missing_config_produces_no_finding(tmp_path):
    _make_root(tmp_path / "no-conf", conf=None)

    assert scan_crypto_inventory_findings(str(tmp_path)) == []


def test_missing_root_diriv_produces_no_finding(tmp_path):
    _make_root(tmp_path / "no-diriv", diriv=None)

    assert scan_crypto_inventory_findings(str(tmp_path)) == []


def test_empty_config_produces_no_finding(tmp_path):
    _make_root(tmp_path / "empty-conf", conf=b"")

    assert scan_crypto_inventory_findings(str(tmp_path)) == []


def test_malformed_json_config_produces_no_finding(tmp_path):
    _make_root(tmp_path / "malformed", conf=b"{not valid json")
    _make_root(tmp_path / "not-an-object", conf=b'["just", "an", "array"]')
    _make_root(tmp_path / "just-a-string", conf=b'"hello"')

    assert scan_crypto_inventory_findings(str(tmp_path)) == []


def test_unsupported_config_version_produces_no_finding(tmp_path):
    for version in (0, 1, 3, 6, 99):
        _make_root(tmp_path / f"version-{version}", conf=_gocryptfs_conf(version=version))
    # A non-integer / boolean Version is also unsupported, not coerced.
    bad_type_config = json.loads(_gocryptfs_conf())
    bad_type_config["Version"] = "2"
    _make_root(tmp_path / "version-string", conf=json.dumps(bad_type_config).encode("ascii"))
    bad_type_config["Version"] = True
    _make_root(tmp_path / "version-bool", conf=json.dumps(bad_type_config).encode("ascii"))

    assert scan_crypto_inventory_findings(str(tmp_path)) == []


# --- 11-12. Reverse mode and plaintextnames mode are unsupported -----------


def test_reverse_mode_like_root_produces_no_finding(tmp_path):
    # gocryptfs.conf carries no "this is reverse mode" field -- forward and
    # reverse configs are structurally identical JSON. What actually differs
    # on disk is that reverse mode never writes a gocryptfs.diriv anywhere
    # (directory IVs are computed live from the plaintext side), so a
    # reverse-mode root is exactly this shape: a valid-looking config with no
    # root diriv at all. This is the same structural case as
    # test_missing_root_diriv_produces_no_finding, verified again here under
    # its own name because Issue #72 requires it as a distinct scenario.
    _make_root(tmp_path / "reverse-like", diriv=None)

    assert scan_crypto_inventory_findings(str(tmp_path)) == []


def test_plaintextnames_mode_produces_no_finding(tmp_path):
    _make_root(tmp_path / "plaintextnames", conf=_gocryptfs_conf(plaintextnames=True))

    assert scan_crypto_inventory_findings(str(tmp_path)) == []


# --- 13-15. Arbitrary/orphaned config, random names alone ------------------


def test_arbitrary_content_named_gocryptfs_conf_produces_no_finding(tmp_path):
    root = tmp_path / "arbitrary"
    root.mkdir()
    (root / "gocryptfs.conf").write_bytes(b"just some unrelated text file\n")
    (root / "gocryptfs.diriv").write_bytes(os.urandom(16))

    assert scan_crypto_inventory_findings(str(tmp_path)) == []


def test_orphaned_config_copied_elsewhere_produces_no_finding(tmp_path):
    # A gocryptfs.conf copied into a directory that has a *different*
    # directory's diriv, or no diriv of its own, is not a root relationship.
    real_root = tmp_path / "real_root"
    _make_root(real_root)
    orphan = tmp_path / "orphan"
    orphan.mkdir()
    (orphan / "gocryptfs.conf").write_bytes(_gocryptfs_conf())
    # No gocryptfs.diriv in `orphan` at all -- the copied config has nothing
    # to pair with here.

    findings = _gocryptfs_findings(scan_crypto_inventory_findings(str(tmp_path)))

    assert len(findings) == 1
    assert findings[0].location == str(real_root)


def test_random_looking_names_alone_produce_no_finding(tmp_path):
    root = tmp_path / "random-names"
    root.mkdir()
    for index in range(10):
        (root / f"AbCd{index}EfGhIjKl==").write_bytes(os.urandom(32))

    assert scan_crypto_inventory_findings(str(tmp_path)) == []


# --- 16-19. Aggregation: no per-file amplification, nested roots -----------


def test_nested_diriv_alone_does_not_amplify(tmp_path):
    root = _make_root(tmp_path / "vault")
    nested = root / "aa" / "bb"
    nested.mkdir(parents=True)
    (nested / "gocryptfs.diriv").write_bytes(os.urandom(16))
    for index in range(5):
        (nested / f"ct{index}").write_bytes(os.urandom(16))

    findings = _gocryptfs_findings(scan_crypto_inventory_findings(str(tmp_path)))

    assert len(findings) == 1
    assert findings[0].location == str(root)


def test_hundreds_of_ciphertext_files_still_yield_one_finding(tmp_path):
    root = _make_root(tmp_path / "vault", ciphertext_files=400)

    findings = _gocryptfs_findings(scan_crypto_inventory_findings(str(tmp_path)))

    assert len(findings) == 1
    assert findings[0].location == str(root)


def test_finding_count_remains_constant_as_ciphertext_count_grows(tmp_path):
    small = _make_root(tmp_path / "small", ciphertext_files=5)
    large = _make_root(tmp_path / "large", ciphertext_files=500)

    small_findings = _gocryptfs_findings(scan_crypto_inventory_findings(str(small)))
    large_findings = _gocryptfs_findings(scan_crypto_inventory_findings(str(large)))

    assert len(small_findings) == len(large_findings) == 1


def test_nested_independent_root_produces_one_separate_finding(tmp_path):
    outer = _make_root(tmp_path / "outer", ciphertext_files=3)
    inner = _make_root(tmp_path / "outer" / "inner", ciphertext_files=3)

    findings = _gocryptfs_findings(scan_crypto_inventory_findings(str(tmp_path)))
    locations = {f.location for f in findings}

    assert len(findings) == 2
    assert locations == {str(outer), str(inner)}


# --- 20-22. Identity, exact finding contract, rule_id propagation ----------


def test_deterministic_identity_across_repeated_scans(tmp_path):
    _make_root(tmp_path / "vault")

    first = _gocryptfs_findings(scan_crypto_inventory_findings(str(tmp_path)))[0]
    second = _gocryptfs_findings(scan_crypto_inventory_findings(str(tmp_path)))[0]

    assert first.finding_id == second.finding_id
    assert first.identity_key == second.identity_key


def test_exact_finding_contract(tmp_path):
    root = _make_root(tmp_path / "vault")

    finding = _gocryptfs_findings(scan_crypto_inventory_findings(str(tmp_path)))[0]

    assert finding.source_type == "crypto_inventory"
    assert finding.asset_type == "Encrypted Filesystem"
    assert finding.rule_id == RULE_ID
    assert finding.confidence == "High"
    assert finding.location == str(root)
    assert finding.asset_name == root.name
    assert finding.evidence == "Observed supported gocryptfs cipher-root structure."
    # Evidence-only: no decryption/strength/business/compliance claim.
    for forbidden in (
        "decrypt",
        "password",
        "passphrase",
        "strong",
        "weak",
        "risk",
        "remediat",
        "quantum",
        "complian",
        "mounted",
    ):
        assert forbidden not in finding.evidence.lower()


def test_rule_id_survives_the_normalization_adapter(tmp_path):
    _make_root(tmp_path / "vault")

    df = scan_crypto_inventory(str(tmp_path))
    findings = normalize_crypto_inventory_df(df)

    gocryptfs_rows = df[df["Rule ID"] == RULE_ID]
    assert len(gocryptfs_rows) == 1
    gocryptfs = [f for f in findings if f.rule_id == RULE_ID]
    assert len(gocryptfs) == 1
    assert gocryptfs[0].asset_type == "Encrypted Filesystem"


def test_rule_id_reaches_json_and_markdown_output(tmp_path, capsys):
    _make_root(tmp_path / "vault")

    assert harvestguard.main(
        ["scan", str(tmp_path), "--type", "crypto", "--json", "--quiet"]
    ) == 0
    payload = json.loads(capsys.readouterr().out)
    gocryptfs_records = [r for r in payload if r.get("rule_id") == RULE_ID]
    assert len(gocryptfs_records) == 1
    assert gocryptfs_records[0]["asset_type"] == "Encrypted Filesystem"
    assert gocryptfs_records[0]["source_type"] == "crypto_inventory"
    assert gocryptfs_records[0]["confidence"] == "High"

    assert harvestguard.main(
        ["scan", str(tmp_path), "--type", "crypto", "--markdown", "--quiet"]
    ) == 0
    report = capsys.readouterr().out
    assert "Encrypted Filesystem" in report
    assert "Observed supported gocryptfs cipher-root structure." in report


# --- 23-27. Scanner ownership: crypto-only, filesystem-only, combined ------


def test_crypto_only_scan_emits_one_root_finding(tmp_path):
    _make_root(tmp_path / "vault", ciphertext_files=10)

    findings = _gocryptfs_findings(scan_crypto_inventory_findings(str(tmp_path)))

    assert len(findings) == 1


def test_filesystem_only_scan_has_no_gocryptfs_finding(tmp_path):
    _make_root(tmp_path / "vault", ciphertext_files=10)

    findings = scan_filesystem_findings(str(tmp_path))

    assert [f for f in findings if f.rule_id == RULE_ID] == []
    # Existing filesystem behavior for the ordinary-looking conf/diriv/
    # ciphertext files is unchanged: no per-file findings (no recognized
    # file-level signature), represented by aggregate context only.
    assert [f for f in findings if f.asset_type == "file"] == []
    assert any(f.asset_type == "volume" for f in findings)


def test_type_all_emits_one_crypto_inventory_root_finding(tmp_path, capsys):
    _make_root(tmp_path / "vault", ciphertext_files=10)

    exit_code = harvestguard.main(
        ["scan", str(tmp_path), "--type", "all", "--json", "--quiet"]
    )

    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    gocryptfs_records = [r for r in payload if r.get("rule_id") == RULE_ID]
    assert len(gocryptfs_records) == 1
    assert gocryptfs_records[0]["source_type"] == "crypto_inventory"


def test_scanner_order_independence(tmp_path):
    _make_root(tmp_path / "vault", ciphertext_files=10)

    fs_findings = scan_filesystem_findings(str(tmp_path))
    crypto_findings = scan_crypto_inventory_findings(str(tmp_path))

    forward = _deduplicate_encrypted_file_findings(fs_findings + crypto_findings)
    reverse = _deduplicate_encrypted_file_findings(crypto_findings + fs_findings)

    forward_gocryptfs = _gocryptfs_findings(forward)
    reverse_gocryptfs = _gocryptfs_findings(reverse)
    assert len(forward_gocryptfs) == len(reverse_gocryptfs) == 1
    assert forward_gocryptfs[0].finding_id == reverse_gocryptfs[0].finding_id


def test_filesystem_context_and_coverage_not_removed_as_duplicates(tmp_path, capsys):
    _make_root(tmp_path / "vault", ciphertext_files=5)

    exit_code = harvestguard.main(
        ["scan", str(tmp_path), "--type", "all", "--json", "--quiet"]
    )

    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert any(r.get("rule_id") == RULE_ID for r in payload)
    # The aggregate filesystem mount-context record is unrelated evidence and
    # must still be present, not dropped as if it duplicated the gocryptfs
    # finding.
    assert any(
        r["source_type"] == "local_filesystem" and r["asset_type"] == "volume" for r in payload
    )


# --- 28-29. Accounting: Files scanned and Crypto files inspected -----------


def test_files_scanned_unchanged_by_gocryptfs(tmp_path, capsys):
    _make_root(tmp_path / "vault", ciphertext_files=10)
    # 2 markers + 10 ciphertext = 12 regular files for the filesystem scanner.

    assert harvestguard.main(
        ["scan", str(tmp_path), "--type", "filesystem", "--summary", "--quiet"]
    ) == 0
    assert "Files scanned: 12" in capsys.readouterr().out

    assert harvestguard.main(
        ["scan", str(tmp_path), "--type", "crypto", "--summary", "--quiet"]
    ) == 0
    # A pure --type crypto run correctly reports 0 -- the crypto-inventory
    # scanner is not the filesystem scanner (HG-029/HG-030 semantics).
    assert "Files scanned: 0" in capsys.readouterr().out


def test_crypto_files_inspected_counts_every_gocryptfs_file(tmp_path, capsys):
    _make_root(tmp_path / "vault", ciphertext_files=10)
    # 2 markers + 10 ciphertext = 12 files the crypto scanner visits, whether
    # or not each one produces a finding.

    stats: dict[str, int] = {}
    scan_crypto_inventory(str(tmp_path), stats=stats)
    assert stats["files_inspected"] == 12

    assert harvestguard.main(
        ["scan", str(tmp_path), "--type", "crypto", "--summary", "--quiet"]
    ) == 0
    assert "Crypto files inspected: 12" in capsys.readouterr().out


# --- 30-31. JSON bare array, evidence-only Markdown -------------------------


def test_json_output_remains_a_bare_array(tmp_path, capsys):
    _make_root(tmp_path / "vault")

    exit_code = harvestguard.main(
        ["scan", str(tmp_path), "--type", "crypto", "--json", "--quiet"]
    )

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert isinstance(payload, list)


def test_markdown_output_is_evidence_only(tmp_path, capsys):
    _make_root(tmp_path / "vault")

    harvestguard.main(["scan", str(tmp_path), "--type", "crypto", "--markdown", "--quiet"])
    report = capsys.readouterr().out

    assert "Encrypted Filesystem" in report
    # The report's standard "Known Limitations" boilerplate legitimately
    # *disclaims* risk/remediation/compliance content in every report (see
    # reports.py), so a blanket substring ban would false-positive on that
    # existing, correct disclaimer. Check instead that the gocryptfs
    # evidence text itself makes no such claim, and that no affirmative
    # (non-disclaiming) risk/compliance/quantum phrasing appears anywhere.
    assert "Observed supported gocryptfs cipher-root structure." in report
    for forbidden in (
        "hndl",
        "quantum-ready",
        "quantum readiness",
        "business impact",
        "is compliant",
        "high risk",
        "must remediate",
    ):
        assert forbidden not in report.lower()
    assert "No risk scores, executive priority, remediation recommendations" in report


# --- 32-33. Incomplete subtree traversal, no exact aggregate counts --------


def test_incomplete_subtree_traversal_still_permits_root_finding(tmp_path):
    root = _make_root(tmp_path / "vault")
    blocked = root / "blocked"
    blocked.mkdir()
    (blocked / "hidden_ciphertext").write_bytes(os.urandom(16))
    blocked.chmod(0o000)
    try:
        findings = _gocryptfs_findings(scan_crypto_inventory_findings(str(tmp_path)))
    finally:
        blocked.chmod(0o755)

    assert len(findings) == 1
    assert findings[0].location == str(root)
    assert findings[0].confidence == "High"


def test_no_exact_aggregate_counts_are_claimed(tmp_path):
    _make_root(tmp_path / "vault", ciphertext_files=25)

    finding = _gocryptfs_findings(scan_crypto_inventory_findings(str(tmp_path)))[0]

    # The smallest defensible implementation: no ciphertext/file/directory
    # count claim of any kind, complete or otherwise, in technical_metadata.
    metadata_keys = set(finding.technical_metadata.keys())
    for forbidden_substring in ("count", "files represented", "ciphertext"):
        assert not any(forbidden_substring in key.lower() for key in metadata_keys)


# --- 34-35. No secret/config/content leakage --------------------------------


def test_no_raw_config_or_disallowed_values_in_output(tmp_path, capsys):
    encrypted_key_marker = "ZmFrZWtleWZha2VrZXlmYWtla2V5ZmFrZWtleQ=="
    salt_marker = "c2FsdHNhbHQ="
    _make_root(tmp_path / "vault", conf=_gocryptfs_conf(encrypted_key=encrypted_key_marker))

    harvestguard.main(["scan", str(tmp_path), "--type", "crypto", "--json", "--quiet"])
    json_output = capsys.readouterr().out
    harvestguard.main(["scan", str(tmp_path), "--type", "crypto", "--markdown", "--quiet"])
    markdown_output = capsys.readouterr().out

    for output in (json_output, markdown_output):
        assert encrypted_key_marker not in output
        assert salt_marker not in output
        assert "EncryptedKey" not in output
        assert "ScryptObject" not in output
        assert "Creator" not in output


def test_no_secret_or_content_material_appears_in_output(tmp_path, capsys):
    ciphertext_marker = os.urandom(16)
    diriv_marker = os.urandom(16)
    root = tmp_path / "vault"
    _make_root(root, diriv=diriv_marker)
    (root / "ct0").write_bytes(ciphertext_marker)

    harvestguard.main(["scan", str(tmp_path), "--type", "crypto", "--json", "--quiet"])
    json_output = capsys.readouterr().out
    harvestguard.main(["scan", str(tmp_path), "--type", "crypto", "--markdown", "--quiet"])
    markdown_output = capsys.readouterr().out

    for output in (json_output, markdown_output):
        assert ciphertext_marker.hex() not in output
        assert diriv_marker.hex() not in output
        assert ciphertext_marker not in output.encode("utf-8", errors="ignore")
        assert diriv_marker not in output.encode("utf-8", errors="ignore")


# --- Dedup ownership from HG-030/HG-031 is preserved alongside gocryptfs ---


def test_dedup_preserves_openssl_and_openpgp_ownership_alongside_gocryptfs(tmp_path):
    _make_root(tmp_path / "vault")
    (tmp_path / "openssl.enc").write_bytes(b"Salted__" + b"\x00" * 24)

    combined = _deduplicate_encrypted_file_findings(
        scan_filesystem_findings(str(tmp_path)) + scan_crypto_inventory_findings(str(tmp_path))
    )

    rule_ids_by_basename = {}
    for finding in combined:
        rule_ids_by_basename.setdefault(os.path.basename(finding.location), []).append(
            finding.rule_id
        )
    assert rule_ids_by_basename["openssl.enc"] == ["encrypted_file:openssl"]
    assert rule_ids_by_basename["vault"] == [RULE_ID]
