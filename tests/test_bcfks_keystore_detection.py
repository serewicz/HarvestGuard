"""Regression coverage for HG-036 (GitHub issue #81): BCFKS keystore-container
detection in the crypto-inventory scanner, the exact evidence-only finding
contract, and the narrow supported-format boundary (the default encrypted
object store written by the Bouncy Castle provider).

Complements tests/test_openssl_encrypted_file_detection.py (HG-030),
tests/test_openpgp_encrypted_file_detection.py (HG-031), and
tests/test_age_encrypted_file_detection.py (HG-035), which have the same shape
of coverage for the `Encrypted File` rules, and
tests/test_crypto_detector_framework.py, which pins the registry composition
this adds one detector to.

Positive coverage uses **real BCFKS stores written by the official Bouncy
Castle provider** (`tests/fixtures/crypto_inventory/bcfks/`, generated as
recorded in that directory's PROVENANCE.md), never bytes this test invented:
four stores with different contents, passwords, salts, MACs, and encrypted
content, all of which must produce the identical public finding contract.

Negative controls are constructed narrowly here rather than committed --
truncated, corrupted, near-match, and the two BCFKS-compatible forms HG-036
deliberately does not support (the unencrypted `ObjectStoreData` store and the
`[0] SignatureCheck` integrity form). Several of them are derived from the real
fixture's own DER elements, so they differ from a supported store in exactly the
one structural way each case is named for.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

import harvestguard
import scanner.crypto_inventory as crypto_inventory
from finding_adapters import normalize_crypto_inventory_df
from scanner.crypto_inventory import (
    CRYPTO_DETECTORS,
    scan_crypto_inventory,
    scan_crypto_inventory_findings,
)
from scanner.filesystem import scan_filesystem_findings

REPO_ROOT = Path(__file__).parent.parent
FIXTURE_DIR = Path(__file__).parent / "fixtures" / "crypto_inventory"
BCFKS_DIR = FIXTURE_DIR / "bcfks"

# The four real stores, and what each one was at generation time. The generated
# contents are recorded here only to show that the *same* public contract comes
# out of a truststore, a keystore, an empty store, and a multiple-entry store:
# HarvestGuard cannot tell them apart and never claims to.
REAL_FIXTURES = {
    "trusted_certificate_store.bcfks": "trusted-certificate store",
    "private_key_store.bcfks": "private-key store",
    "empty_store.bcfks": "empty store (minimum valid supported form)",
    "multi_entry_store.bcfks": "multiple-entry store, different password",
}

EVIDENCE = "Observed supported BCFKS keystore structure."
RULE_ID = "java_keystore:bcfks"


def _real_store(name: str = "trusted_certificate_store.bcfks") -> bytes:
    return (BCFKS_DIR / name).read_bytes()


def _write(directory: Path, name: str, data: bytes) -> Path:
    path = directory / name
    path.write_bytes(data)
    return path


# --- A minimal DER reader/writer, independent of the implementation ----------
#
# Deliberately not imported from scanner.crypto_inventory: a negative control
# built with the parser under test would only prove that parser agrees with
# itself. These two helpers are enough to split a real store into its own DER
# elements and reassemble a near-match from them.


def _split_elements(data: bytes) -> list[bytes]:
    """The complete TLV bytes of each immediate child of the DER element at
    offset 0 of ``data``."""
    tag_length = data[1]
    assert tag_length & 0x80, "the real fixtures all use the long length form"
    offset = 2 + (tag_length & 0x7F)
    end = len(data)
    elements = []
    while offset < end:
        length_octet = data[offset + 1]
        if length_octet & 0x80:
            count = length_octet & 0x7F
            length = int.from_bytes(data[offset + 2 : offset + 2 + count], "big")
            header = 2 + count
        else:
            length, header = length_octet, 2
        elements.append(data[offset : offset + header + length])
        offset += header + length
    return elements


def _tlv(tag: int, content: bytes) -> bytes:
    """``content`` wrapped in a DER tag/length header, minimally encoded."""
    if len(content) < 0x80:
        return bytes([tag, len(content)]) + content
    octets = (len(content).bit_length() + 7) // 8
    return bytes([tag, 0x80 | octets]) + len(content).to_bytes(octets, "big") + content


# PBES2 (1.2.840.113549.1.5.13), used only to give the near-matches below a
# well-formed OBJECT IDENTIFIER so the malformed part is the nested parameters
# encoding and nothing else.
_OID = _tlv(0x06, b"\x2a\x86\x48\x86\xf7\x0d\x01\x05\x0d")
# An OCTET STRING declaring 0x7f content octets with four present: a child whose
# declared length runs past the constructed element holding it.
_TRUNCATED_CHILD = b"\x04\x7f" + b"\x00" * 4


def _store_parts(name: str = "trusted_certificate_store.bcfks") -> tuple[bytes, ...]:
    """``(algorithm identifier, encrypted content, MAC algorithm, KDF, MAC)``
    -- the five DER elements a real store is built from, reused below to build
    near-matches that differ in exactly one way."""
    store_data, integrity_check = _split_elements(_real_store(name))
    encryption_algorithm, encrypted_content = _split_elements(store_data)
    mac_algorithm, kdf, mac = _split_elements(integrity_check)
    return encryption_algorithm, encrypted_content, mac_algorithm, kdf, mac


def _object_store(store_data: bytes, integrity_check: bytes) -> bytes:
    return _tlv(0x30, store_data + integrity_check)


def _encrypted_store_data(algorithm: bytes | None = None, content: bytes | None = None) -> bytes:
    algorithm_element, content_element, *_ = _store_parts()
    return _tlv(
        0x30,
        (algorithm_element if algorithm is None else algorithm)
        + (content_element if content is None else content),
    )


def _integrity_check(
    mac_algorithm: bytes | None = None,
    kdf: bytes | None = None,
    mac: bytes | None = None,
) -> bytes:
    _, _, mac_algorithm_element, kdf_element, mac_element = _store_parts()
    return _tlv(
        0x30,
        (mac_algorithm_element if mac_algorithm is None else mac_algorithm)
        + (kdf_element if kdf is None else kdf)
        + (mac_element if mac is None else mac),
    )


# --- 1-8. Real BCFKS stores are detected ------------------------------------


@pytest.mark.parametrize("name", sorted(REAL_FIXTURES), ids=sorted(REAL_FIXTURES))
def test_real_bouncy_castle_store_produces_the_exact_finding_contract(tmp_path, name):
    _write(tmp_path, name, _real_store(name))

    findings = scan_crypto_inventory_findings(str(tmp_path))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.source_type == "crypto_inventory"
    assert finding.asset_type == "Java Keystore"
    assert finding.rule_id == RULE_ID
    assert finding.confidence == "High"
    assert finding.evidence == EVIDENCE
    assert finding.technical_metadata["Format"] == "BCFKS"
    assert not finding.errors


def test_every_real_store_produces_the_same_public_contract(tmp_path):
    # Four stores with different contents, passwords, salts, MAC values, and
    # encrypted content -- one identical public record shape, and no claim
    # distinguishing a truststore from a keystore, an empty store from a
    # populated one, or one entry from several.
    for name in REAL_FIXTURES:
        _write(tmp_path, name, _real_store(name))

    findings = scan_crypto_inventory_findings(str(tmp_path))

    assert len(findings) == len(REAL_FIXTURES)
    contracts = {
        (
            f.asset_type,
            f.rule_id,
            f.confidence,
            f.evidence,
            f.technical_metadata["Format"],
        )
        for f in findings
    }
    assert contracts == {("Java Keystore", RULE_ID, "High", EVIDENCE, "BCFKS")}


@pytest.mark.parametrize(
    "name",
    [
        "misleading.p12",
        "misleading.pfx",
        "misleading.der",
        "misleading.cer",
        "misleading.crt",
        "misleading.jks",
        "no_extension",
        "store.bcfks",
        "UPPERCASE.BCFKS",
    ],
)
def test_bcfks_content_beats_a_misleading_extension(tmp_path, name):
    # Priority 35 runs before the extension-based JKS/PKCS#12/DER branches and is
    # terminal, so a supported store is classified from its content rather than
    # reported as a malformed PKCS#12, DER certificate, or keystore.
    _write(tmp_path, name, _real_store())

    findings = scan_crypto_inventory_findings(str(tmp_path))

    assert [f.rule_id for f in findings] == [RULE_ID]
    assert [f.asset_type for f in findings] == ["Java Keystore"]


def test_every_misleading_extension_in_one_scan(tmp_path):
    names = [
        "a.p12",
        "b.pfx",
        "c.der",
        "d.cer",
        "e.crt",
        "f.jks",
        "g",
        "h.bcfks",
    ]
    for name in names:
        _write(tmp_path, name, _real_store("private_key_store.bcfks"))

    findings = scan_crypto_inventory_findings(str(tmp_path))

    assert len(findings) == len(names)
    assert {f.rule_id for f in findings} == {RULE_ID}
    assert not [f for f in findings if "Malformed" in f.asset_type]


# --- 9-32. Negative controls -------------------------------------------------


def _negative_cases() -> list[tuple[str, bytes]]:
    real = _real_store()
    algorithm, content, mac_algorithm, kdf, mac = _store_parts()
    cases: list[tuple[str, bytes]] = [
        ("empty.bcfks", b""),
        ("short.bcfks", b"\x30"),
        ("two-bytes.bcfks", b"\x30\x82"),
        # Truncated: the declared outer length now runs past the end of the file.
        ("truncated.bcfks", real[: len(real) // 2]),
        ("truncated-header.bcfks", real[:8]),
        # Corrupted length octet: the outer SEQUENCE no longer ends at the end of
        # the file.
        ("corrupt-length.bcfks", real[:2] + bytes([real[2] ^ 0x01]) + real[3:]),
        # Trailing bytes after an otherwise complete store.
        ("trailing-bytes.bcfks", real + b"\x00"),
        # Nonzero offset: supported bytes embedded in a larger file.
        ("embedded.bcfks", b"\x00\x00\x00\x00" + real),
        # One top-level element.
        ("one-element.bcfks", _tlv(0x30, _encrypted_store_data())),
        # Three top-level elements.
        (
            "three-elements.bcfks",
            _tlv(
                0x30,
                _encrypted_store_data() + _integrity_check() + _tlv(0x02, b"\x01"),
            ),
        ),
        # First element is not an EncryptedObjectStoreData.
        (
            "first-not-a-sequence.bcfks",
            _object_store(_tlv(0x04, b"\x01\x02\x03"), _integrity_check()),
        ),
        (
            "first-element-not-an-algorithm-identifier.bcfks",
            _object_store(
                _tlv(0x30, _tlv(0x02, b"\x01") + content), _integrity_check()
            ),
        ),
        # First element missing its encrypted-content octet string.
        (
            "no-encrypted-content.bcfks",
            _object_store(_tlv(0x30, algorithm), _integrity_check()),
        ),
        (
            "encrypted-content-not-an-octet-string.bcfks",
            _object_store(
                _tlv(0x30, algorithm + _tlv(0x03, b"\x00\xff")), _integrity_check()
            ),
        ),
        # Empty encrypted content.
        (
            "empty-encrypted-content.bcfks",
            _object_store(_encrypted_store_data(content=_tlv(0x04, b"")), _integrity_check()),
        ),
        # Second element is not a PbkdMacIntegrityCheck.
        (
            "second-not-a-sequence.bcfks",
            _object_store(_encrypted_store_data(), _tlv(0x04, b"\x01\x02\x03")),
        ),
        (
            "integrity-check-two-elements.bcfks",
            _object_store(_encrypted_store_data(), _tlv(0x30, mac_algorithm + mac)),
        ),
        (
            "integrity-check-kdf-not-an-algorithm-identifier.bcfks",
            _object_store(
                _encrypted_store_data(), _integrity_check(kdf=_tlv(0x02, b"\x01"))
            ),
        ),
        (
            "integrity-check-malformed-child-length.bcfks",
            _object_store(
                _encrypted_store_data(),
                _tlv(0x30, mac_algorithm + kdf + b"\x04\x7f" + b"\x00" * 4),
            ),
        ),
        # Empty MAC octet string.
        (
            "empty-mac.bcfks",
            _object_store(_encrypted_store_data(), _integrity_check(mac=_tlv(0x04, b""))),
        ),
        # The two BCFKS-compatible forms HG-036 deliberately does not support.
        # Unencrypted ObjectStoreData: version INTEGER, integrity algorithm,
        # object data sequence, creation and last-modified dates.
        (
            "unencrypted-object-store-data.bcfks",
            _object_store(
                _tlv(
                    0x30,
                    _tlv(0x02, b"\x01")
                    + mac_algorithm
                    + _tlv(0x30, b"")
                    + _tlv(0x18, b"20240101000000Z")
                    + _tlv(0x18, b"20240101000000Z"),
                ),
                _integrity_check(),
            ),
        ),
        # Signature integrity: an explicit [0] context tag holding a
        # SignatureCheck in place of the PBKD MAC.
        (
            "signature-integrity-check.bcfks",
            _object_store(
                _encrypted_store_data(),
                _tlv(0xA0, _tlv(0x30, mac_algorithm + _tlv(0x03, b"\x00\xab\xcd"))),
            ),
        ),
        # Malformed OBJECT IDENTIFIER encodings inside an otherwise
        # correctly-shaped AlgorithmIdentifier. Wearing the OID tag is not
        # enough: a payload that ends mid-subidentifier (a trailing
        # continuation bit), one whose subidentifier is padded with a leading
        # 0x80 group, and an empty one are all malformed DER, so the structure
        # they sit in is a near-match rather than a supported store.
        (
            "encryption-oid-unterminated.bcfks",
            _object_store(
                _encrypted_store_data(algorithm=_tlv(0x30, _tlv(0x06, b"\x2a\x86"))),
                _integrity_check(),
            ),
        ),
        (
            "encryption-oid-single-continuation-octet.bcfks",
            _object_store(
                _encrypted_store_data(algorithm=_tlv(0x30, _tlv(0x06, b"\x80"))),
                _integrity_check(),
            ),
        ),
        (
            "encryption-oid-non-minimal-subidentifier.bcfks",
            _object_store(
                _encrypted_store_data(
                    algorithm=_tlv(0x30, _tlv(0x06, b"\x2a\x80\x86\x48"))
                ),
                _integrity_check(),
            ),
        ),
        (
            "encryption-oid-empty.bcfks",
            _object_store(
                _encrypted_store_data(algorithm=_tlv(0x30, _tlv(0x06, b""))),
                _integrity_check(),
            ),
        ),
        (
            "mac-algorithm-oid-unterminated.bcfks",
            _object_store(
                _encrypted_store_data(),
                _integrity_check(mac_algorithm=_tlv(0x30, _tlv(0x06, b"\x2a\x86"))),
            ),
        ),
        (
            "kdf-oid-non-minimal-subidentifier.bcfks",
            _object_store(
                _encrypted_store_data(),
                _integrity_check(kdf=_tlv(0x30, _tlv(0x06, b"\x80\x2a"))),
            ),
        ),
        # Constructed AlgorithmIdentifier parameters holding malformed nested
        # DER. The parameters element's own header and length are consistent
        # with the AlgorithmIdentifier around it, so every outer check passes
        # and only walking inside the parameters rejects the store: a child
        # declaring more content than the parameters element holds, and one
        # leaving content unconsumed after the last child. Both are corrupted
        # encodings, and neither may earn a High-confidence finding.
        (
            "encryption-parameters-truncated-nested-der.bcfks",
            _object_store(
                _encrypted_store_data(
                    algorithm=_tlv(0x30, _OID + _tlv(0x30, _TRUNCATED_CHILD))
                ),
                _integrity_check(),
            ),
        ),
        (
            "encryption-parameters-unconsumed-nested-der.bcfks",
            _object_store(
                _encrypted_store_data(
                    algorithm=_tlv(0x30, _OID + _tlv(0x30, _tlv(0x02, b"\x01") + b"\xff"))
                ),
                _integrity_check(),
            ),
        ),
        (
            "mac-algorithm-parameters-truncated-nested-der.bcfks",
            _object_store(
                _encrypted_store_data(),
                _integrity_check(
                    mac_algorithm=_tlv(0x30, _OID + _tlv(0x30, _TRUNCATED_CHILD))
                ),
            ),
        ),
        (
            "kdf-parameters-truncated-nested-der.bcfks",
            _object_store(
                _encrypted_store_data(),
                _integrity_check(kdf=_tlv(0x30, _OID + _tlv(0x30, _TRUNCATED_CHILD))),
            ),
        ),
        # The malformed child is one level deeper still, inside a nested
        # AlgorithmIdentifier of the kind real PBES2 parameters carry.
        (
            "kdf-parameters-deeply-nested-truncated-der.bcfks",
            _object_store(
                _encrypted_store_data(),
                _integrity_check(
                    kdf=_tlv(
                        0x30,
                        _OID + _tlv(0x30, _tlv(0x30, _OID + _tlv(0x30, _TRUNCATED_CHILD))),
                    )
                ),
            ),
        ),
        # Primitive AlgorithmIdentifier parameters whose content is illegal for
        # the tag that carries it. Each element's own header and declared length
        # are consistent with the AlgorithmIdentifier around it, so the outer
        # structure looks exactly like a supported store and only checking the
        # primitive's content against its universal tag rejects it. All of these
        # are invalid DER, not merely unfamiliar parameter values.
        (
            "encryption-parameters-nonempty-null.bcfks",
            _object_store(
                _encrypted_store_data(algorithm=_tlv(0x30, _OID + _tlv(0x05, b"\x00"))),
                _integrity_check(),
            ),
        ),
        (
            "encryption-parameters-invalid-boolean-value.bcfks",
            _object_store(
                _encrypted_store_data(algorithm=_tlv(0x30, _OID + _tlv(0x01, b"\x01"))),
                _integrity_check(),
            ),
        ),
        (
            "encryption-parameters-overlong-boolean.bcfks",
            _object_store(
                _encrypted_store_data(algorithm=_tlv(0x30, _OID + _tlv(0x01, b"\xff\xff"))),
                _integrity_check(),
            ),
        ),
        (
            "mac-algorithm-parameters-empty-integer.bcfks",
            _object_store(
                _encrypted_store_data(),
                _integrity_check(mac_algorithm=_tlv(0x30, _OID + _tlv(0x02, b""))),
            ),
        ),
        (
            "mac-algorithm-parameters-padded-integer.bcfks",
            _object_store(
                _encrypted_store_data(),
                _integrity_check(mac_algorithm=_tlv(0x30, _OID + _tlv(0x02, b"\x00\x01"))),
            ),
        ),
        (
            "kdf-parameters-bit-string-overlarge-unused-bits.bcfks",
            _object_store(
                _encrypted_store_data(),
                _integrity_check(kdf=_tlv(0x30, _OID + _tlv(0x03, b"\x08\xff"))),
            ),
        ),
        (
            "kdf-parameters-bit-string-unused-bits-set.bcfks",
            _object_store(
                _encrypted_store_data(),
                _integrity_check(kdf=_tlv(0x30, _OID + _tlv(0x03, b"\x04\xff"))),
            ),
        ),
        (
            "kdf-parameters-empty-bit-string.bcfks",
            _object_store(
                _encrypted_store_data(),
                _integrity_check(kdf=_tlv(0x30, _OID + _tlv(0x03, b""))),
            ),
        ),
        # Universal tags used in the wrong form: DER fixes which universal types
        # are constructed and which are primitive, and neither end-of-contents
        # nor the reserved number is an element at all.
        (
            "encryption-parameters-constructed-octet-string.bcfks",
            _object_store(
                _encrypted_store_data(
                    algorithm=_tlv(0x30, _OID + _tlv(0x24, _tlv(0x04, b"\x00")))
                ),
                _integrity_check(),
            ),
        ),
        (
            "encryption-parameters-primitive-sequence.bcfks",
            _object_store(
                _encrypted_store_data(algorithm=_tlv(0x30, _OID + _tlv(0x10, b""))),
                _integrity_check(),
            ),
        ),
        (
            "kdf-parameters-end-of-contents-tag.bcfks",
            _object_store(
                _encrypted_store_data(),
                _integrity_check(kdf=_tlv(0x30, _OID + _tlv(0x00, b""))),
            ),
        ),
        (
            "kdf-parameters-reserved-universal-tag.bcfks",
            _object_store(
                _encrypted_store_data(),
                _integrity_check(kdf=_tlv(0x30, _OID + _tlv(0x0F, b"\x00"))),
            ),
        ),
        # The invalid primitive is one level deeper, inside a nested
        # AlgorithmIdentifier of the kind real PBES2 parameters carry.
        (
            "kdf-parameters-deeply-nested-nonempty-null.bcfks",
            _object_store(
                _encrypted_store_data(),
                _integrity_check(
                    kdf=_tlv(
                        0x30,
                        _OID + _tlv(0x30, _tlv(0x30, _OID + _tlv(0x05, b"\x00"))),
                    )
                ),
            ),
        ),
        # Other DER and near-match structures.
        ("generic-der-sequence.bcfks", _tlv(0x30, _tlv(0x02, b"\x01") + _tlv(0x04, b"\x02"))),
        (
            "encrypted-private-key-info-shape.bcfks",
            _tlv(0x30, algorithm + content),
        ),
        ("indefinite-length.bcfks", b"\x30\x80" + _encrypted_store_data() + b"\x00\x00"),
        (
            "non-minimal-length.bcfks",
            b"\x30\x81\x04" + b"\x30\x00\x30\x00",
        ),
        # Not DER at all.
        ("random.bin", bytes(range(256)) * 4),
        ("text-naming-bcfks.txt", b"This document describes the BCFKS keystore format.\n"),
        (
            "asn1-documentation.txt",
            b"ObjectStore ::= SEQUENCE {\n"
            b"    storeData       ObjectStoreData,\n"
            b"    integrityCheck  ObjectStoreIntegrityCheck\n}\n",
        ),
        ("extension-only.bcfks", b"not a keystore, just a suggestive filename\n"),
    ]
    return cases


NEGATIVE_CASES = _negative_cases()


@pytest.mark.parametrize(
    ("name", "data"), NEGATIVE_CASES, ids=[case[0] for case in NEGATIVE_CASES]
)
def test_unsupported_and_malformed_bcfks_like_files_are_not_detected(tmp_path, name, data):
    _write(tmp_path, name, data)

    findings = scan_crypto_inventory_findings(str(tmp_path))

    assert [f for f in findings if f.rule_id == RULE_ID] == []
    assert [f for f in findings if "BCFKS" in (f.asset_type or "")] == []


def test_no_unsupported_case_becomes_a_scanner_error_or_a_partial_finding(tmp_path):
    for name, data in NEGATIVE_CASES:
        _write(tmp_path, name, data)

    # One scan over every malformed/unsupported shape at once: no exception, no
    # scanner error, and no BCFKS finding or lower-confidence stand-in for one.
    findings = scan_crypto_inventory_findings(str(tmp_path))

    assert [f for f in findings if f.rule_id == RULE_ID] == []
    assert [f for f in findings if "bcfks" in (f.asset_type or "").lower()] == []
    assert [f for f in findings if "bcfks" in (f.evidence or "").lower()] == []


def test_committed_non_bcfks_fixtures_keep_their_own_classification(tmp_path):
    # The PEM/DER/PKCS#12/JKS fixtures must keep their existing asset types, and
    # none of them may acquire a BCFKS rule ID.
    for fixture in (
        "rsa_cert.pem",
        "valid_key.pem",
        "bundle.p12",
        "rsa_cert.der",
        "sample.jks",
        "ssh_key.pub",
    ):
        _write(tmp_path, fixture, (FIXTURE_DIR / fixture).read_bytes())

    findings = scan_crypto_inventory_findings(str(tmp_path))
    by_name: dict[str, list] = {}
    for finding in findings:
        by_name.setdefault(os.path.basename(finding.location), []).append(finding)

    assert [f for f in findings if f.rule_id == RULE_ID] == []
    assert {f.asset_type for f in by_name["rsa_cert.pem"]} == {"PEM Certificate"}
    assert {f.asset_type for f in by_name["valid_key.pem"]} == {"PEM Private Key"}
    assert {f.asset_type for f in by_name["rsa_cert.der"]} == {"DER Certificate"}
    assert {f.asset_type for f in by_name["ssh_key.pub"]} == {"OpenSSH Public Key"}
    assert {f.evidence for f in by_name["sample.jks"]} == {"JKS magic header detected"}
    assert {f.confidence for f in by_name["sample.jks"]} == {"Medium"}
    assert by_name["bundle.p12"]


def test_openssl_openpgp_and_age_keep_ownership_of_their_files(tmp_path):
    _write(tmp_path, "openssl.enc", b"Salted__" + b"\x00" * 24)
    skesk = bytes([0x8C, 0x0D, 0x04, 0x09, 0x03, 0x08]) + bytes(range(0x10, 0x18)) + bytes([0x60])
    _write(tmp_path, "binary.gpg", skesk + bytes([0xD2, 0x11, 0x01]) + bytes(range(0x40, 0x50)))

    findings = scan_crypto_inventory_findings(str(tmp_path))
    by_name = {os.path.basename(f.location): f for f in findings}

    assert by_name["openssl.enc"].rule_id == "encrypted_file:openssl"
    assert by_name["binary.gpg"].rule_id == "encrypted_file:openpgp"
    assert [f for f in findings if f.rule_id == RULE_ID] == []


def test_gocryptfs_root_markers_do_not_create_bcfks_findings(tmp_path):
    root = tmp_path / "vault"
    root.mkdir()
    (root / "gocryptfs.conf").write_text(
        json.dumps(
            {
                "Version": 2,
                "FeatureFlags": ["HKDF", "GCMIV128", "DirIV", "EMENames", "LongNames"],
                "EncryptedKey": "ZmFrZWtleWZha2VrZXlmYWtla2V5ZmFrZWtleQ==",
                "ScryptObject": {
                    "Salt": "c2FsdHNhbHRzYWx0c2FsdA==",
                    "N": 65536,
                    "R": 8,
                    "P": 1,
                    "KeyLen": 32,
                },
            }
        )
    )
    (root / "gocryptfs.diriv").write_bytes(b"\x00" * 16)

    findings = scan_crypto_inventory_findings(str(tmp_path))

    assert [f.rule_id for f in findings] == ["encrypted_filesystem:gocryptfs"]


# --- 33-46. Framework, ownership, terminal behavior, accounting -------------


def _bcfks_detector():
    matches = [d for d in CRYPTO_DETECTORS if d.detector_id == RULE_ID]
    assert len(matches) == 1
    return matches[0]


def test_registry_includes_the_bcfks_detector_exactly_once_with_a_unique_id():
    ids = [d.detector_id for d in CRYPTO_DETECTORS]
    assert ids.count(RULE_ID) == 1
    assert len(ids) == len(set(ids))


def test_bcfks_detector_declares_the_required_contract():
    detector = _bcfks_detector()
    assert detector.priority == 35
    assert detector.scope == "file"
    assert detector.terminal is True
    assert detector.rule_id == RULE_ID
    assert detector.confidence == "High"
    assert detector.evidence == EVIDENCE
    # One safe metadata key, and no new one introduced for BCFKS.
    assert detector.metadata_keys == frozenset({"Format"})


def test_bcfks_priority_is_unique_and_sits_between_gocryptfs_and_jks():
    priorities = {d.detector_id: d.priority for d in CRYPTO_DETECTORS}
    assert list(priorities.values()) == sorted(priorities.values())
    assert len(set(priorities.values())) == len(priorities)
    for earlier in (
        "encrypted_file:openssl",
        "encrypted_file:openpgp",
        "encrypted_file:age",
        "encrypted_filesystem:gocryptfs",
    ):
        assert priorities[earlier] < priorities[RULE_ID]
    for later in (
        "java_keystore:jks_magic",
        "pkcs12:container",
        "certificate:der",
        "certificate:pem",
        "private_key:pem",
        "public_key:ssh",
    ):
        assert priorities[RULE_ID] < priorities[later]


def test_registry_order_remains_deterministic_under_perturbed_input():
    from scanner.crypto_detectors import build_registry

    assert build_registry(list(reversed(CRYPTO_DETECTORS))) == CRYPTO_DETECTORS
    rotated = list(CRYPTO_DETECTORS[4:]) + list(CRYPTO_DETECTORS[:4])
    assert build_registry(rotated) == CRYPTO_DETECTORS


def test_a_bcfks_match_is_terminal_for_that_file(tmp_path):
    from scanner.crypto_detectors import DetectionResult, FileDetector, build_registry

    later_detector_ran = []

    def _record(context):
        later_detector_ran.append(context.location)
        return DetectionResult.no_match()

    registry = build_registry(
        [
            *CRYPTO_DETECTORS,
            FileDetector(
                detector_id="test:after-bcfks",
                # Any free priority above BCFKS's 35 proves the same thing; 38
                # is used rather than 36 because the registry now declares
                # java_truststore:jceks there (HG-042) and rejects duplicates.
                priority=38,
                candidate=lambda context: True,
                detect=_record,
                evidence="",
                confidence="Low",
            ),
        ]
    )
    valid = _write(tmp_path, "valid.bcfks", _real_store())
    malformed = _write(tmp_path, "malformed.bcfks", _real_store()[:64])

    assert [f.rule_id for f in crypto_inventory._scan_file(valid, registry)] == [RULE_ID]
    # Terminal: nothing after priority 35 saw the matched file...
    assert later_detector_ran == []
    # ...but a non-match does not stop later detectors.
    crypto_inventory._scan_file(malformed, registry)
    assert later_detector_ran == [str(malformed)]


def test_one_valid_store_emits_exactly_one_bcfks_finding(tmp_path):
    _write(tmp_path, "store.bcfks", _real_store())

    df = scan_crypto_inventory(str(tmp_path))

    assert list(df["Rule ID"]) == [RULE_ID]
    assert len(df) == 1


def test_crypto_scan_emits_the_finding_and_filesystem_scan_does_not(tmp_path):
    _write(tmp_path, "store.bcfks", _real_store())

    crypto_findings = scan_crypto_inventory_findings(str(tmp_path))
    filesystem_findings = scan_filesystem_findings(str(tmp_path))

    assert [f.rule_id for f in crypto_findings] == [RULE_ID]
    assert [f for f in filesystem_findings if f.rule_id == RULE_ID] == []
    assert [f for f in filesystem_findings if f.asset_type == "Java Keystore"] == []


def test_type_all_emits_one_bcfks_finding_and_keeps_filesystem_records(tmp_path, capsys):
    _write(tmp_path, "store.bcfks", _real_store())

    assert harvestguard.main(["scan", str(tmp_path), "--type", "all", "--json", "--quiet"]) == 0
    payload = json.loads(capsys.readouterr().out)

    bcfks_records = [r for r in payload if r["rule_id"] == RULE_ID]
    assert len(bcfks_records) == 1
    assert bcfks_records[0]["source_type"] == "crypto_inventory"
    assert bcfks_records[0]["asset_type"] == "Java Keystore"
    # The filesystem scanner's own, unrelated context/coverage records for the
    # same target are preserved: HG-036 adds no cross-scanner dedup path.
    assert [r for r in payload if r["source_type"] == "local_filesystem"]


def test_no_cross_scanner_dedup_path_is_added_for_bcfks():
    # HG-036 adds no dedup pairing: the filesystem scanner has no BCFKS rule to
    # pair with, and the OpenSSL/OpenPGP pairings are untouched.
    assert harvestguard.CRYPTO_OWNED_ENCRYPTED_FILE_RULE_IDS == {
        "encrypted_file:openssl": "file_signature:file_level_openssl",
        "encrypted_file:openpgp": "file_signature:file_level_pgp_gpg",
    }


def test_one_bcfks_file_counts_once_in_crypto_files_inspected(tmp_path, capsys):
    _write(tmp_path, "store.bcfks", _real_store())
    for index in range(3):
        (tmp_path / f"ordinary_{index}.txt").write_text("harvestguard fixture text")

    stats: dict[str, int] = {}
    scan_crypto_inventory(str(tmp_path), stats=stats)
    assert stats["files_inspected"] == 4

    assert harvestguard.main(
        ["scan", str(tmp_path), "--type", "crypto", "--summary", "--quiet"]
    ) == 0
    output = capsys.readouterr().out
    assert "Crypto files inspected: 4" in output
    # HG-029 semantics unchanged: the crypto scanner contributes nothing to
    # Files scanned, and there is no BCFKS-specific count or bucket.
    assert "Files scanned: 0" in output
    for bcfks_specific in ("bcfks files", "keystores inspected", RULE_ID):
        assert bcfks_specific not in output.lower()


def test_the_store_is_read_once_through_the_shared_context(tmp_path, monkeypatch):
    target = _write(tmp_path, "store.bcfks", _real_store())
    reads: list[str] = []
    real_read_bytes = Path.read_bytes

    def counting_read_bytes(self):
        reads.append(str(self))
        return real_read_bytes(self)

    monkeypatch.setattr(Path, "read_bytes", counting_read_bytes)
    findings = scan_crypto_inventory_findings(str(tmp_path))

    assert [f.rule_id for f in findings] == [RULE_ID]
    assert reads == [str(target)]


# --- 47-60. Finding identity, output shape, and privacy ---------------------


def test_rule_id_survives_scanner_dataframe_adapter_and_normalized_finding(tmp_path):
    _write(tmp_path, "store.bcfks", _real_store())

    df = scan_crypto_inventory(str(tmp_path))
    findings = normalize_crypto_inventory_df(df)

    assert df.loc[0, "Rule ID"] == RULE_ID
    assert df.loc[0, "Format"] == "BCFKS"
    assert [f.rule_id for f in findings] == [RULE_ID]
    assert findings[0].provenance.rule_id == RULE_ID


def test_dataframe_columns_are_unchanged(tmp_path):
    _write(tmp_path, "store.bcfks", _real_store())
    (tmp_path / "rsa_cert.pem").write_bytes((FIXTURE_DIR / "rsa_cert.pem").read_bytes())

    columns = list(scan_crypto_inventory(str(tmp_path)).columns)

    assert columns == [
        "Asset Type",
        "Location",
        "Algorithm",
        "Key Size",
        "Signature Algorithm",
        "Expiration",
        "Issuer",
        "Subject",
        "Fingerprint",
        "Evidence",
        "Confidence",
        "Rule ID",
        "Format",
        "Config Version",
        "Mode",
        "Errors",
        "Scanner",
        "Scanner Version",
        "Observed At",
    ]


def test_finding_id_is_deterministic_across_repeated_scans(tmp_path):
    _write(tmp_path, "store.bcfks", _real_store())

    first = scan_crypto_inventory_findings(str(tmp_path))
    second = scan_crypto_inventory_findings(str(tmp_path))

    assert [f.finding_id for f in first] == [f.finding_id for f in second]


def test_json_remains_a_bare_array_and_markdown_remains_evidence_only(tmp_path, capsys):
    _write(tmp_path, "store.bcfks", _real_store())

    assert harvestguard.main(
        ["scan", str(tmp_path), "--type", "crypto", "--json", "--quiet"]
    ) == 0
    payload = json.loads(capsys.readouterr().out)
    assert isinstance(payload, list)
    assert len(payload) == 1
    assert payload[0]["rule_id"] == RULE_ID
    assert payload[0]["evidence"] == EVIDENCE
    # No new NormalizedFinding field, and no relationship record anywhere.
    assert not [key for key in payload[0] if "relationship" in key.lower()]

    assert harvestguard.main(
        ["scan", str(tmp_path), "--type", "crypto", "--markdown", "--quiet"]
    ) == 0
    report = capsys.readouterr().out
    assert "Java Keystore" in report
    assert EVIDENCE in report
    assert "| Crypto Files Inspected | 1 |" in report
    # The report's own standing disclaimers legitimately name risk, remediation,
    # and quantum readiness in order to deny them, so this checks the evidence
    # HG-036 contributes rather than the whole document: the BCFKS finding makes
    # no assessment claim, and no relationship record appears anywhere.
    assert "relationship" not in report.lower()
    for forbidden in ("risk", "remediat", "quantum", "hndl", "compliance", "strength"):
        assert forbidden not in payload[0]["evidence"].lower()


def test_the_finding_makes_no_truststore_or_entry_claim(tmp_path, capsys):
    for name in REAL_FIXTURES:
        _write(tmp_path, name, _real_store(name))

    assert harvestguard.main(
        ["scan", str(tmp_path), "--type", "crypto", "--json", "--quiet"]
    ) == 0
    payload = json.loads(capsys.readouterr().out)

    for record in payload:
        # Everything the scanner itself wrote about the store, excluding the
        # location/asset name, which are the caller's own path.
        claims = json.dumps(
            {
                "asset_type": record["asset_type"],
                "evidence": record["evidence"],
                "technical_metadata": record["technical_metadata"],
                "unknowns": record["unknowns"],
                "limitations": record["limitations"],
                "errors": record["errors"],
            }
        ).lower()
        for forbidden in (
            "truststore",
            "trust store",
            "alias",
            "entry",
            "entries",
            "password",
            "decrypt",
            "private key",
            "certificate",
        ):
            assert forbidden not in claims


def test_cli_summary_structure_is_unchanged_and_gains_no_bucket(tmp_path, capsys):
    _write(tmp_path, "store.bcfks", _real_store())

    assert harvestguard.main(
        ["scan", str(tmp_path), "--type", "crypto", "--summary", "--quiet"]
    ) == 0
    with_bcfks = capsys.readouterr().out

    (tmp_path / "store.bcfks").unlink()
    (tmp_path / "plain.txt").write_text("harvestguard fixture text")
    assert harvestguard.main(
        ["scan", str(tmp_path), "--type", "crypto", "--summary", "--quiet"]
    ) == 0
    without_bcfks = capsys.readouterr().out

    def _labels(output: str) -> list[str]:
        return [line.split(":")[0] for line in output.splitlines() if ":" in line]

    assert _labels(with_bcfks) == _labels(without_bcfks)


def test_safe_metadata_carries_only_the_format_key(tmp_path):
    _write(tmp_path, "store.bcfks", _real_store())

    finding = scan_crypto_inventory_findings(str(tmp_path))[0]

    assert finding.technical_metadata["Format"] == "BCFKS"
    assert all(
        value is None
        for key, value in finding.technical_metadata.items()
        if key != "Format"
    )
    from scanner.crypto_detectors import SAFE_METADATA_KEYS

    assert SAFE_METADATA_KEYS == frozenset(
        {
            "Algorithm",
            "Key Size",
            "Signature Algorithm",
            "Expiration",
            "Issuer",
            "Subject",
            "Fingerprint",
            "Format",
            "Config Version",
            "Mode",
        }
    )


@pytest.mark.parametrize("name", sorted(REAL_FIXTURES), ids=sorted(REAL_FIXTURES))
def test_no_store_content_reaches_json_or_markdown(tmp_path, capsys, name):
    store = _real_store(name)
    _write(tmp_path, name, store)
    algorithm, content, mac_algorithm, kdf, mac = _store_parts(name)

    harvestguard.main(["scan", str(tmp_path), "--type", "crypto", "--json", "--quiet"])
    json_output = capsys.readouterr().out
    harvestguard.main(["scan", str(tmp_path), "--type", "crypto", "--markdown", "--quiet"])
    markdown_output = capsys.readouterr().out

    for output in (json_output, markdown_output):
        encoded = output.encode("utf-8", errors="ignore")
        # No encrypted content, MAC, KDF/algorithm identifier, or any other raw
        # ASN.1 fragment of the store, in bytes or as hex.
        for fragment in (content, mac, kdf, algorithm, mac_algorithm):
            assert fragment not in encoded
            assert fragment.hex() not in output
        # Nor the store's own leading bytes, nor the generation-time password,
        # aliases, or certificate subjects recorded in PROVENANCE.md.
        assert store[:32].hex() not in output
        for secret in (
            "password123",
            "trustpass456",
            "aDifferentPassphrase!42",
            "HarvestGuard BCFKS Test",
            "HarvestGuard BCFKS Multi",
            "trusted1",
            "trusted2",
        ):
            assert secret not in output


def test_a_detector_exception_surfaces_as_a_scanner_error_without_a_parser_payload(
    tmp_path, monkeypatch
):
    from scanner.errors import LocalScanError

    marker = "SECRET-BCFKS-ASN1-0xdeadbeef"

    def boom(data):
        raise ValueError(marker)

    monkeypatch.setattr(crypto_inventory, "_looks_like_bcfks_object_store", boom)
    _write(tmp_path, "store.bcfks", _real_store())
    (tmp_path / "aaa_cert.pem").write_bytes((FIXTURE_DIR / "rsa_cert.pem").read_bytes())
    # Traversal order is filesystem order, which is not part of any contract;
    # fixing it here is what makes "the certificate was already collected when
    # the later file's detector failed" a deterministic assertion.
    real_iter = crypto_inventory._iter_candidate_files
    monkeypatch.setattr(
        crypto_inventory,
        "_iter_candidate_files",
        lambda *args, **kwargs: iter(sorted(real_iter(*args, **kwargs))),
    )

    with pytest.raises(LocalScanError) as excinfo:
        scan_crypto_inventory_findings(str(tmp_path))

    message = str(excinfo.value)
    assert RULE_ID in message
    assert "ValueError" in message
    assert marker not in message
    # The evidence collected before the failure is preserved, not discarded.
    assert [f.asset_type for f in excinfo.value.partial_findings] == ["PEM Certificate"]


# --- 61-70. Regression boundaries -------------------------------------------


def test_bcfks_introduces_no_new_asset_type(tmp_path):
    _write(tmp_path, "store.bcfks", _real_store())
    (tmp_path / "sample.jks").write_bytes((FIXTURE_DIR / "sample.jks").read_bytes())

    findings = scan_crypto_inventory_findings(str(tmp_path))

    # The existing Java Keystore asset type, shared with the JKS detector -- no
    # `Malformed BCFKS` type and no BCFKS-specific asset type is added.
    assert {f.asset_type for f in findings} == {"Java Keystore"}
    bcfks_rule_ids = {
        d.rule_id for d in CRYPTO_DETECTORS if d.rule_id and "bcfks" in d.rule_id
    }
    assert bcfks_rule_ids == {RULE_ID}


def test_no_new_dependency_is_declared_for_bcfks():
    for manifest in ("requirements.txt", "requirements-dev.txt", "pyproject.toml"):
        text = (REPO_ROOT / manifest).read_text(encoding="utf-8").lower()
        for library in ("pyasn1", "asn1crypto", "asn1tools", "jks", "pyjks", "javaobj"):
            assert library not in text


def test_detection_invokes_no_external_process(tmp_path, monkeypatch):
    source = (REPO_ROOT / "scanner" / "crypto_inventory.py").read_text(encoding="utf-8")
    assert "subprocess" not in source

    def _forbidden(*args, **kwargs):  # pragma: no cover - must never run
        raise AssertionError("the BCFKS detector must not invoke an external process")

    for name in ("run", "Popen", "check_output", "call"):
        monkeypatch.setattr(subprocess, name, _forbidden)
    monkeypatch.setattr(os, "system", _forbidden)
    _write(tmp_path, "store.bcfks", _real_store())

    assert [f.rule_id for f in scan_crypto_inventory_findings(str(tmp_path))] == [RULE_ID]


def test_no_relationship_record_is_created_by_bcfks_detection():
    source = (REPO_ROOT / "scanner" / "crypto_inventory.py").read_text(encoding="utf-8")
    assert "crypto_relationships" not in source
    assert "relationship" not in source.lower()


def test_the_committed_fixtures_are_the_recorded_real_artifacts():
    # Provenance is part of the contract: positive coverage must keep resting on
    # the recorded Bouncy Castle output rather than on regenerated or
    # hand-edited bytes.
    provenance = (BCFKS_DIR / "PROVENANCE.md").read_text(encoding="utf-8")
    import hashlib

    for name in REAL_FIXTURES:
        data = (BCFKS_DIR / name).read_bytes()
        assert hashlib.sha256(data).hexdigest() in provenance
        assert str(len(data)) in provenance
        assert name in provenance
    assert "bcprov-jdk18on" in provenance
