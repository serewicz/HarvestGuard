"""Regression coverage for HG-038 (GitHub issue #83): encrypted PKCS#8
private-key detection in the crypto-inventory scanner, the exact evidence-only
finding contract, and the deliberately narrow boundary of that claim (the outer
``EncryptedPrivateKeyInfo`` structure, never the private key inside it).

Complements tests/test_bcfks_keystore_detection.py (HG-036) and
tests/test_jceks_keystore_detection.py (HG-037), which have the same shape of
coverage for the Java keystore containers and share the DER reader this reuses,
and tests/test_crypto_detector_framework.py, which pins the registry
composition this adds one detector to.

Positive coverage uses **real encrypted PKCS#8 keys written by OpenSSL**
(`tests/fixtures/crypto_inventory/pkcs8_encrypted/`, generated as recorded in
that directory's PROVENANCE.md), never bytes this test invented: two
independently generated keys with different private-key types and different
encryption configurations, in both PEM and DER form, all of which must produce
the identical public finding contract.

The structural negative controls are derived here by mutating exactly one
property of a real fixture -- element count, an element's tag, a length
encoding, the PEM framing -- so each stays anchored to real tool output while
isolating the single rule under test. The neighbouring real formats
(unencrypted PKCS#8, traditional PEM, legacy `Proc-Type` encrypted PEM,
encrypted OpenSSH, PKCS#12, DER certificates, BCFKS, JCEKS, JKS) are committed
fixtures and must keep their own classification.
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
PKCS8_DIR = FIXTURE_DIR / "pkcs8_encrypted"

ASSET_TYPE = "Encrypted PKCS#8 Private Key"
RULE_ID = "private_key:pkcs8_encrypted"
EVIDENCE = "Encrypted PKCS#8 private-key structure detected"
CONFIDENCE = "High"
FORMAT = "PKCS#8"
PRIORITY = 45

# The four real encrypted PKCS#8 fixtures, and what each one was at generation
# time. Recorded here only to show that the *same* public contract comes out of
# an RSA key encrypted with AES-256-CBC and an EC key encrypted with 3DES, in
# both encodings: HarvestGuard cannot tell them apart and never claims to.
REAL_FIXTURES = {
    "rsa_encrypted_pkcs8.pem": "RSA 2048, PBES2/AES-256-CBC, PEM",
    "rsa_encrypted_pkcs8.der": "RSA 2048, PBES2/AES-256-CBC, DER",
    "ec_encrypted_pkcs8.pem": "EC P-256, PBES2/3DES, PEM",
    "ec_encrypted_pkcs8.der": "EC P-256, PBES2/3DES, DER",
}

# Everything PROVENANCE.md records about how the fixtures were made, none of
# which may ever appear in HarvestGuard's own output.
GENERATION_SECRETS = (
    "harvestguard-fixture-not-a-real-secret",
    "aes-256-cbc",
    "des3",
    "PBES2",
    "PBKDF2",
)

PEM_BEGIN = "-----BEGIN ENCRYPTED PRIVATE KEY-----"
PEM_END = "-----END ENCRYPTED PRIVATE KEY-----"

# Tags used by the independently built negative controls below.
_TAG_INTEGER = 0x02
_TAG_BIT_STRING = 0x03
_TAG_OCTET_STRING = 0x04
_TAG_NULL = 0x05
_TAG_OID = 0x06
_TAG_SEQUENCE = 0x30
_TAG_CONSTRUCTED_OCTET_STRING = 0x24


def _real(name: str) -> bytes:
    return (PKCS8_DIR / name).read_bytes()


def _write(directory: Path, name: str, data: bytes) -> Path:
    path = directory / name
    path.write_bytes(data)
    return path


def _findings(target: Path):
    return scan_crypto_inventory_findings(str(target))


def _only_finding(target: Path):
    found = _findings(target)
    assert len(found) == 1, [(f.asset_type, f.rule_id) for f in found]
    return found[0]


def _pkcs8_findings(target: Path):
    return [f for f in _findings(target) if f.rule_id == RULE_ID]


# --- An independent DER builder/reader, used only by the negative controls ---
#
# Deliberately not the scanner's reader: a negative control built with the code
# under test could not show that the code rejects it.


def _length(count: int) -> bytes:
    if count < 0x80:
        return bytes([count])
    octets = count.to_bytes((count.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(octets)]) + octets


def _element(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _length(len(content)) + content


def _seq(*elements: bytes) -> bytes:
    return _element(_TAG_SEQUENCE, b"".join(elements))


def _split(der: bytes) -> tuple[bytes, bytes]:
    """``(encryptionAlgorithm, encryptedData)`` of a real fixture, as raw
    encoded elements, so a control can reuse one real field while varying the
    other."""
    assert der[0] == _TAG_SEQUENCE
    offset = 1
    length_octet = der[offset]
    offset += 1
    if length_octet & 0x80:
        offset += length_octet & 0x7F
    elements = []
    while offset < len(der):
        start = offset
        offset += 1
        inner = der[offset]
        offset += 1
        if inner & 0x80:
            count = inner & 0x7F
            inner = int.from_bytes(der[offset : offset + count], "big")
            offset += count
        offset += inner
        elements.append(der[start:offset])
    assert len(elements) == 2, len(elements)
    return elements[0], elements[1]


REAL_DER = _real("rsa_encrypted_pkcs8.der")
ALGORITHM_ID, ENCRYPTED_DATA = _split(REAL_DER)
# A minimal well-formed OID element (1.2.840.113549.1.5.13, id-PBES2), used only
# where a control needs *some* structurally valid OID.
VALID_OID = _element(_TAG_OID, bytes([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0D]))


# --- 1-10. The positive contract, from real OpenSSL output ------------------


@pytest.mark.parametrize("name", sorted(REAL_FIXTURES))
def test_real_openssl_key_produces_the_exact_finding_contract(tmp_path, name):
    _write(tmp_path, name, _real(name))

    finding = _only_finding(tmp_path)

    assert finding.asset_type == ASSET_TYPE
    assert finding.rule_id == RULE_ID
    assert finding.confidence == CONFIDENCE
    assert finding.evidence == EVIDENCE
    assert finding.technical_metadata["Format"] == FORMAT


@pytest.mark.parametrize("name", sorted(REAL_FIXTURES))
def test_one_finding_per_key_regardless_of_encoding_or_algorithm(tmp_path, name):
    _write(tmp_path, name, _real(name))

    assert len(_findings(tmp_path)) == 1


def test_pem_and_der_forms_of_the_same_key_share_one_detector_identity(tmp_path):
    _write(tmp_path, "key.pem", _real("rsa_encrypted_pkcs8.pem"))
    _write(tmp_path, "key.der", _real("rsa_encrypted_pkcs8.der"))

    found = _findings(tmp_path)

    assert len(found) == 2
    assert {f.rule_id for f in found} == {RULE_ID}
    assert {f.asset_type for f in found} == {ASSET_TYPE}
    assert {f.evidence for f in found} == {EVIDENCE}


def test_two_independently_generated_keys_produce_the_same_public_contract(tmp_path):
    _write(tmp_path, "rsa.der", _real("rsa_encrypted_pkcs8.der"))
    _write(tmp_path, "ec.der", _real("ec_encrypted_pkcs8.der"))

    contracts = {
        (f.asset_type, f.rule_id, f.confidence, f.evidence, f.technical_metadata["Format"])
        for f in _findings(tmp_path)
    }

    assert contracts == {(ASSET_TYPE, RULE_ID, CONFIDENCE, EVIDENCE, FORMAT)}


def test_multiple_pem_blocks_in_one_file_are_one_container_finding(tmp_path):
    _write(
        tmp_path,
        "keys.pem",
        _real("rsa_encrypted_pkcs8.pem") + _real("ec_encrypted_pkcs8.pem"),
    )

    finding = _only_finding(tmp_path)

    assert finding.rule_id == RULE_ID


def test_pem_block_surrounded_by_unrelated_text_is_still_detected(tmp_path):
    body = _real("ec_encrypted_pkcs8.pem").decode("ascii")
    _write(
        tmp_path,
        "notes.pem",
        f"# key rotated during the 2026 audit\n{body}\n# end of file\n".encode("ascii"),
    )

    assert _only_finding(tmp_path).rule_id == RULE_ID


def test_the_key_is_read_once_through_the_shared_context(tmp_path, monkeypatch):
    # Adding a detector must not add a read: every view it takes comes from the
    # one cached read the scanner already performed for the file.
    _write(tmp_path, "key.der", REAL_DER)
    reads: list[str] = []
    original = Path.read_bytes

    def counting_read_bytes(self):
        reads.append(self.name)
        return original(self)

    monkeypatch.setattr(Path, "read_bytes", counting_read_bytes)

    assert [f.rule_id for f in _findings(tmp_path)] == [RULE_ID]
    assert reads.count("key.der") == 1


# --- 11-20. Misleading extensions: content wins ----------------------------


@pytest.mark.parametrize(
    "name",
    [
        "key",
        "key.bin",
        "key.der",
        "key.p8",
        "key.pk8",
        "key.key",
        "key.pem",
        "key.crt",
        "key.cer",
        "key.p12",
        "key.pfx",
    ],
)
def test_der_key_is_detected_under_any_filename(tmp_path, name):
    # In particular .der/.crt/.cer must not reach the generic DER certificate
    # detector as malformed-certificate evidence, and .p12/.pfx must not reach
    # the PKCS#12 detector as a malformed container.
    _write(tmp_path, name, REAL_DER)

    finding = _only_finding(tmp_path)

    assert finding.asset_type == ASSET_TYPE
    assert finding.rule_id == RULE_ID
    assert finding.confidence == CONFIDENCE


@pytest.mark.parametrize("name", ["key", "key.txt", "secret.dat", "key.crt", "key.p12"])
def test_pem_key_is_detected_under_nonstandard_filenames(tmp_path, name):
    _write(tmp_path, name, _real("rsa_encrypted_pkcs8.pem"))

    assert _only_finding(tmp_path).rule_id == RULE_ID


@pytest.mark.parametrize("suffix", [".p8", ".pk8", ".key", ".der", ".pem"])
def test_extension_alone_never_produces_a_finding(tmp_path, suffix):
    _write(tmp_path, f"looks_like_a_key{suffix}", b"just some ordinary text, not a key\n")

    assert _pkcs8_findings(tmp_path) == []


def test_the_detector_consults_no_extension_at_all():
    # A structural claim about the implementation, not just its outputs: neither
    # the candidate predicate nor the detect callable may branch on a suffix.
    detector = next(d for d in CRYPTO_DETECTORS if d.detector_id == RULE_ID)
    source = (REPO_ROOT / "scanner" / "crypto_inventory.py").read_text(encoding="utf-8")
    start = source.index("def _pkcs8_encrypted_candidate")
    end = source.index("def _jks_candidate")
    body = source[start:end]

    assert detector.candidate.__name__ == "_pkcs8_encrypted_candidate"
    assert detector.detect.__name__ == "_detect_pkcs8_encrypted"
    # Call sites, not prose: the docstrings explain *why* the extension gate is
    # bypassed, so only an actual use of one of these may be absent.
    for forbidden in (
        "context.suffix",
        "_BINARY_PARSE_EXTENSIONS",
        "_passes_candidate_gate(",
        "_looks_like_der_candidate",
    ):
        assert forbidden not in body


# --- 21-40. Structural negative controls ------------------------------------


def _control_cases() -> dict[str, bytes]:
    """One mutation of a real fixture per DER rule under test."""
    return {
        "empty_file": b"",
        "truncated_sequence": REAL_DER[: len(REAL_DER) // 2],
        "trailing_bytes": REAL_DER + b"\x00",
        "one_element": _seq(ALGORITHM_ID),
        "three_elements": _seq(ALGORITHM_ID, ENCRYPTED_DATA, ENCRYPTED_DATA),
        # AlgorithmIdentifier whose parameters field declares more content than
        # it holds: length-consistent at the top level, malformed inside.
        "malformed_algorithm_identifier": _seq(
            _element(_TAG_SEQUENCE, VALID_OID + b"\x30\x05\x02"),
            ENCRYPTED_DATA,
        ),
        # An INTEGER where the algorithm OID must be.
        "missing_oid": _seq(
            _element(_TAG_SEQUENCE, _element(_TAG_INTEGER, b"\x01")),
            ENCRYPTED_DATA,
        ),
        # A NULL carrying content octets: legal length, illegal DER.
        "malformed_parameters": _seq(
            _element(_TAG_SEQUENCE, VALID_OID + _element(_TAG_NULL, b"\x00")),
            ENCRYPTED_DATA,
        ),
        "wrong_second_element_tag": _seq(ALGORITHM_ID, _element(_TAG_BIT_STRING, b"\x00\xff")),
        "empty_encrypted_data": _seq(ALGORITHM_ID, _element(_TAG_OCTET_STRING, b"")),
        "constructed_octet_string": _seq(
            ALGORITHM_ID,
            _element(_TAG_CONSTRUCTED_OCTET_STRING, _element(_TAG_OCTET_STRING, b"abc")),
        ),
        # Indefinite length: legal BER, never legal DER.
        "indefinite_length": b"\x30\x80" + ALGORITHM_ID + ENCRYPTED_DATA + b"\x00\x00",
        # A three-octet long form for a length two octets encode: non-minimal.
        "non_minimal_length": b"\x30\x83"
        + b"\x00"
        + (len(ALGORITHM_ID) + len(ENCRYPTED_DATA)).to_bytes(2, "big")
        + ALGORITHM_ID
        + ENCRYPTED_DATA,
        "embedded_at_nonzero_offset": b"\x00" * 8 + REAL_DER,
        "arbitrary_der_like_binary": b"\x30\x82\xff\xff" + bytes(range(256)) * 2,
    }


@pytest.mark.parametrize("case", sorted(_control_cases()))
def test_structural_negative_control_produces_no_pkcs8_finding(tmp_path, case):
    _write(tmp_path, "candidate.p8", _control_cases()[case])

    assert _pkcs8_findings(tmp_path) == []


@pytest.mark.parametrize("case", sorted(_control_cases()))
def test_structural_negative_control_never_produces_high_confidence_evidence(tmp_path, case):
    _write(tmp_path, "candidate.der", _control_cases()[case])

    for finding in _findings(tmp_path):
        assert finding.rule_id != RULE_ID
        assert not (finding.confidence == CONFIDENCE and "PKCS#8" in finding.asset_type)


def test_pem_negative_controls_produce_no_pkcs8_finding(tmp_path):
    real_pem = _real("rsa_encrypted_pkcs8.pem").decode("ascii")
    body = real_pem.split(PEM_BEGIN)[1].split(PEM_END)[0]
    import base64

    cases = {
        "header_only.pem": f"{PEM_BEGIN}\n",
        "footer_missing.pem": f"{PEM_BEGIN}\n{body.strip()}\n",
        "invalid_base64.pem": f"{PEM_BEGIN}\nnot base64 at all ***\n{PEM_END}\n",
        "empty_body.pem": f"{PEM_BEGIN}\n{PEM_END}\n",
        # Valid base64 whose decoded DER is a PKCS#8 *PrivateKeyInfo*, not an
        # EncryptedPrivateKeyInfo: the label claims encryption, the structure
        # does not support the claim.
        "wrong_structure.pem": "{}\n{}\n{}\n".format(
            PEM_BEGIN,
            base64.b64encode(_real("unencrypted_pkcs8.der")).decode("ascii"),
            PEM_END,
        ),
    }
    for name, text in cases.items():
        target = tmp_path / name
        target.mkdir()
        (target / name).write_text(text, encoding="ascii")

        assert _pkcs8_findings(target) == [], name


def test_the_word_encrypted_alone_is_not_evidence(tmp_path):
    _write(
        tmp_path,
        "notes.txt",
        b"ENCRYPTED PRIVATE KEY -- see the vault for the actual encrypted key\n",
    )

    assert _pkcs8_findings(tmp_path) == []


# --- 41-50. Neighbouring real formats keep their own classification ---------


@pytest.mark.parametrize(
    ("name", "expected_asset_type"),
    [
        ("unencrypted_pkcs8.pem", "PEM Private Key"),
        ("traditional_rsa.pem", "PEM Private Key"),
        ("traditional_ec.pem", "PEM Private Key"),
        ("legacy_encrypted_rsa.pem", "Encrypted PEM Private Key"),
        ("encrypted_openssh_key", "Encrypted OpenSSH Private Key"),
    ],
)
def test_existing_private_key_behavior_is_preserved(tmp_path, name, expected_asset_type):
    _write(tmp_path, name, _real(name))

    finding = _only_finding(tmp_path)

    assert finding.asset_type == expected_asset_type
    assert finding.rule_id != RULE_ID


def test_unencrypted_pkcs8_der_is_not_claimed(tmp_path):
    # The .der extension still routes it to the generic DER certificate branch,
    # exactly as before HG-038: a version INTEGER where the encryption
    # AlgorithmIdentifier would be is not an EncryptedPrivateKeyInfo.
    _write(tmp_path, "key.der", _real("unencrypted_pkcs8.der"))

    finding = _only_finding(tmp_path)

    assert finding.rule_id != RULE_ID
    assert finding.asset_type == "Malformed DER Certificate"


@pytest.mark.parametrize(
    ("relative_name", "expected_asset_type"),
    [
        ("bundle.p12", "PKCS#12 Certificate"),
        ("rsa_cert.der", "DER Certificate"),
        ("sample.jks", "Java Keystore"),
        ("bcfks/private_key_store.bcfks", "Java Keystore"),
        ("jceks/private_key_store.jceks", "Java Keystore"),
    ],
)
def test_existing_container_detectors_keep_their_files(
    tmp_path, relative_name, expected_asset_type
):
    source = FIXTURE_DIR / relative_name
    _write(tmp_path, Path(relative_name).name, source.read_bytes())

    found = _findings(tmp_path)

    assert {f.rule_id for f in found} != {RULE_ID}
    assert expected_asset_type in {f.asset_type for f in found}
    assert all(f.rule_id != RULE_ID for f in found)


def test_committed_non_pkcs8_fixtures_are_unaffected():
    # A whole-directory scan of the existing fixture corpus gains no encrypted
    # PKCS#8 finding outside the new fixture directory -- except the one
    # committed encrypted PKCS#8 key that already lived at the top level, whose
    # classification HG-038 deliberately moved to this detector.
    found = [f for f in scan_crypto_inventory_findings(str(FIXTURE_DIR)) if f.rule_id == RULE_ID]

    locations = {Path(f.location).name: Path(f.location).parent.name for f in found}

    assert locations.pop("encrypted_key.pem") == "crypto_inventory"
    assert set(locations.values()) == {"pkcs8_encrypted"}
    assert set(locations) == {name for name in REAL_FIXTURES}


# --- 51-60. Registry contract ----------------------------------------------


def test_registry_includes_the_detector_exactly_once_with_a_unique_id():
    ids = [d.detector_id for d in CRYPTO_DETECTORS]

    assert ids.count(RULE_ID) == 1
    assert len(ids) == len(set(ids))


def test_detector_declares_the_required_contract():
    detector = next(d for d in CRYPTO_DETECTORS if d.detector_id == RULE_ID)

    assert detector.priority == PRIORITY
    assert detector.terminal is True
    assert detector.rule_id == RULE_ID
    assert detector.confidence == CONFIDENCE
    assert detector.evidence == EVIDENCE
    assert detector.metadata_keys == frozenset({"Format"})
    assert detector.scope == "file"
    assert detector.verification_rationale


def test_registry_order_places_the_detector_before_der_and_pem_key_handling():
    by_id = {d.detector_id: d.priority for d in CRYPTO_DETECTORS}

    # Before generic DER certificate and generic PEM private-key handling.
    assert by_id[RULE_ID] < by_id["certificate:der"]
    assert by_id[RULE_ID] < by_id["private_key:pem"]
    # After the container detectors that own a whole file of their own.
    for container in (
        "encrypted_filesystem:gocryptfs",
        "java_keystore:bcfks",
        "java_keystore:jceks",
        "java_keystore:jks_magic",
    ):
        assert by_id[container] < by_id[RULE_ID]
    priorities = [d.priority for d in CRYPTO_DETECTORS]
    assert priorities == sorted(priorities)
    assert len(priorities) == len(set(priorities))


def test_a_positive_match_is_terminal(tmp_path):
    # A real encrypted PKCS#8 DER key named .crt would otherwise also be read by
    # the DER certificate detector; terminality is what keeps one asset to one
    # finding.
    _write(tmp_path, "key.crt", REAL_DER)

    assert [f.rule_id for f in _findings(tmp_path)] == [RULE_ID]


def test_a_non_match_falls_through_to_the_existing_detectors(tmp_path):
    # Terminality applies to a match only: a .der file this detector rejected
    # must still reach the DER certificate branch it always reached.
    _write(tmp_path, "cert.der", (FIXTURE_DIR / "rsa_cert.der").read_bytes())

    assert [f.asset_type for f in _findings(tmp_path)] == ["DER Certificate"]


def test_introduces_no_new_rule_id_beyond_its_own():
    declared = {d.rule_id for d in CRYPTO_DETECTORS if d.rule_id and "pkcs8" in d.rule_id}

    assert declared == {RULE_ID}


# --- 61-70. Normalization, evidence store, and output shape -----------------


def test_normalized_finding_preserves_the_whole_contract(tmp_path):
    _write(tmp_path, "key.p8", REAL_DER)

    df = scan_crypto_inventory(str(tmp_path))
    findings = normalize_crypto_inventory_df(df)

    assert df.loc[0, "Rule ID"] == RULE_ID
    assert df.loc[0, "Format"] == FORMAT
    assert len(findings) == 1
    finding = findings[0]
    assert finding.source_type == "crypto_inventory"
    assert finding.asset_type == ASSET_TYPE
    assert finding.rule_id == RULE_ID
    assert finding.confidence == CONFIDENCE
    assert finding.evidence == EVIDENCE
    assert finding.technical_metadata["Format"] == FORMAT
    assert finding.provenance.rule_id == RULE_ID


def test_safe_metadata_carries_only_the_format_key(tmp_path):
    _write(tmp_path, "key.p8", REAL_DER)

    finding = _only_finding(tmp_path)
    populated = {k: v for k, v in finding.technical_metadata.items() if v is not None}

    assert populated == {"Format": FORMAT}


def test_dataframe_columns_are_unchanged(tmp_path):
    _write(tmp_path, "key.p8", REAL_DER)
    (tmp_path / "rsa_cert.pem").write_bytes((FIXTURE_DIR / "rsa_cert.pem").read_bytes())

    assert list(scan_crypto_inventory(str(tmp_path)).columns) == [
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
    _write(tmp_path, "key.p8", REAL_DER)

    first = scan_crypto_inventory_findings(str(tmp_path))
    second = scan_crypto_inventory_findings(str(tmp_path))

    assert [f.finding_id for f in first] == [f.finding_id for f in second]
    assert all(f.finding_id for f in first)


def test_cli_json_carries_the_finding_and_markdown_stays_evidence_only(tmp_path, capsys):
    _write(tmp_path, "key.p8", REAL_DER)

    assert (
        harvestguard.main(["scan", str(tmp_path), "--type", "crypto", "--json", "--quiet"]) == 0
    )
    payload = json.loads(capsys.readouterr().out)

    assert isinstance(payload, list) and len(payload) == 1
    record = payload[0]
    assert record["source_type"] == "crypto_inventory"
    assert record["asset_type"] == ASSET_TYPE
    assert record["rule_id"] == RULE_ID
    assert record["confidence"] == CONFIDENCE
    assert record["evidence"] == EVIDENCE
    assert record["technical_metadata"]["Format"] == FORMAT

    assert (
        harvestguard.main(["scan", str(tmp_path), "--type", "crypto", "--markdown", "--quiet"])
        == 0
    )
    report = capsys.readouterr().out
    assert ASSET_TYPE in report
    assert EVIDENCE in report
    for forbidden in ("risk", "remediat", "quantum", "hndl", "compliance", "migrat"):
        assert forbidden not in record["evidence"].lower()


def test_evidence_store_round_trip_preserves_the_finding(tmp_path, capsys):
    target = tmp_path / "target"
    target.mkdir()
    _write(target, "key.p8", REAL_DER)
    db = tmp_path / "evidence.db"

    assert (
        harvestguard.main(
            [
                "scan",
                str(target),
                "--type",
                "crypto",
                "--json",
                "--quiet",
                "--evidence-db",
                str(db),
            ]
        )
        == 0
    )
    live = capsys.readouterr().out
    scan_id = json.loads(live)[0]["scan_id"]
    assert scan_id

    assert harvestguard.main(["evidence", "verify", scan_id, "--evidence-db", str(db)]) == 0
    capsys.readouterr()

    assert (
        harvestguard.main(
            ["evidence", "export", scan_id, "--evidence-db", str(db), "--json", "--quiet"]
        )
        == 0
    )
    stored = capsys.readouterr().out

    assert stored == live
    record = json.loads(stored)[0]
    assert record["scan_id"] == scan_id
    assert record["rule_id"] == RULE_ID
    assert record["asset_type"] == ASSET_TYPE
    assert record["confidence"] == CONFIDENCE
    assert record["evidence"] == EVIDENCE
    assert record["technical_metadata"]["Format"] == FORMAT
    assert record["schema_version"] == "1.0.0"

    assert (
        harvestguard.main(
            ["evidence", "export", scan_id, "--evidence-db", str(db), "--markdown", "--quiet"]
        )
        == 0
    )
    markdown = capsys.readouterr().out
    assert ASSET_TYPE in markdown
    assert EVIDENCE in markdown


# --- 71-80. Accounting ------------------------------------------------------


def test_scan_accounting_is_unchanged_by_the_new_detector(tmp_path, capsys):
    _write(tmp_path, "key.p8", REAL_DER)
    _write(tmp_path, "plain.txt", b"ordinary file content\n")
    (tmp_path / "rsa_cert.pem").write_bytes((FIXTURE_DIR / "rsa_cert.pem").read_bytes())

    assert harvestguard.main(["scan", str(tmp_path), "--type", "crypto"]) == 0
    output = capsys.readouterr().out

    # Three files visited, whatever the detectors concluded about them: this
    # detector inspects files the scanner already counted and adds no read.
    assert "3" in output


def test_one_file_target_still_scans_exactly_that_file(tmp_path):
    key = _write(tmp_path, "key.p8", REAL_DER)
    _write(tmp_path, "other.p8", REAL_DER)

    found = _findings(key)

    assert len(found) == 1
    assert found[0].location == str(key)


def test_an_unreadable_file_produces_no_finding_and_no_error(tmp_path):
    path = _write(tmp_path, "key.p8", REAL_DER)
    path.chmod(0o000)
    try:
        if os.access(path, os.R_OK):  # pragma: no cover - running as root
            pytest.skip("cannot make a file unreadable as this user")
        assert _findings(tmp_path) == []
    finally:
        path.chmod(0o600)


# --- 81-95. The no-decryption, no-password, privacy boundary ---------------


def test_detection_requires_no_password_and_calls_no_key_loading_api(tmp_path, monkeypatch):
    from cryptography.hazmat.primitives import serialization

    def _forbidden(*args, **kwargs):  # pragma: no cover - must never run
        raise AssertionError("the encrypted PKCS#8 detector must not load or prompt")

    for api in (
        "load_pem_private_key",
        "load_der_private_key",
        "load_ssh_private_key",
    ):
        monkeypatch.setattr(serialization, api, _forbidden)
    monkeypatch.setattr("builtins.input", _forbidden)
    for name in sorted(REAL_FIXTURES):
        _write(tmp_path, name, _real(name))

    found = _findings(tmp_path)

    assert len(found) == len(REAL_FIXTURES)
    assert {f.rule_id for f in found} == {RULE_ID}


def test_detection_reads_no_password_from_the_environment(tmp_path, monkeypatch):
    for variable in (
        "HARVESTGUARD_PASSWORD",
        "PKCS8_PASSWORD",
        "KEY_PASSPHRASE",
        "PASSWORD",
        "PASSPHRASE",
    ):
        monkeypatch.setenv(variable, "harvestguard-fixture-not-a-real-secret")
    _write(tmp_path, "key.p8", REAL_DER)

    assert [f.rule_id for f in _findings(tmp_path)] == [RULE_ID]

    source = (REPO_ROOT / "scanner" / "crypto_inventory.py").read_text(encoding="utf-8")
    start = source.index("# --- Encrypted PKCS#8 private-key detection")
    end = source.index("# --- Detector registry (HG-033)")
    section = source[start:end]
    # Call sites, not prose: this section's comments describe the boundary in
    # words, so only an actual password-reading or key-loading call may appear.
    for forbidden in (
        "os.environ",
        "os.getenv",
        "getpass",
        "input(",
        "load_pem_private_key(",
        "load_der_private_key(",
        "password=",
        "passphrase=",
    ):
        assert forbidden not in section


def test_detection_invokes_no_external_process(tmp_path, monkeypatch):
    source = (REPO_ROOT / "scanner" / "crypto_inventory.py").read_text(encoding="utf-8")
    assert "subprocess" not in source

    def _forbidden(*args, **kwargs):  # pragma: no cover - must never run
        raise AssertionError("the encrypted PKCS#8 detector must not invoke a process")

    for name in ("run", "Popen", "check_output", "call"):
        monkeypatch.setattr(subprocess, name, _forbidden)
    monkeypatch.setattr(os, "system", _forbidden)
    _write(tmp_path, "key.p8", REAL_DER)

    assert [f.rule_id for f in _findings(tmp_path)] == [RULE_ID]


@pytest.mark.parametrize("name", sorted(REAL_FIXTURES))
def test_no_key_content_reaches_json_or_markdown(tmp_path, capsys, name):
    data = _real(name)
    _write(tmp_path, name, data)

    assert (
        harvestguard.main(["scan", str(tmp_path), "--type", "crypto", "--json", "--quiet"]) == 0
    )
    json_output = capsys.readouterr().out
    assert (
        harvestguard.main(["scan", str(tmp_path), "--type", "crypto", "--markdown", "--quiet"])
        == 0
    )
    markdown_output = capsys.readouterr().out

    for output in (json_output, markdown_output):
        lowered = output.lower()
        # The generation passphrase and the algorithm/KDF names PROVENANCE.md
        # records: never in a finding.
        for secret in GENERATION_SECRETS:
            assert secret.lower() not in lowered
        # No raw PEM body and no raw DER excerpt: every 8-byte window of the
        # fixture, hex-encoded, must be absent, as must the base64 body itself.
        for offset in range(0, min(len(data), 200) - 8):
            assert data[offset : offset + 8].hex() not in lowered
        if data.startswith(b"-----BEGIN"):
            body = "".join(data.decode("ascii").split("\n")[1:-2])
            assert body[:32].lower() not in lowered


def test_no_algorithm_kdf_or_parameter_detail_is_ever_reported(tmp_path):
    for name in sorted(REAL_FIXTURES):
        _write(tmp_path, name, _real(name))

    for finding in _findings(tmp_path):
        record = json.dumps(finding.to_dict()).lower()
        # Whole words, so "private" cannot mask a search for "iv" and
        # "provenance" cannot mask one for "ec".
        for forbidden in (
            "pbes",
            "pbes1",
            "pbes2",
            "pbkdf",
            "pbkdf2",
            "scrypt",
            "aes",
            "des",
            "3des",
            "sha1",
            "hmac",
            "salt",
            "iv",
            "nonce",
            "iteration",
            "iterations",
            "oid",
            "rsa",
            "ec",
            "p-256",
            "secp256r1",
            "password",
            "passphrase",
            "decrypt",
            "decrypted",
        ):
            assert re.search(rf"\b{re.escape(forbidden)}\b", record) is None, forbidden
        assert finding.technical_metadata["Algorithm"] is None
        assert finding.technical_metadata["Key Size"] is None
        assert finding.technical_metadata["Fingerprint"] is None


def test_the_finding_makes_no_strength_or_business_claim(tmp_path):
    _write(tmp_path, "key.p8", REAL_DER)

    finding = _only_finding(tmp_path)
    claims = " ".join(
        [finding.evidence, finding.asset_type, finding.confidence_rationale or ""]
    ).lower()

    for forbidden in (
        "risk",
        "remediat",
        "quantum",
        "hndl",
        "compliance",
        "migrat",
        "weak",
        "strong",
        "vulnerab",
        "decrypted",
        "validated key",
        "recovered",
    ):
        assert forbidden not in claims


def test_malformed_input_surfaces_no_parser_payload(tmp_path, capsys):
    # A rejected candidate must not put ASN.1 parser detail or target bytes into
    # output; the malformed DER path this file's controls exercise produces
    # either nothing or an existing generic finding with no byte excerpt.
    data = _control_cases()["malformed_algorithm_identifier"]
    _write(tmp_path, "candidate.der", data)

    assert (
        harvestguard.main(["scan", str(tmp_path), "--type", "crypto", "--json", "--quiet"]) == 0
    )
    output = capsys.readouterr().out.lower()

    assert RULE_ID not in output
    for offset in range(0, len(data) - 8):
        assert data[offset : offset + 8].hex() not in output


# --- 96-100. Fixture provenance and documentation ---------------------------


def test_the_committed_fixtures_are_the_recorded_real_artifacts():
    # Provenance is part of the contract: positive coverage must keep resting on
    # the recorded OpenSSL output rather than on regenerated or hand-edited
    # bytes.
    provenance = (PKCS8_DIR / "PROVENANCE.md").read_text(encoding="utf-8")

    for name in REAL_FIXTURES:
        data = _real(name)
        assert hashlib.sha256(data).hexdigest() in provenance
        assert str(len(data)) in provenance
        assert name in provenance
    assert "openssl pkcs8 -topk8" in provenance
    assert "OpenSSL 3.0.13" in provenance
    # The test-only passphrase and the explicit runtime statement about it.
    assert "harvestguard-fixture-not-a-real-secret" in provenance
    assert "requires no password and accepts none" in provenance


def test_characterization_documents_the_pkcs8_boundary():
    doc = (REPO_ROOT / "docs" / "DETECTION_CHARACTERIZATION.md").read_text(encoding="utf-8")

    assert RULE_ID in doc
    assert ASSET_TYPE in doc
    assert "EncryptedPrivateKeyInfo" in doc


@pytest.mark.parametrize(
    "relative_path", ["README.md", "docs/CLI.md", "docs/CRYPTO_INVENTORY.md"]
)
def test_support_claims_are_documented_consistently(relative_path):
    text = (REPO_ROOT / relative_path).read_text(encoding="utf-8")

    assert "PKCS#8" in text


def test_no_new_dependency_is_declared_for_pkcs8_detection():
    for manifest in ("requirements.txt", "requirements-dev.txt", "pyproject.toml"):
        text = (REPO_ROOT / manifest).read_text(encoding="utf-8").lower()
        for library in ("asn1crypto", "pyasn1", "asn1tools", "pkcs8"):
            assert library not in text
