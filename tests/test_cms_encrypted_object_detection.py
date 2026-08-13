"""HG-039: CMS / PKCS#7 encrypted-object detection.

The claim under test is deliberately narrow:

    This file contains a structurally valid supported CMS/PKCS#7
    encrypted-content object.

and deliberately not: who can decrypt it, whether any recipient certificate or
signature is valid, which algorithms it uses, or whether anything should be done
about it. These tests hold both halves of that line.

Every positive case is driven by **real OpenSSL `cms` output** committed under
`tests/fixtures/crypto_inventory/cms_encrypted/` (see its `PROVENANCE.md`).
Negative and hostile controls are built here with an independent DER
builder/reader, or derived from the real fixtures by changing exactly one thing:
a control built with the code under test could not show that the code rejects
it.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import subprocess
import textwrap
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
CMS_DIR = FIXTURE_DIR / "cms_encrypted"

ENVELOPED_ASSET_TYPE = "CMS/PKCS#7 Enveloped Data"
ENVELOPED_RULE_ID = "cms:enveloped_data"
ENVELOPED_EVIDENCE = "CMS/PKCS#7 EnvelopedData encrypted-content structure detected"
ENVELOPED_PRIORITY = 46

ENCRYPTED_ASSET_TYPE = "CMS/PKCS#7 Encrypted Data"
ENCRYPTED_RULE_ID = "cms:encrypted_data"
ENCRYPTED_EVIDENCE = "CMS/PKCS#7 EncryptedData encrypted-content structure detected"
ENCRYPTED_PRIORITY = 47

CONFIDENCE = "High"
FORMAT = "CMS/PKCS#7"
RULE_IDS = {ENVELOPED_RULE_ID, ENCRYPTED_RULE_ID}

# The real positive fixtures, and the contract each must produce.
REAL_POSITIVES = {
    "enveloped_data.der": (ENVELOPED_RULE_ID, "EnvelopedData, DER"),
    "enveloped_data.pem": (ENVELOPED_RULE_ID, "EnvelopedData, textual CMS label"),
    "enveloped_data_pkcs7.pem": (ENVELOPED_RULE_ID, "EnvelopedData, textual PKCS7 label"),
    "encrypted_data.der": (ENCRYPTED_RULE_ID, "EncryptedData, DER"),
    "encrypted_data.pem": (ENCRYPTED_RULE_ID, "EncryptedData, textual CMS label"),
}

# Real CMS/PKCS#7 objects that are not encrypted-content objects. None may
# produce an HG-039 finding: the container shape and the CMS/PKCS7 label are
# never themselves evidence of encryption.
REAL_NEGATIVES = {
    "signed_data.der": "CMS SignedData",
    "certificates_only.p7b": "PKCS#7 certificate-only / degenerate SignedData",
    "data.der": "CMS Data (id-data)",
    "digested_data.der": "valid ContentInfo, unsupported non-encrypted content OID",
}

# Everything PROVENANCE.md records about how the fixtures were made, none of
# which may ever appear in HarvestGuard's own output.
GENERATION_DETAIL = (
    "aes-256-cbc",
    "rsaEncryption",
    "HarvestGuard CMS Fixture Recipient",
    "000102030405060708090a0b0c0d0e0f",
    "HarvestGuard CMS fixture plaintext",
    "1.2.840.113549.1.7.3",
    "1.2.840.113549.1.7.6",
)

_TAG_INTEGER = 0x02
_TAG_OCTET_STRING = 0x04
_TAG_NULL = 0x05
_TAG_OID = 0x06
_TAG_SEQUENCE = 0x30
_TAG_SET = 0x31
_TAG_CONTEXT_0 = 0x80
_TAG_CONTEXT_0_CONSTRUCTED = 0xA0
_TAG_CONTEXT_1_CONSTRUCTED = 0xA1

OID_ENVELOPED_DATA = bytes((0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x03))
OID_ENCRYPTED_DATA = bytes((0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x06))
OID_DATA = bytes((0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01))
OID_SIGNED_DATA = bytes((0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02))
OID_AES_256_CBC = bytes((0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2A))


def _real(name: str) -> bytes:
    return (CMS_DIR / name).read_bytes()


def _write(directory: Path, name: str, data: bytes) -> Path:
    path = directory / name
    path.write_bytes(data)
    return path


def _findings(target: Path):
    return scan_crypto_inventory_findings(str(target))


def _cms_findings(target: Path):
    return [f for f in _findings(target) if f.rule_id in RULE_IDS]


def _only_cms_finding(target: Path):
    found = _cms_findings(target)
    assert len(found) == 1, [(f.asset_type, f.rule_id) for f in found]
    return found[0]


# --- An independent DER builder/reader, used only by the controls -----------


def _length(count: int) -> bytes:
    if count < 0x80:
        return bytes([count])
    octets = count.to_bytes((count.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(octets)]) + octets


def _element(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _length(len(content)) + content


def _seq(*elements: bytes) -> bytes:
    return _element(_TAG_SEQUENCE, b"".join(elements))


def _children(der: bytes) -> list[bytes]:
    """The raw encoded children of a constructed element, read without the
    scanner's own reader."""
    offset = 1
    length_octet = der[offset]
    offset += 1
    if length_octet & 0x80:
        offset += length_octet & 0x7F
    children: list[bytes] = []
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
        children.append(der[start:offset])
    return children


def _content_info(oid: bytes, content: bytes) -> bytes:
    """A ContentInfo carrying ``content`` (already encoded) under ``oid``."""
    return _seq(_element(_TAG_OID, oid), _element(_TAG_CONTEXT_0_CONSTRUCTED, content))


def _pem(label: str, der: bytes, newline: str = "\n") -> bytes:
    body = textwrap.wrap(base64.b64encode(der).decode("ascii"), 64)
    lines = [f"-----BEGIN {label}-----", *body, f"-----END {label}-----", ""]
    return newline.join(lines).encode("ascii")


ENVELOPED_DER = _real("enveloped_data.der")
ENCRYPTED_DER = _real("encrypted_data.der")

# The real inner structures, so a derived control changes exactly one thing
# about real OpenSSL output rather than inventing an object wholesale.
ENVELOPED_BODY = _children(_children(ENVELOPED_DER)[1])[0]
ENCRYPTED_BODY = _children(_children(ENCRYPTED_DER)[1])[0]
ENVELOPED_PARTS = _children(ENVELOPED_BODY)  # version, recipientInfos, ECI
ENCRYPTED_PARTS = _children(ENCRYPTED_BODY)  # version, ECI
REAL_ECI_PARTS = _children(ENCRYPTED_PARTS[1])  # contentType, algorithm, [0]
REAL_ALGORITHM = REAL_ECI_PARTS[1]
REAL_CIPHERTEXT = REAL_ECI_PARTS[2]
REAL_RECIPIENT_INFOS = ENVELOPED_PARTS[1]

VERSION_0 = _element(_TAG_INTEGER, b"\x00")
VERSION_2 = _element(_TAG_INTEGER, b"\x02")
CONTENT_TYPE = _element(_TAG_OID, OID_DATA)


def _eci(
    content_type: bytes = CONTENT_TYPE,
    algorithm: bytes = REAL_ALGORITHM,
    encrypted_content: bytes | None = REAL_CIPHERTEXT,
) -> bytes:
    parts = [content_type, algorithm]
    if encrypted_content is not None:
        parts.append(encrypted_content)
    return _seq(*parts)


def _enveloped(*parts: bytes) -> bytes:
    return _content_info(OID_ENVELOPED_DATA, _seq(*parts))


def _encrypted(*parts: bytes) -> bytes:
    return _content_info(OID_ENCRYPTED_DATA, _seq(*parts))


# --- 1. The positive contract, from real OpenSSL output ---------------------


@pytest.mark.parametrize("name", sorted(REAL_POSITIVES))
def test_real_openssl_object_produces_the_exact_finding_contract(tmp_path, name):
    rule_id = REAL_POSITIVES[name][0]
    _write(tmp_path, name, _real(name))

    finding = _only_cms_finding(tmp_path)

    if rule_id == ENVELOPED_RULE_ID:
        assert finding.asset_type == ENVELOPED_ASSET_TYPE
        assert finding.evidence == ENVELOPED_EVIDENCE
    else:
        assert finding.asset_type == ENCRYPTED_ASSET_TYPE
        assert finding.evidence == ENCRYPTED_EVIDENCE
    assert finding.rule_id == rule_id
    assert finding.confidence == CONFIDENCE
    assert finding.technical_metadata["Format"] == FORMAT


@pytest.mark.parametrize("name", sorted(REAL_POSITIVES))
def test_one_finding_per_object_regardless_of_encoding(tmp_path, name):
    _write(tmp_path, name, _real(name))

    assert len(_findings(tmp_path)) == 1


def test_binary_and_textual_forms_share_one_detector_identity(tmp_path):
    _write(tmp_path, "a.der", ENVELOPED_DER)
    _write(tmp_path, "b.pem", _real("enveloped_data.pem"))
    _write(tmp_path, "c.pem", _real("enveloped_data_pkcs7.pem"))

    found = _cms_findings(tmp_path)

    assert len(found) == 3
    assert {f.rule_id for f in found} == {ENVELOPED_RULE_ID}
    assert {f.asset_type for f in found} == {ENVELOPED_ASSET_TYPE}
    assert {f.evidence for f in found} == {ENVELOPED_EVIDENCE}


def test_the_two_content_types_keep_separate_identities(tmp_path):
    _write(tmp_path, "enveloped.der", ENVELOPED_DER)
    _write(tmp_path, "encrypted.der", ENCRYPTED_DER)

    found = _cms_findings(tmp_path)

    assert {f.rule_id for f in found} == RULE_IDS
    assert {f.asset_type for f in found} == {ENVELOPED_ASSET_TYPE, ENCRYPTED_ASSET_TYPE}


def test_multiple_textual_blocks_in_one_file_are_one_finding(tmp_path):
    _write(
        tmp_path,
        "bundle.pem",
        _real("enveloped_data.pem") + _real("enveloped_data_pkcs7.pem"),
    )

    finding = _only_cms_finding(tmp_path)

    assert finding.rule_id == ENVELOPED_RULE_ID


# --- Coexistence: both supported content types in one physical file --------
#
# Codex Principal Review (PR #105) found that because both CMS detectors are
# terminal, a textual file carrying both a valid EnvelopedData block and a
# valid EncryptedData block silently lost the EncryptedData finding: the
# priority-46 EnvelopedData detector matched first, terminally, and the shared
# dispatch loop never reached cms:encrypted_data's own detect() for that file.
# These tests prove both claims now survive, in either block order, and that
# same-type multiplicity still collapses to one finding per rule.


def test_enveloped_then_encrypted_blocks_in_one_file_produce_both_rule_ids(tmp_path):
    _write(
        tmp_path,
        "bundle.pem",
        _real("enveloped_data.pem") + _real("encrypted_data.pem"),
    )

    found = _cms_findings(tmp_path)

    assert {f.rule_id for f in found} == RULE_IDS
    assert len(found) == 2


def test_encrypted_then_enveloped_blocks_in_one_file_produce_both_rule_ids(tmp_path):
    # Reverse block order: the shared structural pass observes both content
    # types regardless of which block comes first in the file.
    _write(
        tmp_path,
        "bundle.pem",
        _real("encrypted_data.pem") + _real("enveloped_data.pem"),
    )

    found = _cms_findings(tmp_path)

    assert {f.rule_id for f in found} == RULE_IDS
    assert len(found) == 2


def test_two_enveloped_data_blocks_remain_one_enveloped_finding(tmp_path):
    _write(
        tmp_path,
        "bundle.pem",
        _real("enveloped_data.pem") + _real("enveloped_data.pem"),
    )

    found = _cms_findings(tmp_path)

    assert [f.rule_id for f in found] == [ENVELOPED_RULE_ID]


def test_two_encrypted_data_blocks_remain_one_encrypted_finding(tmp_path):
    _write(
        tmp_path,
        "bundle.pem",
        _real("encrypted_data.pem") + _real("encrypted_data.pem"),
    )

    found = _cms_findings(tmp_path)

    assert [f.rule_id for f in found] == [ENCRYPTED_RULE_ID]


def test_mixed_cms_and_pkcs7_labels_produce_both_rule_ids(tmp_path):
    # enveloped_data.pem is OpenSSL's own CMS-labelled EnvelopedData block; the
    # PKCS7-labelled EncryptedData block is built the same deterministic way as
    # the committed enveloped_data_pkcs7.pem fixture -- the real ENCRYPTED_DER
    # bytes, only the RFC 7468 wrapper applied.
    _write(
        tmp_path,
        "bundle.pem",
        _real("enveloped_data.pem") + _pem("PKCS7", ENCRYPTED_DER),
    )

    found = _cms_findings(tmp_path)

    assert {f.rule_id for f in found} == RULE_IDS


def test_evidence_store_and_json_preserve_both_findings_from_one_file(tmp_path, capsys):
    target = tmp_path / "target"
    target.mkdir()
    _write(target, "bundle.pem", _real("enveloped_data.pem") + _real("encrypted_data.pem"))
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
    live_records = json.loads(capsys.readouterr().out)
    live_cms = [r for r in live_records if r["rule_id"] in RULE_IDS]
    assert {r["rule_id"] for r in live_cms} == RULE_IDS
    scan_id = live_cms[0]["scan_id"]
    assert scan_id
    assert all(r["scan_id"] == scan_id for r in live_cms)

    assert harvestguard.main(["evidence", "verify", scan_id, "--evidence-db", str(db)]) == 0
    capsys.readouterr()

    assert (
        harvestguard.main(
            ["evidence", "export", scan_id, "--evidence-db", str(db), "--json", "--quiet"]
        )
        == 0
    )
    exported_records = json.loads(capsys.readouterr().out)
    exported_cms = [r for r in exported_records if r["rule_id"] in RULE_IDS]
    assert {r["rule_id"] for r in exported_cms} == RULE_IDS
    assert len(exported_cms) == 2


def test_textual_block_surrounded_by_unrelated_text_is_still_detected(tmp_path):
    _write(
        tmp_path,
        "message.txt",
        b"Subject: notes about an encrypted attachment\n"
        + _real("enveloped_data.pem")
        + b"end of message\n",
    )

    assert _only_cms_finding(tmp_path).rule_id == ENVELOPED_RULE_ID


@pytest.mark.parametrize("label", ["CMS", "PKCS7"])
def test_crlf_line_endings_are_supported(tmp_path, label):
    _write(tmp_path, "message.txt", _pem(label, ENCRYPTED_DER, newline="\r\n"))

    assert _only_cms_finding(tmp_path).rule_id == ENCRYPTED_RULE_ID


@pytest.mark.parametrize("label", ["CMS", "PKCS7"])
def test_lf_line_endings_are_supported(tmp_path, label):
    _write(tmp_path, "message.txt", _pem(label, ENCRYPTED_DER))

    assert _only_cms_finding(tmp_path).rule_id == ENCRYPTED_RULE_ID


def test_optional_unprotected_attributes_are_permitted(tmp_path):
    attributes = _element(_TAG_CONTEXT_1_CONSTRUCTED, _seq(CONTENT_TYPE))
    _write(tmp_path, "enveloped.der", _enveloped(*ENVELOPED_PARTS, attributes))
    _write(
        tmp_path,
        "encrypted.der",
        _encrypted(VERSION_2, ENCRYPTED_PARTS[1], attributes),
    )

    assert {f.rule_id for f in _cms_findings(tmp_path)} == RULE_IDS


def test_optional_originator_info_is_permitted(tmp_path):
    originator = _element(_TAG_CONTEXT_0_CONSTRUCTED, _seq(CONTENT_TYPE))
    _write(
        tmp_path,
        "enveloped.der",
        _enveloped(ENVELOPED_PARTS[0], originator, *ENVELOPED_PARTS[1:]),
    )

    assert _only_cms_finding(tmp_path).rule_id == ENVELOPED_RULE_ID


def test_the_object_is_read_once_through_the_shared_context(tmp_path, monkeypatch):
    target = _write(tmp_path, "message.p7m", ENVELOPED_DER)
    reads: list[str] = []
    original = Path.read_bytes

    def _counted(self):
        reads.append(str(self))
        return original(self)

    monkeypatch.setattr(Path, "read_bytes", _counted)

    assert _only_cms_finding(tmp_path).rule_id == ENVELOPED_RULE_ID
    assert reads.count(str(target)) == 1


# --- 2. Misleading extensions: content wins ---------------------------------

MISLEADING_NAMES = [
    "message",
    "message.bin",
    "message.cms",
    "message.p7m",
    "message.p7e",
    "message.p7b",
    "message.p7c",
    "message.der",
    "message.cer",
    "message.crt",
    "message.p12",
    "message.pfx",
]


@pytest.mark.parametrize("name", MISLEADING_NAMES)
def test_a_valid_object_is_detected_under_any_filename(tmp_path, name):
    target = _write(tmp_path, name, ENVELOPED_DER)

    finding = _only_cms_finding(target)

    assert finding.asset_type == ENVELOPED_ASSET_TYPE
    assert finding.rule_id == ENVELOPED_RULE_ID
    assert finding.confidence == CONFIDENCE


@pytest.mark.parametrize("name", MISLEADING_NAMES)
def test_arbitrary_content_under_those_names_produces_no_finding(tmp_path, name):
    target = _write(tmp_path, name, b"not a CMS object at all\n" * 4)

    assert _cms_findings(target) == []


@pytest.mark.parametrize("name", MISLEADING_NAMES)
def test_a_textual_object_is_detected_under_any_filename(tmp_path, name):
    target = _write(tmp_path, name, _real("encrypted_data.pem"))

    assert _only_cms_finding(target).rule_id == ENCRYPTED_RULE_ID


def test_the_detectors_consult_no_extension_at_all():
    import inspect

    from scanner import crypto_inventory

    for function in (
        crypto_inventory._cms_candidate,
        crypto_inventory._detect_cms_enveloped_data,
        crypto_inventory._detect_cms_encrypted_data,
        crypto_inventory._cms_content_types,
        crypto_inventory._cms_encrypted_content_type,
        crypto_inventory._cms_pem_bodies,
    ):
        source = inspect.getsource(function)
        assert ".suffix" not in source
        assert ".name" not in source


# --- 3. Certificate-only and signed-object separation -----------------------


@pytest.mark.parametrize("name", sorted(REAL_NEGATIVES))
def test_real_non_encrypted_cms_object_produces_no_cms_finding(tmp_path, name):
    _write(tmp_path, name, _real(name))

    assert _cms_findings(tmp_path) == []


@pytest.mark.parametrize("name", sorted(REAL_NEGATIVES))
def test_textual_wrapper_around_a_non_encrypted_object_is_not_evidence(tmp_path, name):
    for label in ("CMS", "PKCS7"):
        _write(tmp_path, f"{label}_{name}.pem", _pem(label, _real(name)))

    assert _cms_findings(tmp_path) == []


def test_the_labels_alone_are_never_evidence(tmp_path):
    _write(
        tmp_path,
        "claims.txt",
        b"-----BEGIN CMS-----\n-----END CMS-----\n"
        b"-----BEGIN PKCS7-----\n-----END PKCS7-----\n"
        b"This file is PKCS7 and CMS encrypted, honestly.\n",
    )

    assert _cms_findings(tmp_path) == []


# --- 4. Structural negative and hostile controls ----------------------------


def _control_cases() -> dict[str, bytes]:
    truncated = ENVELOPED_DER[: len(ENVELOPED_DER) // 2]
    # The real object's own length, re-encoded in a longer form with a leading
    # zero octet -- length-consistent, and not the minimal encoding DER requires.
    non_minimal_outer = (
        bytes([_TAG_SEQUENCE, 0x83])
        + b"\x00"
        + (len(ENVELOPED_DER) - 4).to_bytes(2, "big")
        + ENVELOPED_DER[4:]
    )
    return {
        "empty": b"",
        "truncated outer object": truncated,
        "outer is not a sequence": _element(_TAG_OCTET_STRING, ENVELOPED_DER),
        "trailing bytes": ENVELOPED_DER + b"\x00",
        "embedded at a nonzero offset": b"\x00\x00\x00\x00" + ENVELOPED_DER,
        "unsupported content oid (id-data)": _content_info(OID_DATA, ENVELOPED_BODY),
        "unsupported content oid (id-signedData)": _content_info(
            OID_SIGNED_DATA, ENVELOPED_BODY
        ),
        "oid with a truncated subidentifier": _content_info(
            OID_ENVELOPED_DATA[:-1] + b"\x80", ENVELOPED_BODY
        ),
        "oid is not an oid": _seq(
            _element(_TAG_OCTET_STRING, OID_ENVELOPED_DATA),
            _element(_TAG_CONTEXT_0_CONSTRUCTED, ENVELOPED_BODY),
        ),
        "one child only": _seq(_element(_TAG_OID, OID_ENVELOPED_DATA)),
        "three children": _seq(
            _element(_TAG_OID, OID_ENVELOPED_DATA),
            _element(_TAG_CONTEXT_0_CONSTRUCTED, ENVELOPED_BODY),
            _element(_TAG_CONTEXT_0_CONSTRUCTED, ENVELOPED_BODY),
        ),
        "wrapper is not context [0]": _seq(
            _element(_TAG_OID, OID_ENVELOPED_DATA),
            _element(_TAG_CONTEXT_1_CONSTRUCTED, ENVELOPED_BODY),
        ),
        "wrapper is primitive": _seq(
            _element(_TAG_OID, OID_ENVELOPED_DATA),
            _element(_TAG_CONTEXT_0, ENVELOPED_BODY),
        ),
        "wrapper holds no child": _seq(
            _element(_TAG_OID, OID_ENVELOPED_DATA),
            _element(_TAG_CONTEXT_0_CONSTRUCTED, b""),
        ),
        "wrapper holds two children": _seq(
            _element(_TAG_OID, OID_ENVELOPED_DATA),
            _element(_TAG_CONTEXT_0_CONSTRUCTED, ENVELOPED_BODY + ENVELOPED_BODY),
        ),
        "inner content is not a sequence": _content_info(
            OID_ENVELOPED_DATA, _element(_TAG_OCTET_STRING, b"\x01\x02\x03")
        ),
        "indefinite-length ber outer": b"\x30\x80" + ENVELOPED_DER[4:] + b"\x00\x00",
        "indefinite-length ber wrapper": _seq(
            _element(_TAG_OID, OID_ENVELOPED_DATA),
            b"\xa0\x80" + ENVELOPED_BODY + b"\x00\x00",
        ),
        "non-minimal outer length": non_minimal_outer,
        "high-tag-number form": b"\x3f\x81\x01" + ENVELOPED_DER[3:],
        "oversized declared length": b"\x30\x84\xff\xff\xff\xff" + ENVELOPED_DER[4:],
        "excessive nesting": _content_info(
            OID_ENCRYPTED_DATA,
            _seq(VERSION_0, _eci(algorithm=_nested(20))),
        ),
        # EnvelopedData field controls.
        "enveloped: no version": _enveloped(*ENVELOPED_PARTS[1:]),
        "enveloped: version is not an integer": _enveloped(
            _element(_TAG_OCTET_STRING, b"\x00"), *ENVELOPED_PARTS[1:]
        ),
        "enveloped: non-minimal version": _enveloped(
            _element(_TAG_INTEGER, b"\x00\x00"), *ENVELOPED_PARTS[1:]
        ),
        "enveloped: recipientInfos missing": _enveloped(
            ENVELOPED_PARTS[0], ENVELOPED_PARTS[2]
        ),
        "enveloped: recipientInfos is empty": _enveloped(
            ENVELOPED_PARTS[0], _element(_TAG_SET, b""), ENVELOPED_PARTS[2]
        ),
        "enveloped: recipientInfos is not a set": _enveloped(
            ENVELOPED_PARTS[0], _seq(CONTENT_TYPE), ENVELOPED_PARTS[2]
        ),
        "enveloped: recipientInfos holds malformed der": _enveloped(
            ENVELOPED_PARTS[0], _element(_TAG_SET, b"\x30\x7f"), ENVELOPED_PARTS[2]
        ),
        "enveloped: no encryptedContentInfo": _enveloped(*ENVELOPED_PARTS[:2]),
        "enveloped: trailing child": _enveloped(*ENVELOPED_PARTS, CONTENT_TYPE),
        "enveloped: empty body": _content_info(OID_ENVELOPED_DATA, _seq()),
        # EncryptedData field controls.
        "encrypted: no version": _encrypted(ENCRYPTED_PARTS[1]),
        "encrypted: version 1": _encrypted(
            _element(_TAG_INTEGER, b"\x01"), ENCRYPTED_PARTS[1]
        ),
        "encrypted: version 2 without attributes": _encrypted(
            VERSION_2, ENCRYPTED_PARTS[1]
        ),
        "encrypted: version 0 with attributes": _encrypted(
            VERSION_0,
            ENCRYPTED_PARTS[1],
            _element(_TAG_CONTEXT_1_CONSTRUCTED, _seq(CONTENT_TYPE)),
        ),
        "encrypted: trailing child": _encrypted(*ENCRYPTED_PARTS, CONTENT_TYPE),
        # EncryptedContentInfo controls.
        "eci: is not a sequence": _encrypted(
            VERSION_0, _element(_TAG_OCTET_STRING, b"\x01")
        ),
        "eci: content type is not an oid": _encrypted(
            VERSION_0, _eci(content_type=_element(_TAG_OCTET_STRING, OID_DATA))
        ),
        "eci: algorithm is not a sequence": _encrypted(
            VERSION_0, _eci(algorithm=_element(_TAG_OID, OID_AES_256_CBC))
        ),
        "eci: algorithm has no oid": _encrypted(
            VERSION_0, _eci(algorithm=_seq(_element(_TAG_NULL, b"")))
        ),
        "eci: algorithm holds malformed der": _encrypted(
            VERSION_0,
            _eci(algorithm=_seq(_element(_TAG_OID, OID_AES_256_CBC), _seq(b"\x30\x7f"))),
        ),
        "eci: encrypted content absent (detached)": _encrypted(
            VERSION_0, _eci(encrypted_content=None)
        ),
        "eci: encrypted content empty": _encrypted(
            VERSION_0, _eci(encrypted_content=_element(_TAG_CONTEXT_0, b""))
        ),
        "eci: encrypted content is not context [0]": _encrypted(
            VERSION_0, _eci(encrypted_content=_element(_TAG_OCTET_STRING, b"\x01\x02"))
        ),
        "eci: encrypted content is constructed": _encrypted(
            VERSION_0,
            _eci(
                encrypted_content=_element(
                    _TAG_CONTEXT_0_CONSTRUCTED, _element(_TAG_OCTET_STRING, b"\x01\x02")
                )
            ),
        ),
        "eci: fourth child": _encrypted(
            VERSION_0, _seq(CONTENT_TYPE, REAL_ALGORITHM, REAL_CIPHERTEXT, CONTENT_TYPE)
        ),
        "eci: two children only": _encrypted(VERSION_0, _seq(CONTENT_TYPE, REAL_ALGORITHM)),
        # Arbitrary CMS-like binary.
        "cms-like noise": bytes(range(256)) * 2,
        "sequence header over noise": _seq(b"\xff" * 64),
    }


def _nested(depth: int) -> bytes:
    """A SEQUENCE nested ``depth`` levels deep, for the recursion bound."""
    element = _seq(_element(_TAG_OID, OID_AES_256_CBC))
    for _ in range(depth):
        element = _seq(element)
    return _seq(_element(_TAG_OID, OID_AES_256_CBC), element)


CONTROL_CASES = _control_cases()


@pytest.mark.parametrize("case", sorted(CONTROL_CASES))
def test_structural_control_produces_no_cms_finding(tmp_path, case):
    _write(tmp_path, "message.p7m", CONTROL_CASES[case])

    assert _cms_findings(tmp_path) == [], case


@pytest.mark.parametrize("case", sorted(CONTROL_CASES))
def test_structural_control_never_raises_and_never_claims_high_confidence(tmp_path, case):
    _write(tmp_path, "message.p7m", CONTROL_CASES[case])

    for finding in _findings(tmp_path):
        assert finding.rule_id not in RULE_IDS
        assert FORMAT not in json.dumps(finding.technical_metadata)


@pytest.mark.parametrize("case", sorted(CONTROL_CASES))
def test_a_textual_wrapper_cannot_rescue_a_structural_control(tmp_path, case):
    _write(tmp_path, "message.pem", _pem("CMS", CONTROL_CASES[case]))

    assert _cms_findings(tmp_path) == [], case


TEXT_CONTROL_CASES = {
    "prefix on the begin line": b"junk-----BEGIN CMS-----\n"
    + base64.b64encode(ENVELOPED_DER)
    + b"\n-----END CMS-----\n",
    "suffix on the begin line": b"-----BEGIN CMS-----junk\n"
    + base64.b64encode(ENVELOPED_DER)
    + b"\n-----END CMS-----\n",
    "prefix on the end line": b"-----BEGIN CMS-----\n"
    + base64.b64encode(ENVELOPED_DER)
    + b"\njunk-----END CMS-----\n",
    "suffix on the end line": b"-----BEGIN CMS-----\n"
    + base64.b64encode(ENVELOPED_DER)
    + b"\n-----END CMS-----junk\n",
    "mismatched labels": b"-----BEGIN CMS-----\n"
    + base64.b64encode(ENVELOPED_DER)
    + b"\n-----END PKCS7-----\n",
    "no footer": b"-----BEGIN CMS-----\n" + base64.b64encode(ENVELOPED_DER) + b"\n",
    "empty body": b"-----BEGIN CMS-----\n-----END CMS-----\n",
    "invalid base64": b"-----BEGIN PKCS7-----\nnot base64 !!!\n-----END PKCS7-----\n",
    "valid base64 carrying non-cms data": b"-----BEGIN CMS-----\n"
    + base64.b64encode(b"this is not a CMS ContentInfo at all")
    + b"\n-----END CMS-----\n",
    "lowercase label": b"-----begin cms-----\n"
    + base64.b64encode(ENVELOPED_DER)
    + b"\n-----end cms-----\n",
    "unsupported label": b"-----BEGIN PKCS#7-----\n"
    + base64.b64encode(ENVELOPED_DER)
    + b"\n-----END PKCS#7-----\n",
}


@pytest.mark.parametrize("case", sorted(TEXT_CONTROL_CASES))
def test_malformed_textual_block_produces_no_cms_finding(tmp_path, case):
    _write(tmp_path, "message.txt", TEXT_CONTROL_CASES[case])

    assert _cms_findings(tmp_path) == [], case


# --- 5. Neighbouring real formats keep their own classification -------------

ADJACENT_FIXTURES = {
    "rsa_cert.der": FIXTURE_DIR / "rsa_cert.der",
    "bundle.p12": FIXTURE_DIR / "bundle.p12",
    "sample.jks": FIXTURE_DIR / "sample.jks",
    "rsa_encrypted_pkcs8.der": FIXTURE_DIR / "pkcs8_encrypted" / "rsa_encrypted_pkcs8.der",
    "ec_encrypted_pkcs8.der": FIXTURE_DIR / "pkcs8_encrypted" / "ec_encrypted_pkcs8.der",
    "rsa_encrypted_pkcs8.pem": FIXTURE_DIR / "pkcs8_encrypted" / "rsa_encrypted_pkcs8.pem",
    "private_key_store.bcfks": FIXTURE_DIR / "bcfks" / "private_key_store.bcfks",
    "private_key_store.jceks": FIXTURE_DIR / "jceks" / "private_key_store.jceks",
    "rsa_cert.pem": FIXTURE_DIR / "rsa_cert.pem",
    "valid_key.pem": FIXTURE_DIR / "valid_key.pem",
}


@pytest.mark.parametrize("name", sorted(ADJACENT_FIXTURES))
def test_adjacent_real_format_is_never_claimed_as_cms(tmp_path, name):
    _write(tmp_path, name, ADJACENT_FIXTURES[name].read_bytes())

    assert _cms_findings(tmp_path) == []


def test_existing_detectors_keep_their_own_findings_unchanged(tmp_path):
    for name, source in ADJACENT_FIXTURES.items():
        _write(tmp_path, name, source.read_bytes())

    rule_ids = {f.rule_id for f in _findings(tmp_path)}

    assert RULE_IDS.isdisjoint(rule_ids)
    assert {
        "java_keystore:bcfks",
        "java_keystore:jceks",
        "private_key:pkcs8_encrypted",
    } <= rule_ids


# --- 6. Registry contract ---------------------------------------------------


def _detector(detector_id: str):
    return next(d for d in CRYPTO_DETECTORS if d.detector_id == detector_id)


def _priority(detector_id: str) -> int:
    return _detector(detector_id).priority


@pytest.mark.parametrize(
    "detector_id,priority,rule_id,evidence",
    [
        (ENVELOPED_RULE_ID, ENVELOPED_PRIORITY, ENVELOPED_RULE_ID, ENVELOPED_EVIDENCE),
        (ENCRYPTED_RULE_ID, ENCRYPTED_PRIORITY, ENCRYPTED_RULE_ID, ENCRYPTED_EVIDENCE),
    ],
)
def test_detector_declares_the_required_contract(detector_id, priority, rule_id, evidence):
    detector = _detector(detector_id)

    assert [d.detector_id for d in CRYPTO_DETECTORS].count(detector_id) == 1
    assert detector.priority == priority
    assert detector.rule_id == rule_id
    assert detector.evidence == evidence
    assert detector.confidence == CONFIDENCE
    assert detector.terminal is True
    assert detector.metadata_keys == frozenset({"Format"})
    assert detector.verification_rationale


@pytest.mark.parametrize("detector_id", sorted(RULE_IDS))
def test_registry_order_places_the_detectors_correctly(detector_id):
    for later in ("pkcs12:container", "certificate:der", "certificate:pem", "private_key:pem"):
        assert _priority(detector_id) < _priority(later)
    for earlier in (
        "java_keystore:bcfks",
        "java_keystore:jceks",
        "java_keystore:jks_magic",
        "private_key:pkcs8_encrypted",
    ):
        assert _priority(earlier) < _priority(detector_id)
    assert _priority(ENVELOPED_RULE_ID) < _priority(ENCRYPTED_RULE_ID)


@pytest.mark.parametrize("name", sorted(REAL_POSITIVES))
def test_a_positive_match_is_terminal(tmp_path, name):
    # A real object saved under an extension the DER/PKCS#12 detectors claim is
    # reported once, as what it is -- not also as a malformed container.
    for suffix in (".der", ".p12", ".cer"):
        _write(tmp_path, f"{Path(name).stem}{suffix}", _real(name))

    found = _findings(tmp_path)

    assert len(found) == 3
    assert {f.rule_id for f in found} == {REAL_POSITIVES[name][0]}


def test_a_non_match_falls_through_to_the_existing_detectors(tmp_path):
    _write(tmp_path, "cert.der", (FIXTURE_DIR / "rsa_cert.der").read_bytes())

    found = _findings(tmp_path)

    assert [f.asset_type for f in found] == ["DER Certificate"]


# --- 7. Normalization, evidence store, and output shape ---------------------


@pytest.mark.parametrize("name", sorted(REAL_POSITIVES))
def test_normalized_finding_preserves_the_whole_contract(tmp_path, name):
    rule_id = REAL_POSITIVES[name][0]
    _write(tmp_path, name, _real(name))

    df = scan_crypto_inventory(str(tmp_path))
    findings = normalize_crypto_inventory_df(df)

    assert df.loc[0, "Rule ID"] == rule_id
    assert df.loc[0, "Format"] == FORMAT
    assert len(findings) == 1
    finding = findings[0]
    assert finding.source_type == "crypto_inventory"
    assert finding.rule_id == rule_id
    assert finding.confidence == CONFIDENCE
    assert finding.provenance.rule_id == rule_id
    assert finding.technical_metadata["Format"] == FORMAT


@pytest.mark.parametrize("name", sorted(REAL_POSITIVES))
def test_safe_metadata_carries_only_the_format_key(tmp_path, name):
    _write(tmp_path, name, _real(name))

    finding = _only_cms_finding(tmp_path)
    populated = {k: v for k, v in finding.technical_metadata.items() if v is not None}

    assert populated == {"Format": FORMAT}


def test_dataframe_columns_are_unchanged(tmp_path):
    _write(tmp_path, "message.p7m", ENVELOPED_DER)
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
    _write(tmp_path, "enveloped.p7m", ENVELOPED_DER)
    _write(tmp_path, "encrypted.p7m", ENCRYPTED_DER)

    first = scan_crypto_inventory_findings(str(tmp_path))
    second = scan_crypto_inventory_findings(str(tmp_path))

    assert [f.finding_id for f in first] == [f.finding_id for f in second]
    assert all(f.finding_id for f in first)


def test_cli_json_carries_both_findings_and_markdown_stays_evidence_only(tmp_path, capsys):
    _write(tmp_path, "enveloped.p7m", ENVELOPED_DER)
    _write(tmp_path, "encrypted.p7m", ENCRYPTED_DER)

    assert (
        harvestguard.main(["scan", str(tmp_path), "--type", "crypto", "--json", "--quiet"]) == 0
    )
    payload = json.loads(capsys.readouterr().out)

    assert isinstance(payload, list) and len(payload) == 2
    assert {r["rule_id"] for r in payload} == RULE_IDS
    for record in payload:
        assert record["source_type"] == "crypto_inventory"
        assert record["confidence"] == CONFIDENCE
        assert record["technical_metadata"]["Format"] == FORMAT
        for forbidden in ("risk", "remediat", "quantum", "hndl", "compliance", "migrat"):
            assert forbidden not in record["evidence"].lower()

    assert (
        harvestguard.main(["scan", str(tmp_path), "--type", "crypto", "--markdown", "--quiet"])
        == 0
    )
    report = capsys.readouterr().out
    assert ENVELOPED_ASSET_TYPE in report
    assert ENCRYPTED_ASSET_TYPE in report
    assert ENVELOPED_EVIDENCE in report
    assert ENCRYPTED_EVIDENCE in report


def test_evidence_store_round_trip_preserves_both_findings(tmp_path, capsys):
    target = tmp_path / "target"
    target.mkdir()
    _write(target, "enveloped.p7m", ENVELOPED_DER)
    _write(target, "encrypted.p7m", ENCRYPTED_DER)
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
    records = json.loads(live)
    scan_id = records[0]["scan_id"]
    assert scan_id
    assert all(r["scan_id"] == scan_id for r in records)

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
    exported = json.loads(stored)
    assert {r["rule_id"] for r in exported} == RULE_IDS
    for record in exported:
        assert record["scan_id"] == scan_id
        assert record["confidence"] == CONFIDENCE
        assert record["technical_metadata"]["Format"] == FORMAT
        assert record["schema_version"] == "1.0.0"

    assert (
        harvestguard.main(
            ["evidence", "export", scan_id, "--evidence-db", str(db), "--markdown", "--quiet"]
        )
        == 0
    )
    markdown = capsys.readouterr().out
    assert ENVELOPED_ASSET_TYPE in markdown
    assert ENCRYPTED_ASSET_TYPE in markdown


# --- 8. Accounting ----------------------------------------------------------


def test_scan_accounting_is_unchanged_by_the_new_detectors(tmp_path, capsys):
    _write(tmp_path, "enveloped.p7m", ENVELOPED_DER)
    _write(tmp_path, "plain.txt", b"ordinary file content\n")
    (tmp_path / "rsa_cert.pem").write_bytes((FIXTURE_DIR / "rsa_cert.pem").read_bytes())

    assert harvestguard.main(["scan", str(tmp_path), "--type", "crypto"]) == 0
    output = capsys.readouterr().out

    assert "3" in output


def test_one_file_target_still_scans_exactly_that_file(tmp_path):
    target = _write(tmp_path, "message.p7m", ENVELOPED_DER)
    _write(tmp_path, "other.p7m", ENCRYPTED_DER)

    found = _findings(target)

    assert len(found) == 1
    assert found[0].location == str(target)


def test_an_unreadable_file_produces_no_finding_and_no_error(tmp_path):
    path = _write(tmp_path, "message.p7m", ENVELOPED_DER)
    path.chmod(0o000)
    try:
        if os.access(path, os.R_OK):  # pragma: no cover - running as root
            pytest.skip("cannot make a file unreadable as this user")
        assert _findings(tmp_path) == []
    finally:
        path.chmod(0o600)


def test_a_malformed_neighbour_does_not_suppress_a_valid_object(tmp_path):
    _write(tmp_path, "good.p7m", ENVELOPED_DER)
    _write(tmp_path, "bad.p7m", CONTROL_CASES["truncated outer object"])

    assert [f.rule_id for f in _cms_findings(tmp_path)] == [ENVELOPED_RULE_ID]


# --- 9. The no-decryption, no-secret, privacy boundary ----------------------


def test_detection_calls_no_key_loading_or_decryption_api(tmp_path, monkeypatch):
    from cryptography.hazmat.primitives import serialization

    def _forbidden(*args, **kwargs):  # pragma: no cover - must never run
        raise AssertionError("the CMS detectors must not load keys or decrypt")

    for api in (
        "load_pem_private_key",
        "load_der_private_key",
        "load_pem_public_key",
        "load_der_public_key",
    ):
        monkeypatch.setattr(serialization, api, _forbidden)

    _write(tmp_path, "enveloped.p7m", ENVELOPED_DER)
    _write(tmp_path, "encrypted.p7m", ENCRYPTED_DER)

    assert {f.rule_id for f in _cms_findings(tmp_path)} == RULE_IDS


def test_detection_invokes_no_external_process(tmp_path, monkeypatch):
    def _forbidden(*args, **kwargs):  # pragma: no cover - must never run
        raise AssertionError("the CMS detectors must not invoke an external process")

    monkeypatch.setattr(subprocess, "run", _forbidden)
    monkeypatch.setattr(subprocess, "Popen", _forbidden)
    monkeypatch.setattr(subprocess, "check_output", _forbidden)
    monkeypatch.setattr(os, "system", _forbidden)

    _write(tmp_path, "enveloped.p7m", ENVELOPED_DER)

    assert _only_cms_finding(tmp_path).rule_id == ENVELOPED_RULE_ID


def test_detection_reads_no_secret_from_the_environment(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("CMS_PASSWORD", "harvestguard-canary-not-a-real-secret")
    monkeypatch.setenv("CMS_SECRETKEY", "harvestguard-canary-not-a-real-secret")
    _write(tmp_path, "encrypted.p7m", ENCRYPTED_DER)

    assert harvestguard.main(["scan", str(tmp_path), "--type", "crypto", "--json"]) == 0
    output = capsys.readouterr().out

    assert "harvestguard-canary-not-a-real-secret" not in output


@pytest.mark.parametrize("name", sorted(REAL_POSITIVES))
def test_no_object_content_reaches_json_or_markdown(tmp_path, capsys, name):
    data = _real(name)
    _write(tmp_path, name, data)

    assert harvestguard.main(["scan", str(tmp_path), "--type", "crypto", "--json"]) == 0
    json_output = capsys.readouterr().out
    assert harvestguard.main(["scan", str(tmp_path), "--type", "crypto", "--markdown"]) == 0
    markdown_output = capsys.readouterr().out

    for output in (json_output, markdown_output):
        lowered = output.lower()
        # No ciphertext, no ASN.1 fragment, no base64 body, no OID, no
        # recipient identity, no algorithm or KDF name, no salt/IV.
        assert base64.b64encode(data).decode("ascii")[:32] not in output
        assert data[:16].hex() not in lowered
        for secret in GENERATION_DETAIL:
            assert secret.lower() not in lowered
        assert "recipient" not in lowered
        assert "octet" not in lowered
        assert "asn.1" not in lowered
        assert not re.search(r"\b\d+\.\d+\.\d+\.\d+\.\d+", output)


def test_the_finding_makes_no_strength_or_business_claim(tmp_path):
    _write(tmp_path, "enveloped.p7m", ENVELOPED_DER)
    _write(tmp_path, "encrypted.p7m", ENCRYPTED_DER)

    for finding in _cms_findings(tmp_path):
        text = json.dumps(
            {
                "asset_type": finding.asset_type,
                "evidence": finding.evidence,
                "metadata": dict(finding.technical_metadata),
            }
        ).lower()
        for forbidden in (
            "weak",
            "strong",
            "quantum",
            "hndl",
            "risk",
            "remediat",
            "migrat",
            "compliance",
            "vulnerab",
            "recommend",
        ):
            assert forbidden not in text


@pytest.mark.parametrize("case", ["truncated outer object", "oversized declared length"])
def test_malformed_input_surfaces_no_parser_payload(tmp_path, capsys, case):
    data = CONTROL_CASES[case]
    _write(tmp_path, "message.p7m", data)

    assert harvestguard.main(["scan", str(tmp_path), "--type", "crypto", "--json"]) == 0
    output = capsys.readouterr().out

    assert "Traceback" not in output
    if data:
        assert data[:8].hex() not in output.lower()


# --- 10. Fixture provenance and documentation -------------------------------


def test_the_committed_fixtures_are_the_recorded_real_artifacts():
    provenance = (CMS_DIR / "PROVENANCE.md").read_text()

    for name in sorted({*REAL_POSITIVES, *REAL_NEGATIVES}):
        data = (CMS_DIR / name).read_bytes()
        assert name in provenance
        assert hashlib.sha256(data).hexdigest() in provenance
        assert str(len(data)) in provenance
    assert "OpenSSL 3.0.13" in provenance
    # No private key or production secret is committed alongside the fixtures.
    committed = {path.name for path in CMS_DIR.iterdir()}
    assert not any(name.endswith("key.pem") for name in committed)
    for path in CMS_DIR.iterdir():
        if path.suffix in {".pem", ".md"}:
            assert "PRIVATE KEY" not in path.read_text()


def test_the_pkcs7_wrapper_fixture_carries_a_real_openssl_payload():
    text = (CMS_DIR / "enveloped_data_pkcs7.pem").read_text()
    body = "".join(text.splitlines()[1:-1])

    assert base64.b64decode(body, validate=True) == ENVELOPED_DER


@pytest.mark.parametrize(
    "relative_path",
    ["README.md", "docs/CLI.md", "docs/CRYPTO_INVENTORY.md", "docs/DETECTION_CHARACTERIZATION.md"],
)
def test_support_claims_are_documented_consistently(relative_path):
    text = (REPO_ROOT / relative_path).read_text()

    assert "CMS" in text
    assert ENVELOPED_RULE_ID in text or "EnvelopedData" in text


def test_characterization_documents_the_cms_boundaries():
    text = (REPO_ROOT / "docs" / "DETECTION_CHARACTERIZATION.md").read_text()

    assert ENVELOPED_RULE_ID in text
    assert ENCRYPTED_RULE_ID in text
    lowered = text.lower()
    for boundary in ("indefinite-length", "detached", "authenveloped", "signeddata"):
        assert boundary in lowered


def test_no_new_dependency_is_declared_for_cms_detection():
    requirements = (REPO_ROOT / "requirements.txt").read_text().lower()

    for forbidden in ("asn1crypto", "pyasn1", "asn1tools", "endesive"):
        assert forbidden not in requirements
