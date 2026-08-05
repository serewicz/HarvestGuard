"""Regression coverage for HG-035 (GitHub issue #80): age encrypted-file
detection in the crypto-inventory scanner, the exact evidence-only finding
contract, and the narrow supported-format boundary (native age v1 only).

Complements tests/test_openssl_encrypted_file_detection.py (HG-030) and
tests/test_openpgp_encrypted_file_detection.py (HG-031), which have the same
shape of coverage for the other two `Encrypted File` rules, and
tests/test_crypto_detector_framework.py, which pins the registry composition
this adds one detector to.

Fixtures are synthesized in-process from the native age v1 header grammar, so no
binary fixture is committed and no test requires the `age` binary -- which the
detector never invokes either.

One boundary is worth stating here because the issue text assumed otherwise:
`scanner/filesystem.py` has recognized the leading bytes
`age-encryption.org/v1` as `File-level (age)` since before HG-035, so under
`--type all` a valid age file also produces that separate `local_filesystem`
`file` record. HG-035 deliberately adds no cross-scanner dedup pairing for age
(see `test_no_cross_scanner_dedup_path_is_added_for_age`), so that pre-existing
record is unchanged; exactly one `encrypted_file:age` finding is emitted, from
crypto inventory.
"""

from __future__ import annotations

import base64
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

# --- Synthetic fixtures ------------------------------------------------------
#
# The native age v1 layout, exactly as the format fixes it:
#
#   age-encryption.org/v1\n
#   -> <recipient type> <argument...>\n
#   <wrapped unpadded-base64 stanza body>\n
#   --- <43 unpadded-base64 characters>\n
#   <binary encrypted payload>
#
# Every base64-shaped value below is arbitrary filler of the right *shape*: no
# real recipient share, file key, MAC, or ciphertext is involved, and the
# detector never interprets any of them.


def _b64(data: bytes) -> str:
    """Unpadded base64, the encoding age uses for stanza bodies and the MAC."""
    return base64.b64encode(data).decode("ascii").rstrip("=")


# A 32-byte X25519 ephemeral share (43 base64 characters), the argument shape a
# real `-> X25519` stanza line carries.
X25519_ARGUMENT = _b64(bytes(range(0x00, 0x20)))
# A 32-byte wrapped file key: 43 base64 characters, so one short body line.
STANZA_BODY = _b64(bytes(range(0x40, 0x60)))
# A 32-byte HMAC-SHA-256, which is always exactly 43 base64 characters.
HEADER_MAC = _b64(bytes(range(0x80, 0xA0)))
# The smallest supported payload: a 16-byte header nonce plus one 16-byte chunk
# authentication tag.
MIN_PAYLOAD = bytes(range(0x20, 0x40))
VERSION_LINE = b"age-encryption.org/v1\n"


def _stanza(arguments: str = f"X25519 {X25519_ARGUMENT}", body: str | None = STANZA_BODY) -> bytes:
    """One recipient stanza: an argument line plus its wrapped base64 body.

    ``body`` is written verbatim (already-wrapped lines included), and None
    writes the argument line with no body line at all.
    """
    stanza = f"-> {arguments}\n"
    if body is not None:
        stanza += f"{body}\n"
    return stanza.encode("ascii")


def _age_file(
    stanzas: bytes | None = None,
    mac: str | None = HEADER_MAC,
    payload: bytes | None = MIN_PAYLOAD,
    version_line: bytes = VERSION_LINE,
) -> bytes:
    """A native age v1 file. Defaults produce the exact supported shape; each
    argument exists so a negative test can break one element and nothing else."""
    data = version_line
    data += _stanza() if stanzas is None else stanzas
    if mac is not None:
        data += f"--- {mac}\n".encode("ascii")
    if payload is not None:
        data += payload
    return data


def _multiline_body(lines: int = 3) -> str:
    """A wrapped stanza body: ``lines`` full 64-character lines followed by a
    short final line, the shape age writes for a longer body."""
    full = _b64(bytes(range(0x00, 0x30)))  # 48 bytes -> exactly 64 characters
    assert len(full) == 64
    return "\n".join([full] * lines + [STANZA_BODY])


def _write(tmp_path: Path, name: str, data: bytes) -> Path:
    target = tmp_path / name
    target.write_bytes(data)
    return target


# --- 1-5. Positive cases -----------------------------------------------------


def test_supported_native_age_v1_file_produces_the_exact_finding_contract(tmp_path):
    _write(tmp_path, "secret.age", _age_file())

    findings = scan_crypto_inventory_findings(str(tmp_path))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.source_type == "crypto_inventory"
    assert finding.asset_type == "Encrypted File"
    assert finding.rule_id == "encrypted_file:age"
    assert finding.confidence == "High"
    assert finding.evidence == "Observed age encrypted file."


def test_valid_file_with_one_recipient_stanza_is_detected(tmp_path):
    _write(tmp_path, "one-recipient.age", _age_file(stanzas=_stanza()))

    findings = scan_crypto_inventory_findings(str(tmp_path))

    assert [f.rule_id for f in findings] == ["encrypted_file:age"]


def test_valid_file_with_multiple_recipient_stanzas_is_detected(tmp_path):
    three = (
        _stanza()
        + _stanza(arguments=f"X25519 {_b64(bytes(range(0x10, 0x30)))}")
        + _stanza(arguments="scrypt bWluaW1hbHNhbHQ 18", body=_multiline_body(2))
    )
    _write(tmp_path, "many-recipients.age", _age_file(stanzas=three))

    findings = scan_crypto_inventory_findings(str(tmp_path))

    assert [f.rule_id for f in findings] == ["encrypted_file:age"]


def test_minimum_supported_payload_boundary_is_detected(tmp_path):
    # Exactly 32 bytes: 16-byte nonce plus one chunk authentication tag.
    assert len(MIN_PAYLOAD) == 32
    _write(tmp_path, "minimum.age", _age_file(payload=MIN_PAYLOAD))

    findings = scan_crypto_inventory_findings(str(tmp_path))

    assert [f.rule_id for f in findings] == ["encrypted_file:age"]


def test_wrapped_lf_terminated_stanza_body_is_detected(tmp_path):
    # Full body lines are exactly 64 characters and the final one is shorter;
    # every line, including the last, is LF-terminated.
    data = _age_file(stanzas=_stanza(body=_multiline_body(3)))
    assert b"\r" not in data
    _write(tmp_path, "wrapped.age", data)

    findings = scan_crypto_inventory_findings(str(tmp_path))

    assert [f.rule_id for f in findings] == ["encrypted_file:age"]


def test_detection_is_independent_of_filename_and_extension(tmp_path):
    for name in ("secret.age", "secret.bin", "secret", "notes.txt"):
        _write(tmp_path, name, _age_file())

    findings = scan_crypto_inventory_findings(str(tmp_path))

    assert len(findings) == 4
    assert all(f.rule_id == "encrypted_file:age" for f in findings)


# --- 6-28. Negative cases ----------------------------------------------------

# Copied from the age README/specification: an example is documentation, not
# evidence of an encrypted file on this disk.
_DOCUMENTATION_EXAMPLE = (
    b"The header of an age file looks like this:\n\n"
    b"    age-encryption.org/v1\n"
    b"    -> X25519 <recipient share>\n"
    b"    <wrapped file key>\n"
    b"    --- <header MAC>\n\n"
    b"followed by the encrypted payload.\n"
)

_NEGATIVE_CASES = [
    # 6-7. Nothing to parse.
    ("empty.age", b""),
    ("short.age", b"age-"),
    ("version-prefix-only.age", VERSION_LINE[:-1]),
    # 8. Header (version line) only.
    ("version-line-only.age", VERSION_LINE),
    # 9. Header plus an incomplete stanza.
    ("stanza-prefix-only.age", VERSION_LINE + b"-> "),
    ("unterminated-stanza-line.age", VERSION_LINE + b"-> X25519 " + X25519_ARGUMENT.encode()),
    ("stanza-line-without-body.age", VERSION_LINE + _stanza(body=None)),
    ("unterminated-body-line.age", VERSION_LINE + b"-> X25519 abc\n" + STANZA_BODY.encode()),
    # 10. Header plus stanza but no MAC line.
    ("no-mac-line.age", _age_file(mac=None)),
    ("unterminated-mac-line.age", VERSION_LINE + _stanza() + f"--- {HEADER_MAC}".encode()),
    # 11. Header plus stanza and MAC line but no payload.
    ("no-payload.age", _age_file(payload=None)),
    ("empty-payload.age", _age_file(payload=b"")),
    # 12. Payload shorter than the supported 32-byte minimum.
    ("payload-31-bytes.age", _age_file(payload=MIN_PAYLOAD[:31])),
    ("payload-1-byte.age", _age_file(payload=MIN_PAYLOAD[:1])),
    # 13. Near-match version strings.
    ("near-match-version.age", _age_file(version_line=b"age-encryption.org/v1.0\n")),
    ("near-match-suffix.age", _age_file(version_line=b"age-encryption.org/v11\n")),
    ("near-match-host.age", _age_file(version_line=b"age-encryption.com/v1\n")),
    ("near-match-space.age", _age_file(version_line=b"age-encryption.org/v1 \n")),
    ("near-match-case.age", _age_file(version_line=b"AGE-ENCRYPTION.ORG/v1\n")),
    # 14. Unsupported (non-v1) native age versions.
    ("version-2.age", _age_file(version_line=b"age-encryption.org/v2\n")),
    ("version-0.age", _age_file(version_line=b"age-encryption.org/v0\n")),
    # 15. A valid header that does not start at byte offset 0.
    ("offset-newline.age", b"\n" + _age_file()),
    ("offset-text.age", b"preamble\n" + _age_file()),
    ("offset-nul.age", b"\x00" + _age_file()),
    # 16-18. Content that is not age at all.
    ("random.bin", bytes(range(256)) * 4),
    ("nulls.bin", b"\x00" * 512),
    ("ascii-with-age.txt", b"the age of this backup is unknown; age matters\n" * 8),
    ("documentation.md", _DOCUMENTATION_EXAMPLE),
    # 19. Malformed stanza argument lines.
    ("stanza-no-space.age", _age_file(stanzas=b"->X25519 abc\n" + f"{STANZA_BODY}\n".encode())),
    ("stanza-no-arguments.age", _age_file(stanzas=_stanza(arguments=""))),
    ("stanza-blank-argument.age", _age_file(stanzas=_stanza(arguments="X25519  abc"))),
    ("stanza-trailing-space.age", _age_file(stanzas=_stanza(arguments="X25519 abc "))),
    ("stanza-tab-argument.age", _age_file(stanzas=_stanza(arguments="X25519\tabc"))),
    ("stanza-wrong-arrow.age", _age_file(stanzas=b"=> X25519 abc\n" + f"{STANZA_BODY}\n".encode())),
    # 20. Empty stanza body.
    ("empty-stanza-body.age", _age_file(stanzas=_stanza(body=""))),
    (
        "second-stanza-empty-body.age",
        _age_file(stanzas=_stanza() + _stanza(arguments="X25519 abc", body="")),
    ),
    # 21. Stanza body characters outside the unpadded-base64 alphabet.
    ("padded-stanza-body.age", _age_file(stanzas=_stanza(body=STANZA_BODY[:-1] + "="))),
    ("stanza-body-punctuation.age", _age_file(stanzas=_stanza(body=STANZA_BODY[:-1] + "!"))),
    ("stanza-body-space.age", _age_file(stanzas=_stanza(body=STANZA_BODY[:-1] + " "))),
    # 22. Stanza body line lengths that do not follow the wrapping rule.
    ("long-stanza-body-line.age", _age_file(stanzas=_stanza(body=_b64(bytes(range(0x00, 0x31)))))),
    (
        "full-line-then-mac.age",
        _age_file(stanzas=_stanza(body=_b64(bytes(range(0x00, 0x30))))),
    ),
    # 23. Invalid MAC-line prefixes.
    ("mac-two-dashes.age", VERSION_LINE + _stanza() + f"-- {HEADER_MAC}\n".encode() + MIN_PAYLOAD),
    (
        "mac-four-dashes.age",
        VERSION_LINE + _stanza() + f"---- {HEADER_MAC}\n".encode() + MIN_PAYLOAD,
    ),
    ("mac-no-space.age", VERSION_LINE + _stanza() + f"---{HEADER_MAC}\n".encode() + MIN_PAYLOAD),
    # 24. Invalid MAC-line lengths.
    ("mac-too-short.age", _age_file(mac=HEADER_MAC[:42])),
    ("mac-too-long.age", _age_file(mac=HEADER_MAC + "A")),
    ("mac-empty.age", _age_file(mac="")),
    # 25. MAC characters outside the unpadded-base64 alphabet.
    ("mac-padded.age", _age_file(mac=HEADER_MAC[:-1] + "=")),
    ("mac-punctuation.age", _age_file(mac=HEADER_MAC[:-1] + "!")),
    ("mac-space.age", _age_file(mac=HEADER_MAC[:-1] + " ")),
    # 26. CRLF native header (out of scope for HG-035, and not silently accepted).
    ("crlf.age", _age_file().replace(b"\n", b"\r\n")),
    (
        "crlf-mac-only.age",
        _age_file().replace(
            f"--- {HEADER_MAC}\n".encode(), f"--- {HEADER_MAC}\r\n".encode()
        ),
    ),
    # 27. ASCII-armored age file: deliberately unsupported in HG-035.
    (
        "armored.age",
        b"-----BEGIN AGE ENCRYPTED FILE-----\n"
        + base64.b64encode(_age_file())
        + b"\n-----END AGE ENCRYPTED FILE-----\n",
    ),
    # 28. Plaintext that merely carries the `.age` extension.
    ("plaintext.age", b"this file is not encrypted at all\n"),
    # A MAC line with no stanza in front of it is an incomplete header.
    ("no-stanza.age", VERSION_LINE + f"--- {HEADER_MAC}\n".encode() + MIN_PAYLOAD),
]


@pytest.mark.parametrize(("name", "data"), _NEGATIVE_CASES, ids=[c[0] for c in _NEGATIVE_CASES])
def test_unsupported_and_malformed_age_like_files_are_not_detected(tmp_path, name, data):
    _write(tmp_path, name, data)

    findings = scan_crypto_inventory_findings(str(tmp_path))

    assert [f for f in findings if f.rule_id == "encrypted_file:age"] == []


def test_no_unsupported_case_becomes_a_scanner_error_or_a_partial_finding(tmp_path):
    for name, data in _NEGATIVE_CASES:
        _write(tmp_path, name, data)

    # One scan over every malformed/unsupported shape at once: no exception, no
    # scanner error, and no age finding or lower-confidence stand-in for one.
    findings = scan_crypto_inventory_findings(str(tmp_path))

    assert [f for f in findings if f.rule_id == "encrypted_file:age"] == []
    assert [f for f in findings if "age" in (f.asset_type or "").lower()] == []


# --- 29-38. Other formats are not classified as age (and age wins on content) -


def test_age_content_beats_a_misleading_crypto_extension(tmp_path):
    # age (priority 25) runs before the extension-based PKCS#12/DER branches and
    # is terminal, so valid age content is classified from its content rather
    # than reported as a malformed container.
    for name in ("misleading.p12", "misleading.pfx", "misleading.der", "misleading.pem",
                 "misleading.gpg", "misleading.cer", "misleading.crt", "misleading.jks"):
        _write(tmp_path, name, _age_file())

    findings = scan_crypto_inventory_findings(str(tmp_path))

    assert len(findings) == 8
    assert {f.asset_type for f in findings} == {"Encrypted File"}
    assert {f.rule_id for f in findings} == {"encrypted_file:age"}


def test_other_encrypted_and_structured_formats_are_not_classified_as_age(tmp_path):
    # OpenSSL Salted__, binary and armored OpenPGP, and the committed
    # PEM/DER/PKCS#12/JKS fixtures: each must keep its own classification, and
    # none of them may acquire an age rule ID.
    _write(tmp_path, "openssl.enc", b"Salted__" + b"\x00" * 24)
    skesk = bytes([0x8C, 0x0D, 0x04, 0x09, 0x03, 0x08]) + bytes(range(0x10, 0x18)) + bytes([0x60])
    encrypted_data_packet = bytes([0xD2, 0x11, 0x01]) + bytes(range(0x40, 0x50))
    _write(tmp_path, "binary.gpg", skesk + encrypted_data_packet)
    body = skesk + encrypted_data_packet
    encoded = base64.b64encode(body).decode("ascii")
    checksum = base64.b64encode(
        crypto_inventory._openpgp_crc24(body).to_bytes(3, "big")
    ).decode("ascii")
    _write(
        tmp_path,
        "armored.asc",
        f"-----BEGIN PGP MESSAGE-----\n\n{encoded}\n={checksum}\n"
        "-----END PGP MESSAGE-----\n".encode("ascii"),
    )
    for fixture in ("rsa_cert.pem", "valid_key.pem", "bundle.p12", "rsa_cert.der", "sample.jks"):
        _write(tmp_path, fixture, (FIXTURE_DIR / fixture).read_bytes())

    findings = scan_crypto_inventory_findings(str(tmp_path))
    by_name = {}
    for finding in findings:
        by_name.setdefault(os.path.basename(finding.location), []).append(finding)

    assert [f.rule_id for f in findings if f.rule_id == "encrypted_file:age"] == []
    assert by_name["openssl.enc"][0].rule_id == "encrypted_file:openssl"
    assert by_name["binary.gpg"][0].rule_id == "encrypted_file:openpgp"
    assert by_name["armored.asc"][0].rule_id == "encrypted_file:openpgp"
    assert {f.asset_type for f in by_name["rsa_cert.pem"]} == {"PEM Certificate"}
    assert {f.asset_type for f in by_name["valid_key.pem"]} == {"PEM Private Key"}
    assert {f.asset_type for f in by_name["rsa_cert.der"]} == {"DER Certificate"}
    assert {f.asset_type for f in by_name["sample.jks"]} == {"Java Keystore"}
    assert by_name["bundle.p12"]


def test_gocryptfs_root_markers_do_not_create_age_findings(tmp_path):
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


# --- 39-50. Framework, ownership, terminal behavior, accounting -------------


def _age_detector():
    matches = [d for d in CRYPTO_DETECTORS if d.detector_id == "encrypted_file:age"]
    assert len(matches) == 1
    return matches[0]


def test_registry_includes_the_age_detector_exactly_once_with_a_unique_id():
    ids = [d.detector_id for d in CRYPTO_DETECTORS]
    assert ids.count("encrypted_file:age") == 1
    assert len(ids) == len(set(ids))


def test_age_detector_declares_the_required_contract():
    detector = _age_detector()
    assert detector.priority == 25
    assert detector.scope == "file"
    assert detector.terminal is True
    assert detector.rule_id == "encrypted_file:age"
    assert detector.confidence == "High"
    assert detector.evidence == "Observed age encrypted file."
    # No age-specific technical metadata in HG-035.
    assert detector.metadata_keys == frozenset()


def test_age_priority_is_unique_and_sits_between_openpgp_and_gocryptfs():
    priorities = {d.detector_id: d.priority for d in CRYPTO_DETECTORS}
    assert list(priorities.values()) == sorted(priorities.values())
    assert len(set(priorities.values())) == len(priorities)
    assert priorities["encrypted_file:openssl"] < priorities["encrypted_file:age"]
    assert priorities["encrypted_file:openpgp"] < priorities["encrypted_file:age"]
    for later in (
        "encrypted_filesystem:gocryptfs",
        "java_keystore:jks_magic",
        "pkcs12:container",
        "certificate:der",
        "certificate:pem",
        "private_key:pem",
        "public_key:ssh",
    ):
        assert priorities["encrypted_file:age"] < priorities[later]


def test_registry_order_remains_deterministic_under_perturbed_input():
    from scanner.crypto_detectors import build_registry

    assert build_registry(list(reversed(CRYPTO_DETECTORS))) == CRYPTO_DETECTORS
    rotated = list(CRYPTO_DETECTORS[3:]) + list(CRYPTO_DETECTORS[:3])
    assert build_registry(rotated) == CRYPTO_DETECTORS


def test_an_age_match_is_terminal_for_that_file(tmp_path):
    from scanner.crypto_detectors import DetectionResult, FileDetector, build_registry

    later_detector_ran = []

    def _record(context):
        later_detector_ran.append(context.location)
        return DetectionResult.no_match()

    registry = build_registry(
        [
            *CRYPTO_DETECTORS,
            FileDetector(
                detector_id="test:after-age",
                priority=26,
                candidate=lambda context: True,
                detect=_record,
                evidence="",
                confidence="Low",
            ),
        ]
    )
    valid = _write(tmp_path, "valid.age", _age_file())
    malformed = _write(tmp_path, "malformed.age", _age_file(mac="short"))

    assert [f.rule_id for f in crypto_inventory._scan_file(valid, registry)] == [
        "encrypted_file:age"
    ]
    # Terminal: nothing after priority 25 saw the matched file...
    assert later_detector_ran == []
    # ...but a non-match does not stop later detectors.
    crypto_inventory._scan_file(malformed, registry)
    assert later_detector_ran == [str(malformed)]


def test_one_valid_file_emits_exactly_one_age_finding(tmp_path):
    _write(tmp_path, "secret.age", _age_file())

    df = scan_crypto_inventory(str(tmp_path))

    assert list(df["Rule ID"]) == ["encrypted_file:age"]
    assert len(df) == 1


def test_crypto_scan_emits_the_finding_and_filesystem_scan_does_not(tmp_path):
    _write(tmp_path, "secret.age", _age_file())

    crypto_findings = scan_crypto_inventory_findings(str(tmp_path))
    filesystem_findings = scan_filesystem_findings(str(tmp_path))

    assert [f.rule_id for f in crypto_findings] == ["encrypted_file:age"]
    assert [f for f in filesystem_findings if f.rule_id == "encrypted_file:age"] == []
    assert [f for f in filesystem_findings if f.asset_type == "Encrypted File"] == []


def test_type_all_emits_exactly_one_age_finding(tmp_path, capsys):
    _write(tmp_path, "secret.age", _age_file())

    assert harvestguard.main(["scan", str(tmp_path), "--type", "all", "--json", "--quiet"]) == 0
    payload = json.loads(capsys.readouterr().out)

    age_records = [r for r in payload if r["rule_id"] == "encrypted_file:age"]
    assert len(age_records) == 1
    assert age_records[0]["source_type"] == "crypto_inventory"
    assert age_records[0]["asset_type"] == "Encrypted File"
    # Exactly one `Encrypted File` record for that location, from crypto
    # inventory. The filesystem scanner's own, broader `File-level (age)`
    # signature record (present since before HG-035) is separate evidence with
    # its own asset type and rule ID, and HG-035 changes neither it nor the
    # cross-scanner dedup pairings.
    encrypted_file_records = [r for r in payload if r["asset_type"] == "Encrypted File"]
    assert len(encrypted_file_records) == 1


def test_no_cross_scanner_dedup_path_is_added_for_age():
    # HG-035 adds no dedup pairing: `encrypted_file:age` is absent from the
    # mapping, and the OpenSSL/OpenPGP pairings are untouched.
    assert harvestguard.CRYPTO_OWNED_ENCRYPTED_FILE_RULE_IDS == {
        "encrypted_file:openssl": "file_signature:file_level_openssl",
        "encrypted_file:openpgp": "file_signature:file_level_pgp_gpg",
    }


def test_one_age_file_counts_once_in_crypto_files_inspected(tmp_path, capsys):
    _write(tmp_path, "secret.age", _age_file())
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
    # Files scanned, and there is no age-specific count or bucket.
    assert "Files scanned: 0" in output
    for age_specific in ("age files", "age encrypted", "encrypted_file:age"):
        assert age_specific not in output.lower()


# --- 51-64. Finding identity, output shape, and privacy ---------------------


def test_rule_id_survives_scanner_dataframe_adapter_and_normalized_finding(tmp_path):
    _write(tmp_path, "secret.age", _age_file())

    df = scan_crypto_inventory(str(tmp_path))
    findings = normalize_crypto_inventory_df(df)

    assert df.loc[0, "Rule ID"] == "encrypted_file:age"
    assert [f.rule_id for f in findings] == ["encrypted_file:age"]
    assert findings[0].provenance.rule_id == "encrypted_file:age"


def test_finding_id_is_deterministic_across_repeated_scans(tmp_path):
    _write(tmp_path, "secret.age", _age_file())

    first = scan_crypto_inventory_findings(str(tmp_path))
    second = scan_crypto_inventory_findings(str(tmp_path))

    assert [f.finding_id for f in first] == [f.finding_id for f in second]


def test_json_remains_a_bare_array_and_markdown_remains_evidence_only(tmp_path, capsys):
    _write(tmp_path, "secret.age", _age_file())

    assert harvestguard.main(
        ["scan", str(tmp_path), "--type", "crypto", "--json", "--quiet"]
    ) == 0
    payload = json.loads(capsys.readouterr().out)
    assert isinstance(payload, list)
    assert len(payload) == 1
    assert payload[0]["rule_id"] == "encrypted_file:age"
    assert payload[0]["evidence"] == "Observed age encrypted file."
    # No new NormalizedFinding field, and no relationship record anywhere.
    assert not [key for key in payload[0] if "relationship" in key.lower()]

    assert harvestguard.main(
        ["scan", str(tmp_path), "--type", "crypto", "--markdown", "--quiet"]
    ) == 0
    report = capsys.readouterr().out
    assert "Encrypted File" in report
    assert "Observed age encrypted file." in report
    assert "| Crypto Files Inspected | 1 |" in report
    # The report's own standing disclaimers legitimately name risk, remediation,
    # and quantum readiness in order to deny them, so this checks the evidence
    # HG-035 contributes rather than the whole document: the age finding makes no
    # assessment claim, and no relationship record appears anywhere.
    assert "relationship" not in report.lower()
    for forbidden in ("risk", "remediat", "quantum", "hndl", "compliance", "strength"):
        assert forbidden not in payload[0]["evidence"].lower()


def test_cli_summary_structure_is_unchanged_and_gains_no_bucket(tmp_path, capsys):
    _write(tmp_path, "secret.age", _age_file())

    assert harvestguard.main(
        ["scan", str(tmp_path), "--type", "crypto", "--summary", "--quiet"]
    ) == 0
    with_age = capsys.readouterr().out

    (tmp_path / "secret.age").unlink()
    (tmp_path / "plain.txt").write_text("harvestguard fixture text")
    assert harvestguard.main(
        ["scan", str(tmp_path), "--type", "crypto", "--summary", "--quiet"]
    ) == 0
    without_age = capsys.readouterr().out

    def _labels(output: str) -> list[str]:
        return [line.split(":")[0] for line in output.splitlines() if ":" in line]

    assert _labels(with_age) == _labels(without_age)


def test_safe_metadata_carries_no_age_specific_values(tmp_path):
    _write(tmp_path, "secret.age", _age_file())

    finding = scan_crypto_inventory_findings(str(tmp_path))[0]

    # The adapter's existing keys remain present with None values; nothing
    # age-specific is added, and SAFE_METADATA_KEYS is unchanged.
    assert all(value is None for value in finding.technical_metadata.values())
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


def test_no_recipient_stanza_data_or_encrypted_payload_reaches_json_or_markdown(
    tmp_path, capsys
):
    payload_marker = os.urandom(24)
    argument_marker = _b64(os.urandom(24))
    body_marker = _b64(os.urandom(24))
    mac_marker = _b64(bytes(range(0xA0, 0xC0)))
    _write(
        tmp_path,
        "secret.age",
        _age_file(
            stanzas=_stanza(arguments=f"X25519 {argument_marker}", body=body_marker),
            mac=mac_marker,
            payload=payload_marker + bytes(8),
        ),
    )

    harvestguard.main(["scan", str(tmp_path), "--type", "crypto", "--json", "--quiet"])
    json_output = capsys.readouterr().out
    harvestguard.main(["scan", str(tmp_path), "--type", "crypto", "--markdown", "--quiet"])
    markdown_output = capsys.readouterr().out

    for output in (json_output, markdown_output):
        for marker in (argument_marker, body_marker, mac_marker):
            assert marker not in output
        assert payload_marker.hex() not in output
        assert payload_marker not in output.encode("utf-8", errors="ignore")
        # Nor the recipient type, the stanza/MAC line shapes, or the version line.
        assert "X25519" not in output
        assert "age-encryption.org" not in output
        assert "-> " not in output


def test_a_detector_exception_leaks_no_parser_payload(tmp_path, monkeypatch):
    from scanner.errors import LocalScanError

    marker = "SECRET-AGE-PAYLOAD-0xdeadbeef"

    def boom(data):
        raise ValueError(marker)

    monkeypatch.setattr(crypto_inventory, "_looks_like_age_v1_encrypted_file", boom)
    _write(tmp_path, "secret.age", _age_file())

    with pytest.raises(LocalScanError) as excinfo:
        scan_crypto_inventory_findings(str(tmp_path))

    message = str(excinfo.value)
    assert "encrypted_file:age" in message
    assert "ValueError" in message
    assert marker not in message


# --- 65-76. Regression boundaries ------------------------------------------


def test_age_introduces_no_new_asset_type_or_rule_id(tmp_path):
    _write(tmp_path, "secret.age", _age_file())

    findings = scan_crypto_inventory_findings(str(tmp_path))

    assert {f.asset_type for f in findings} == {"Encrypted File"}
    age_rule_ids = {
        d.rule_id for d in CRYPTO_DETECTORS if d.rule_id and "age" in d.rule_id
    }
    assert age_rule_ids == {"encrypted_file:age"}


def test_no_new_dependency_is_declared_for_age():
    for manifest in ("requirements.txt", "requirements-dev.txt", "pyproject.toml"):
        text = (REPO_ROOT / manifest).read_text(encoding="utf-8").lower()
        for library in ("pyage", "age-encryption", "pyrage"):
            assert library not in text


def test_detection_invokes_no_external_process(tmp_path, monkeypatch):
    source = (REPO_ROOT / "scanner" / "crypto_inventory.py").read_text(encoding="utf-8")
    assert "subprocess" not in source

    def _forbidden(*args, **kwargs):  # pragma: no cover - must never run
        raise AssertionError("the age detector must not invoke an external process")

    for name in ("run", "Popen", "check_output", "call"):
        monkeypatch.setattr(subprocess, name, _forbidden)
    monkeypatch.setattr(os, "system", _forbidden)
    _write(tmp_path, "secret.age", _age_file())

    assert [f.rule_id for f in scan_crypto_inventory_findings(str(tmp_path))] == [
        "encrypted_file:age"
    ]


def test_the_age_file_is_read_once_through_the_shared_context(tmp_path, monkeypatch):
    target = _write(tmp_path, "secret.age", _age_file())
    reads: list[str] = []
    real_read_bytes = Path.read_bytes

    def counting_read_bytes(self):
        reads.append(str(self))
        return real_read_bytes(self)

    monkeypatch.setattr(Path, "read_bytes", counting_read_bytes)
    findings = scan_crypto_inventory_findings(str(tmp_path))

    assert [f.rule_id for f in findings] == ["encrypted_file:age"]
    assert reads == [str(target)]


def test_no_relationship_record_is_created_by_age_detection():
    source = (REPO_ROOT / "scanner" / "crypto_inventory.py").read_text(encoding="utf-8")
    assert "crypto_relationships" not in source
    assert "relationship" not in source.lower()
