"""Regression coverage for HG-031 (GitHub issue #71): OpenPGP/GPG
encrypted-file detection in the crypto-inventory scanner, deduplication
against the filesystem scanner's existing PGP signature evidence under
`--type all`, and the evidence-only finding contract.

Complements tests/test_openssl_encrypted_file_detection.py (HG-030, the same
shape of coverage for the OpenSSL `Salted__` signature),
tests/test_crypto_inventory.py (PEM/DER/PKCS#12/JKS/SSH coverage, unmodified),
and tests/test_detection_characterization.py (the HG-009 narrowing of the
filesystem scanner's PGP armor prefix, which this must not revert).

Fixtures are synthesized in-process from the packet layouts RFC 4880 fixes, so
no binary fixture is committed and no test requires GPG. The two tests that do
exercise real `gpg` output skip when gpg is unavailable or writes a shape
HG-031 documents as unsupported.
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

import harvestguard
from finding_adapters import normalize_crypto_inventory_df
from harvestguard import _deduplicate_encrypted_file_findings
from scanner.crypto_inventory import (
    _openpgp_crc24,
    scan_crypto_inventory,
    scan_crypto_inventory_findings,
)
from scanner.filesystem import scan_filesystem_findings

# --- Synthetic fixtures ------------------------------------------------------
#
# The field-observed shape from the issue, byte for byte as GnuPG writes it and
# as verified against real `gpg --symmetric` output:
#   8c    old-format packet header, tag 3 (SKESK), 1-octet length
#   0d    body length 13
#   04    packet version 4
#   09    symmetric algorithm 9 (AES-256)
#   03    string-to-key specifier 3 (iterated and salted)
#   08    hash algorithm 8 (SHA-256)
#   + 8-octet salt + 1-octet coded iteration count
SKESK_HEADER = bytes([0x8C, 0x0D, 0x04, 0x09, 0x03, 0x08])
_SALT = bytes(range(0x10, 0x18))
_ITERATION_COUNT = bytes([0x60])
# A public-key encrypted session key packet (tag 1, version 3) as
# `gpg --encrypt` writes it: header, 1-octet length declaring a 94-octet body,
# version 3, 8-octet key ID, then public-key algorithm 18 (ECDH).
_PKESK_DECLARED_BODY_LENGTH = 0x5E
PKESK_HEADER = bytes([0x84, _PKESK_DECLARED_BODY_LENGTH, 0x03]) + bytes(range(0x20, 0x28)) + bytes(
    [0x12]
)
# The ten metadata octets the scanner reads out of that body; everything after
# them is the opaque encrypted session key.
_PKESK_METADATA_OCTETS = 10

# A minimal, complete Sym. Encrypted Integrity Protected Data packet (RFC 4880
# section 5.13): new-format header for tag 18, a 1-octet length declaring 17
# body octets, then a version-1 octet and 16 opaque "ciphertext" octets. This
# is the real, modern shape GnuPG writes immediately after a session-key
# packet for both `gpg --symmetric` and `gpg --encrypt`, and is the supported
# "following encrypted-data packet" HG-031 correction cycle 2's Blocker 1
# requires -- every existing fixture that used to end with unstructured filler
# bytes now ends with this instead, so the fixture is a genuine, complete
# encrypted message rather than a session-key packet with padding after it.
ENCRYPTED_DATA_PACKET = bytes([0xD2, 0x11, 0x01]) + bytes(range(0x40, 0x50))
# The legacy, MDC-less counterpart (RFC 4880 section 5.7, tag 9): opaque from
# its first body octet, no version field. Used where a test specifically wants
# the *other* supported following-packet shape.
LEGACY_ENCRYPTED_DATA_PACKET = bytes([0xC9, 0x10]) + bytes(range(0x50, 0x60))


def _symmetric_encrypted_bytes(payload: bytes = ENCRYPTED_DATA_PACKET) -> bytes:
    """The field-observed `gpg --symmetric` file shape: a session-key packet
    immediately followed by a complete, supported encrypted-data packet.

    The session-key packet declares a 13-octet body and carries exactly that
    (version, symmetric algorithm, specifier type, hash algorithm, salt,
    iteration count); ``payload`` is the encrypted-data packet that follows
    it -- a real one (see ``ENCRYPTED_DATA_PACKET``) by default, since a
    session-key packet alone is not a supported encrypted message (Blocker 1).
    """
    return SKESK_HEADER + _SALT + _ITERATION_COUNT + payload


def _public_key_encrypted_bytes(following: bytes = ENCRYPTED_DATA_PACKET) -> bytes:
    """A `gpg --encrypt` file shape whose session-key packet body is as long
    as its packet header declares -- as a real one is; a declared length that
    runs past the end of the file is a malformed packet, not evidence -- and
    which is followed by a complete, supported encrypted-data packet
    (``following``), since a session-key packet alone is not a supported
    encrypted message (Blocker 1)."""
    session_key = b"\x00" * (_PKESK_DECLARED_BODY_LENGTH - _PKESK_METADATA_OCTETS)
    return PKESK_HEADER + session_key + following


def _armor_checksum_line(decoded: bytes) -> str:
    """The real, correct radix-64 checksum line OpenPGP armor requires for
    ``decoded`` -- HG-031 correction cycle 2's Blocker 2 made the scanner
    actually validate this against the CRC-24 of the decoded body, so a fixed
    placeholder no longer produces armor the scanner accepts."""
    crc_bytes = _openpgp_crc24(decoded).to_bytes(3, "big")
    return base64.b64encode(crc_bytes).decode("ascii")


def _armored(body: bytes, label: str = "PGP MESSAGE") -> bytes:
    """Complete ASCII armor around ``body``, laid out as RFC 4880 section 6.2
    requires: header line, blank line, radix-64 body, a checksum line that is
    the real CRC-24 of ``body`` (not a placeholder -- see
    ``_armor_checksum_line``), and a tail line matching ``label`` exactly."""
    encoded = base64.b64encode(body).decode("ascii")
    lines = [encoded[i : i + 64] for i in range(0, len(encoded), 64)]
    checksum = _armor_checksum_line(body)
    return (
        f"-----BEGIN {label}-----\n\n"
        + "\n".join(lines)
        + f"\n={checksum}\n"
        + f"-----END {label}-----\n"
    ).encode("ascii")


# --- 1. Field-observed symmetric shape / exact finding contract -------------


def test_gpg_symmetric_file_produces_encrypted_file_finding_with_exact_contract(tmp_path):
    (tmp_path / "secret.gpg").write_bytes(_symmetric_encrypted_bytes())

    findings = scan_crypto_inventory_findings(str(tmp_path))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.source_type == "crypto_inventory"
    assert finding.asset_type == "Encrypted File"
    assert finding.rule_id == "encrypted_file:openpgp"
    assert finding.confidence == "High"
    # Evidence states the directly observed packet structure and nothing else.
    assert "symmetric-key encrypted session key packet" in finding.evidence
    assert "packet tag 3, version 4" in finding.evidence
    assert "AES-256" in finding.evidence
    assert "iterated and salted" in finding.evidence
    assert finding.technical_metadata["Algorithm"] == "AES-256"
    # Evidence-only: no decryption, credential, strength, or business claim.
    for forbidden in (
        "decrypt",
        "password",
        "passphrase",
        "strong",
        "weak",
        "risk",
        "remediat",
        "quantum",
        "complete",
    ):
        assert forbidden not in finding.evidence.lower()


def test_symmetric_detection_is_independent_of_filename_and_extension(tmp_path):
    for name in ("secret.gpg", "secret.pgp", "secret.bin", "secret", "notes.txt"):
        (tmp_path / name).write_bytes(_symmetric_encrypted_bytes())

    findings = scan_crypto_inventory_findings(str(tmp_path))

    assert len(findings) == 5
    assert all(f.rule_id == "encrypted_file:openpgp" for f in findings)


def test_openpgp_content_beats_a_misleading_crypto_extension(tmp_path):
    # As with the HG-030 Salted__ check, content is evaluated before any
    # extension-based branch, so this is not reported as a malformed PKCS#12.
    (tmp_path / "misleading.p12").write_bytes(_symmetric_encrypted_bytes())

    findings = scan_crypto_inventory_findings(str(tmp_path))

    assert len(findings) == 1
    assert findings[0].asset_type == "Encrypted File"
    assert findings[0].rule_id == "encrypted_file:openpgp"


def test_public_key_encrypted_file_is_detected(tmp_path):
    (tmp_path / "recipient.gpg").write_bytes(_public_key_encrypted_bytes())

    findings = scan_crypto_inventory_findings(str(tmp_path))

    assert len(findings) == 1
    assert findings[0].rule_id == "encrypted_file:openpgp"
    assert "public-key encrypted session key packet" in findings[0].evidence
    assert "packet tag 1, version 3" in findings[0].evidence
    assert findings[0].technical_metadata["Algorithm"] == "ECDH"


def test_public_key_encrypted_finding_does_not_name_the_recipient_key_id(tmp_path):
    (tmp_path / "recipient.gpg").write_bytes(_public_key_encrypted_bytes())

    finding = scan_crypto_inventory_findings(str(tmp_path))[0]

    key_id = bytes(range(0x20, 0x28)).hex()
    assert key_id not in finding.evidence.lower()
    assert key_id not in json.dumps(finding.to_dict()).lower()


def test_two_octet_length_public_key_packet_is_detected(tmp_path):
    # 0x85 selects a 2-octet length, the header prefix scanner/filesystem.py
    # already recognizes; the body offset shifts by one and must still parse.
    # The declared body is 0x010C = 268 octets, the size of an RSA-2048
    # encrypted session key packet, and the fixture carries all of them.
    packet = bytes([0x85, 0x01, 0x0C, 0x03]) + bytes(range(0x30, 0x38)) + bytes([0x01])
    session_key = b"\x00" * (268 - _PKESK_METADATA_OCTETS)
    (tmp_path / "rsa.gpg").write_bytes(packet + session_key + ENCRYPTED_DATA_PACKET)

    findings = scan_crypto_inventory_findings(str(tmp_path))

    assert len(findings) == 1
    assert findings[0].rule_id == "encrypted_file:openpgp"
    assert findings[0].technical_metadata["Algorithm"] == "RSA"


def test_new_format_packet_header_is_detected(tmp_path):
    # 0xc3 is the new-format header for tag 3; the following octet is a
    # 1-octet body length.
    packet = bytes([0xC3, 0x0D, 0x04, 0x09, 0x03, 0x08]) + _SALT + _ITERATION_COUNT
    (tmp_path / "new-format.gpg").write_bytes(packet + ENCRYPTED_DATA_PACKET)

    findings = scan_crypto_inventory_findings(str(tmp_path))

    assert len(findings) == 1
    assert findings[0].rule_id == "encrypted_file:openpgp"


# --- 2. ASCII-armored encrypted messages ------------------------------------


def test_armored_symmetric_encrypted_message_is_detected(tmp_path):
    (tmp_path / "secret.asc").write_bytes(_armored(_symmetric_encrypted_bytes()))

    findings = scan_crypto_inventory_findings(str(tmp_path))

    assert len(findings) == 1
    assert findings[0].rule_id == "encrypted_file:openpgp"
    assert findings[0].asset_type == "Encrypted File"
    assert findings[0].confidence == "High"
    assert "ASCII-armored OpenPGP MESSAGE" in findings[0].evidence
    assert "symmetric-key encrypted session key packet" in findings[0].evidence


def test_armored_public_key_encrypted_message_is_detected(tmp_path):
    (tmp_path / "secret.asc").write_bytes(_armored(_public_key_encrypted_bytes()))

    findings = scan_crypto_inventory_findings(str(tmp_path))

    assert len(findings) == 1
    assert findings[0].rule_id == "encrypted_file:openpgp"
    assert "public-key encrypted session key packet" in findings[0].evidence


def test_armored_message_with_armor_headers_is_detected(tmp_path):
    armored = _armored(_symmetric_encrypted_bytes())
    with_headers = armored.replace(
        b"-----BEGIN PGP MESSAGE-----\n\n",
        b"-----BEGIN PGP MESSAGE-----\nVersion: GnuPG v2\nComment: test\n\n",
    )
    (tmp_path / "secret.asc").write_bytes(with_headers)

    findings = scan_crypto_inventory_findings(str(tmp_path))

    assert len(findings) == 1
    assert findings[0].rule_id == "encrypted_file:openpgp"


# --- 3. Negative cases -------------------------------------------------------


def test_armored_signed_only_message_is_not_classified_as_encrypted(tmp_path):
    # `gpg --armor --sign` writes MESSAGE armor whose first packet is
    # compressed data (tag 8, old-format indeterminate length), not a session
    # key packet. This is the residual false positive the filesystem scanner
    # documents and crypto inventory must not repeat.
    signed = bytes([0xA3, 0x01, 0x01]) + b"\x00" * 48
    (tmp_path / "signed.asc").write_bytes(_armored(signed))

    assert scan_crypto_inventory_findings(str(tmp_path)) == []


def test_clearsigned_message_is_not_classified_as_encrypted(tmp_path):
    (tmp_path / "clearsigned.asc").write_bytes(
        b"-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\n"
        b"harvestguard fixture cleartext\n"
        b"-----BEGIN PGP SIGNATURE-----\n\niQEzBAABCgAd\n=abcd\n"
        b"-----END PGP SIGNATURE-----\n"
    )

    assert scan_crypto_inventory_findings(str(tmp_path)) == []


def test_detached_signature_is_not_classified_as_encrypted(tmp_path):
    signature = bytes([0x89, 0x01, 0x33]) + b"\x00" * 48
    (tmp_path / "detached.asc").write_bytes(_armored(signature, "PGP SIGNATURE"))

    assert scan_crypto_inventory_findings(str(tmp_path)) == []


def test_public_key_block_is_not_classified_as_encrypted(tmp_path):
    public_key_packet = bytes([0x98, 0x33, 0x04]) + b"\x00" * 48
    (tmp_path / "pub.asc").write_bytes(_armored(public_key_packet, "PGP PUBLIC KEY BLOCK"))

    assert scan_crypto_inventory_findings(str(tmp_path)) == []


def test_private_key_block_is_not_classified_as_encrypted(tmp_path):
    secret_key_packet = bytes([0x94, 0x58, 0x04]) + b"\x00" * 48
    (tmp_path / "sec.asc").write_bytes(_armored(secret_key_packet, "PGP PRIVATE KEY BLOCK"))

    assert scan_crypto_inventory_findings(str(tmp_path)) == []


def test_key_packets_inside_message_armor_are_not_classified_as_encrypted(tmp_path):
    # Belt and braces: the armor label alone is not what rejects a key block --
    # the leading packet tag is checked too.
    (tmp_path / "mislabeled.asc").write_bytes(
        _armored(bytes([0x98, 0x33, 0x04]) + b"\x00" * 48)
    )

    assert scan_crypto_inventory_findings(str(tmp_path)) == []


@pytest.mark.parametrize(
    ("name", "packet"),
    [
        # Version 5/6 SKESK: a real OpenPGP shape HG-031 documents as
        # unsupported rather than guessing at its different body layout.
        ("version6.gpg", bytes([0x8C, 0x0D, 0x06, 0x09, 0x03, 0x08])),
        # Symmetric algorithm 0 is "plaintext or unencrypted data".
        ("plaintext-algorithm.gpg", bytes([0x8C, 0x0D, 0x04, 0x00, 0x03, 0x08])),
        # Undefined symmetric algorithm identifier.
        ("unknown-algorithm.gpg", bytes([0x8C, 0x0D, 0x04, 0x63, 0x03, 0x08])),
        # Undefined string-to-key specifier type.
        ("unknown-s2k.gpg", bytes([0x8C, 0x0D, 0x04, 0x09, 0x63, 0x08])),
        # Undefined hash algorithm identifier.
        ("unknown-hash.gpg", bytes([0x8C, 0x0D, 0x04, 0x09, 0x03, 0x63])),
        # PKESK with a version other than 3.
        ("pkesk-version.gpg", bytes([0x84, 0x5E, 0x09]) + bytes(range(0x20, 0x28)) + b"\x12"),
        # PKESK naming a sign-only public-key algorithm (17 = DSA).
        ("pkesk-sign-only.gpg", bytes([0x84, 0x5E, 0x03]) + bytes(range(0x20, 0x28)) + b"\x11"),
        # A packet tag that is neither 1 nor 3 (tag 18, encrypted data, with no
        # session key packet in front of it).
        ("bare-seipd.gpg", bytes([0xD2, 0x30, 0x01]) + b"\x00" * 32),
        # Bit 7 clear: not an OpenPGP packet header at all.
        ("not-a-packet.bin", bytes([0x0C, 0x0D, 0x04, 0x09, 0x03, 0x08])),
        # Old-format indeterminate length (type 3): body offset is not
        # determinate, so the shape is not validated.
        ("indeterminate.gpg", bytes([0x8F, 0x04, 0x09, 0x03, 0x08])),
        # New-format partial length (224..254).
        ("partial-length.gpg", bytes([0xC3, 0xE1, 0x04, 0x09, 0x03, 0x08])),
    ],
)
def test_near_matches_are_not_detected(tmp_path, name, packet):
    (tmp_path / name).write_bytes(packet + b"\x00" * 32)

    assert scan_crypto_inventory_findings(str(tmp_path)) == []


@pytest.mark.parametrize(
    ("name", "packet"),
    [
        # A packet's declared body length is what separates its own fields from
        # whatever follows it in the stream. Each of these declares a body too
        # short to hold the metadata the specification requires, and is followed
        # by bytes that would look like that metadata if the declared length
        # were ignored -- a malformed near match, not encrypted-file evidence.
        #
        # Tag 3 declaring a zero-length body, then `04 09 03 08`.
        (
            "zero-length-skesk.gpg",
            bytes([0x8C, 0x00, 0x04, 0x09, 0x03, 0x08]) + _SALT + _ITERATION_COUNT,
        ),
        # Tag 3 naming an iterated and salted specifier (13 body octets) while
        # declaring only the four metadata octets: the salt and coded iteration
        # count the specifier requires fall outside the declared body.
        (
            "short-declared-skesk.gpg",
            bytes([0x8C, 0x04, 0x04, 0x09, 0x03, 0x08]) + _SALT + _ITERATION_COUNT,
        ),
        # Tag 3 naming a salted specifier (12 body octets) while declaring 11:
        # one octet of the required salt falls outside the declared body.
        ("short-declared-salted-skesk.gpg", bytes([0x8C, 0x0B, 0x04, 0x09, 0x01, 0x08]) + _SALT),
        # Tag 1 declaring a one-octet body, then PKESK-like metadata.
        (
            "one-byte-pkesk.gpg",
            bytes([0x84, 0x01, 0x03]) + bytes(range(0x20, 0x28)) + bytes([0x12]),
        ),
        # Tag 1 declaring exactly the ten metadata octets: the encrypted session
        # key that must follow the algorithm octet is absent.
        (
            "no-session-key-pkesk.gpg",
            bytes([0x84, 0x0A, 0x03]) + bytes(range(0x20, 0x28)) + bytes([0x12]),
        ),
    ],
)
def test_inconsistent_declared_body_lengths_are_not_detected(tmp_path, name, packet):
    (tmp_path / name).write_bytes(packet + b"\x00" * 32)

    assert scan_crypto_inventory_findings(str(tmp_path)) == []


def test_truncated_declared_body_lengths_are_not_detected(tmp_path):
    # A body declared longer than the file that holds it is inconsistent,
    # whether the missing octets are metadata the scanner reads ...
    (tmp_path / "truncated-salt.gpg").write_bytes(SKESK_HEADER + _SALT[:4])
    # ... or payload it never reads: 0xc3 0xff selects a new-format 5-octet
    # length declaring 4096 body octets, of which 13 are present.
    (tmp_path / "over-declared-new-format.gpg").write_bytes(
        bytes([0xC3, 0xFF, 0x00, 0x00, 0x10, 0x00, 0x04, 0x09, 0x03, 0x08])
        + _SALT
        + _ITERATION_COUNT
    )
    # 0x8e selects an old-format 4-octet length, declaring 4096 the same way.
    (tmp_path / "over-declared-old-format.gpg").write_bytes(
        bytes([0x8E, 0x00, 0x00, 0x10, 0x00, 0x04, 0x09, 0x03, 0x08])
        + _SALT
        + _ITERATION_COUNT
    )
    # A file that ends inside its own multi-octet length header.
    (tmp_path / "truncated-length-header.gpg").write_bytes(bytes([0xC3, 0xFF, 0x00, 0x00]))
    (tmp_path / "truncated-old-length-header.gpg").write_bytes(bytes([0x8E, 0x00, 0x00]))
    (tmp_path / "truncated-two-octet-length.gpg").write_bytes(bytes([0xC3, 0xC1]))

    assert scan_crypto_inventory_findings(str(tmp_path)) == []


def test_packet_stream_ending_exactly_at_the_encrypted_data_packet_is_detected(tmp_path):
    # The complementary boundary: a file that ends exactly where the trailing
    # encrypted-data packet's declared body ends -- no extra padding after it
    # -- is a complete message, so the length check must not reject it.
    (tmp_path / "exact.gpg").write_bytes(_symmetric_encrypted_bytes())

    findings = scan_crypto_inventory_findings(str(tmp_path))

    assert len(findings) == 1
    assert findings[0].rule_id == "encrypted_file:openpgp"


def test_standalone_skesk_packet_is_not_detected(tmp_path):
    # HG-031 correction cycle 2, Blocker 1: a session-key packet with a
    # complete, consistent declared body -- but with *nothing* following it,
    # not even a truncated one -- is not a supported encrypted message.
    # Previously misclassified as `Encrypted File`; this is the exact false
    # positive the correction fixes.
    (tmp_path / "standalone-skesk.gpg").write_bytes(_symmetric_encrypted_bytes(b""))

    assert scan_crypto_inventory_findings(str(tmp_path)) == []


def test_standalone_pkesk_packet_is_not_detected(tmp_path):
    (tmp_path / "standalone-pkesk.gpg").write_bytes(_public_key_encrypted_bytes(b""))

    assert scan_crypto_inventory_findings(str(tmp_path)) == []


def test_standalone_skesk_armored_packet_is_not_detected(tmp_path):
    (tmp_path / "standalone-skesk.asc").write_bytes(_armored(_symmetric_encrypted_bytes(b"")))

    assert scan_crypto_inventory_findings(str(tmp_path)) == []


def test_standalone_pkesk_armored_packet_is_not_detected(tmp_path):
    (tmp_path / "standalone-pkesk.asc").write_bytes(
        _armored(_public_key_encrypted_bytes(b""))
    )

    assert scan_crypto_inventory_findings(str(tmp_path)) == []


def test_session_key_packet_followed_only_by_an_unrelated_packet_is_not_detected(tmp_path):
    # A signature packet (tag 2, old-format, 1-octet length) immediately
    # after a valid SKESK packet is not an encrypted-data packet.
    unrelated_packet = bytes([0x89, 0x08]) + bytes(range(8))
    (tmp_path / "skesk-then-signature.gpg").write_bytes(
        _symmetric_encrypted_bytes(unrelated_packet)
    )
    # Same, for PKESK.
    (tmp_path / "pkesk-then-signature.gpg").write_bytes(
        _public_key_encrypted_bytes(unrelated_packet)
    )
    # Armored counterparts.
    (tmp_path / "skesk-then-signature.asc").write_bytes(
        _armored(_symmetric_encrypted_bytes(unrelated_packet))
    )

    assert scan_crypto_inventory_findings(str(tmp_path)) == []


def test_truncated_encrypted_data_packet_after_valid_session_key_packet_is_not_detected(
    tmp_path,
):
    # The trailing packet's own header is well-formed and names a supported
    # tag (18), but its declared 16-octet body is not fully present -- a
    # truncated encrypted-data packet is not evidence of a complete one.
    truncated_seipd = bytes([0xD2, 0x10, 0x01, 0x02, 0x03])
    (tmp_path / "skesk-then-truncated.gpg").write_bytes(
        _symmetric_encrypted_bytes(truncated_seipd)
    )
    (tmp_path / "skesk-then-truncated.asc").write_bytes(
        _armored(_symmetric_encrypted_bytes(truncated_seipd))
    )

    assert scan_crypto_inventory_findings(str(tmp_path)) == []


def test_supported_skesk_followed_by_supported_encrypted_data_packet_is_detected(tmp_path):
    # Both required positive shapes for Blocker 1, binary and armored: the
    # modern SEIPD v1 packet (the default payload) and the legacy,
    # MDC-less SED packet (tag 9) real GnuPG output can also use.
    (tmp_path / "seipd.gpg").write_bytes(_symmetric_encrypted_bytes(ENCRYPTED_DATA_PACKET))
    (tmp_path / "sed.gpg").write_bytes(_symmetric_encrypted_bytes(LEGACY_ENCRYPTED_DATA_PACKET))
    (tmp_path / "seipd.asc").write_bytes(
        _armored(_symmetric_encrypted_bytes(ENCRYPTED_DATA_PACKET))
    )
    (tmp_path / "sed.asc").write_bytes(
        _armored(_symmetric_encrypted_bytes(LEGACY_ENCRYPTED_DATA_PACKET))
    )

    findings = scan_crypto_inventory_findings(str(tmp_path))

    assert len(findings) == 4
    assert all(f.rule_id == "encrypted_file:openpgp" for f in findings)


def test_supported_pkesk_followed_by_supported_encrypted_data_packet_is_detected(tmp_path):
    (tmp_path / "seipd.gpg").write_bytes(_public_key_encrypted_bytes(ENCRYPTED_DATA_PACKET))
    (tmp_path / "sed.gpg").write_bytes(_public_key_encrypted_bytes(LEGACY_ENCRYPTED_DATA_PACKET))
    (tmp_path / "seipd.asc").write_bytes(
        _armored(_public_key_encrypted_bytes(ENCRYPTED_DATA_PACKET))
    )
    (tmp_path / "sed.asc").write_bytes(
        _armored(_public_key_encrypted_bytes(LEGACY_ENCRYPTED_DATA_PACKET))
    )

    findings = scan_crypto_inventory_findings(str(tmp_path))

    assert len(findings) == 4
    assert all(f.rule_id == "encrypted_file:openpgp" for f in findings)


# A tag 18 (SEIPD) packet whose declared body is exactly one octet: only the
# version octet, with no encrypted-data payload after it. `SKESK + D2 01 01`
# is the exact shape Codex reproduced against `301328d` -- accepted as
# `encrypted_file:openpgp` despite carrying no encrypted data at all.
EMPTY_SEIPD_PACKET = bytes([0xD2, 0x01, 0x01])


def test_binary_skesk_with_empty_seipd_payload_is_not_detected(tmp_path):
    (tmp_path / "empty-seipd.gpg").write_bytes(
        _symmetric_encrypted_bytes(EMPTY_SEIPD_PACKET)
    )

    assert scan_crypto_inventory_findings(str(tmp_path)) == []


def test_binary_pkesk_with_empty_seipd_payload_is_not_detected(tmp_path):
    (tmp_path / "empty-seipd.gpg").write_bytes(
        _public_key_encrypted_bytes(EMPTY_SEIPD_PACKET)
    )

    assert scan_crypto_inventory_findings(str(tmp_path)) == []


def test_armored_skesk_with_empty_seipd_payload_is_not_detected(tmp_path):
    (tmp_path / "empty-seipd.asc").write_bytes(
        _armored(_symmetric_encrypted_bytes(EMPTY_SEIPD_PACKET))
    )

    assert scan_crypto_inventory_findings(str(tmp_path)) == []


def test_armored_pkesk_with_empty_seipd_payload_is_not_detected(tmp_path):
    (tmp_path / "empty-seipd.asc").write_bytes(
        _armored(_public_key_encrypted_bytes(EMPTY_SEIPD_PACKET))
    )

    assert scan_crypto_inventory_findings(str(tmp_path)) == []


def test_seipd_with_exactly_one_payload_byte_is_still_detected(tmp_path):
    # The boundary directly above the rejected case: two declared body octets
    # (version + one payload octet) is a complete encrypted-data packet.
    one_byte_payload_seipd = bytes([0xD2, 0x02, 0x01, 0xAA])
    (tmp_path / "one-byte.gpg").write_bytes(
        _symmetric_encrypted_bytes(one_byte_payload_seipd)
    )
    (tmp_path / "one-byte.asc").write_bytes(
        _armored(_public_key_encrypted_bytes(one_byte_payload_seipd))
    )

    findings = scan_crypto_inventory_findings(str(tmp_path))

    assert len(findings) == 2
    assert all(f.rule_id == "encrypted_file:openpgp" for f in findings)


def test_armored_packet_whose_whole_declared_body_is_present_is_detected(tmp_path):
    # The complete armor body is decoded, so a declared body far longer than the
    # packet header itself (94 octets here) is checked against all of it and,
    # being entirely present, is evidence.
    (tmp_path / "recipient.asc").write_bytes(_armored(_public_key_encrypted_bytes()))

    findings = scan_crypto_inventory_findings(str(tmp_path))

    assert len(findings) == 1
    assert findings[0].rule_id == "encrypted_file:openpgp"


@pytest.mark.parametrize(
    ("name", "packet"),
    [
        # The armored counterparts of the binary truncated/over-declared cases
        # above: the declared length is checked against the whole decoded body,
        # not a prefix of it, so armor is not a way around that check.
        #
        # Tag 1 declaring a 94-octet body while carrying 15.
        ("truncated-pkesk.asc", PKESK_HEADER + b"\x00" * 5),
        # Tag 3 declaring 13 body octets while carrying 4 of them.
        ("truncated-salt.asc", SKESK_HEADER + _SALT[:4]),
        # New-format 5-octet length declaring 4096 body octets, 13 present.
        (
            "over-declared-new-format.asc",
            bytes([0xC3, 0xFF, 0x00, 0x00, 0x10, 0x00, 0x04, 0x09, 0x03, 0x08])
            + _SALT
            + _ITERATION_COUNT,
        ),
        # Old-format 4-octet length declaring 4096 the same way.
        (
            "over-declared-old-format.asc",
            bytes([0x8E, 0x00, 0x00, 0x10, 0x00, 0x04, 0x09, 0x03, 0x08])
            + _SALT
            + _ITERATION_COUNT,
        ),
    ],
)
def test_armored_declared_body_longer_than_the_armor_carries_is_not_detected(
    tmp_path, name, packet
):
    (tmp_path / name).write_bytes(_armored(packet))

    assert scan_crypto_inventory_findings(str(tmp_path)) == []


def test_armored_body_truncated_mid_radix64_quantum_is_not_detected(tmp_path):
    # Only whole radix-64 quantums decode, so a body chopped mid-quantum yields
    # a shorter packet stream than the packet declares (12 octets against the
    # 15 a 13-octet body needs) and is rejected rather than padded out.
    encoded = base64.b64encode(_symmetric_encrypted_bytes(b"")).decode("ascii")
    (tmp_path / "truncated-armor.asc").write_bytes(
        f"-----BEGIN PGP MESSAGE-----\n\n{encoded[:16]}\n".encode("ascii")
    )

    assert scan_crypto_inventory_findings(str(tmp_path)) == []


def test_armor_header_line_with_trailing_content_is_not_read_as_armor(tmp_path):
    # RFC 4880 section 6.2 puts the armor header line alone on its own line.
    for name, header in (
        ("trailing-junk.asc", b"-----BEGIN PGP MESSAGE----- and then some"),
        ("multipart.asc", b"-----BEGIN PGP MESSAGE, PART 01-----"),
    ):
        (tmp_path / name).write_bytes(
            _armored(_symmetric_encrypted_bytes()).replace(
                b"-----BEGIN PGP MESSAGE-----", header, 1
            )
        )

    assert scan_crypto_inventory_findings(str(tmp_path)) == []


def test_armor_without_the_mandatory_blank_separator_is_not_read_as_armor(tmp_path):
    # The blank line between the armor headers and the radix-64 body is
    # mandatory, so a body that follows the header line (or an armor header)
    # directly is not a radix-64 body this scanner will decode.
    encoded = base64.b64encode(_symmetric_encrypted_bytes()).decode("ascii")
    (tmp_path / "no-separator.asc").write_bytes(
        f"-----BEGIN PGP MESSAGE-----\n{encoded}\n=abcd\n-----END PGP MESSAGE-----\n".encode(
            "ascii"
        )
    )
    (tmp_path / "no-separator-after-headers.asc").write_bytes(
        f"-----BEGIN PGP MESSAGE-----\nVersion: GnuPG v2\n{encoded}\n"
        "=abcd\n-----END PGP MESSAGE-----\n".encode("ascii")
    )

    assert scan_crypto_inventory_findings(str(tmp_path)) == []


def test_crlf_armored_message_is_detected(tmp_path):
    # The armor line endings may be CRLF; that is not trailing content.
    (tmp_path / "crlf.asc").write_bytes(
        _armored(_symmetric_encrypted_bytes()).replace(b"\n", b"\r\n")
    )

    findings = scan_crypto_inventory_findings(str(tmp_path))

    assert len(findings) == 1
    assert findings[0].rule_id == "encrypted_file:openpgp"


# --- 2b. Complete armor framing (HG-031 correction cycle 2, Blocker 2) -----
#
# Before this correction, armor parsing accepted any line starting with "="
# as "the checksum line" without validating it, and never checked for a tail
# line at all -- an incomplete or tampered armored message was still reported
# at High confidence. Every scenario below is a real, well-formed message
# (valid checksum computed by `_armor_checksum_line`, valid tail) with exactly
# one required element broken, so each failure is isolated to the property
# named in the test.


def _valid_armor_parts(body: bytes | None = None):
    """(encoded body lines joined, real checksum, tail line) for a genuine
    `_symmetric_encrypted_bytes()` message, so negative tests can build armor
    that is correct except for the one property under test."""
    if body is None:
        body = _symmetric_encrypted_bytes()
    encoded = base64.b64encode(body).decode("ascii")
    return encoded, _armor_checksum_line(body), "-----END PGP MESSAGE-----"


def test_armor_missing_checksum_line_is_not_detected(tmp_path):
    encoded, _checksum, end = _valid_armor_parts()
    (tmp_path / "missing-checksum.asc").write_bytes(
        f"-----BEGIN PGP MESSAGE-----\n\n{encoded}\n{end}\n".encode("ascii")
    )

    assert scan_crypto_inventory_findings(str(tmp_path)) == []


@pytest.mark.parametrize(
    "checksum",
    [
        "ab",  # too short
        "abcde",  # too long
        "ab!d",  # character outside the radix-64 alphabet
        "ab=d",  # "=" is not a radix-64 character
    ],
)
def test_armor_malformed_checksum_is_not_detected(tmp_path, checksum):
    encoded, _real_checksum, end = _valid_armor_parts()
    (tmp_path / "malformed-checksum.asc").write_bytes(
        f"-----BEGIN PGP MESSAGE-----\n\n{encoded}\n={checksum}\n{end}\n".encode("ascii")
    )

    assert scan_crypto_inventory_findings(str(tmp_path)) == []


def test_armor_checksum_mismatch_is_not_detected(tmp_path):
    body = _symmetric_encrypted_bytes()
    encoded = base64.b64encode(body).decode("ascii")
    real_checksum = _armor_checksum_line(body)
    # Flip the checksum's first character to something that cannot equal it
    # -- the radix-64 alphabet has no wraparound at 'A'/'a'/'0'.
    wrong_checksum = ("B" if real_checksum[0] != "B" else "C") + real_checksum[1:]
    (tmp_path / "checksum-mismatch.asc").write_bytes(
        f"-----BEGIN PGP MESSAGE-----\n\n{encoded}\n={wrong_checksum}\n"
        "-----END PGP MESSAGE-----\n".encode("ascii")
    )

    assert scan_crypto_inventory_findings(str(tmp_path)) == []


def test_armor_missing_end_line_is_not_detected(tmp_path):
    encoded, checksum, _end = _valid_armor_parts()
    (tmp_path / "missing-end.asc").write_bytes(
        f"-----BEGIN PGP MESSAGE-----\n\n{encoded}\n={checksum}\n".encode("ascii")
    )

    assert scan_crypto_inventory_findings(str(tmp_path)) == []


@pytest.mark.parametrize(
    "end_line",
    [
        "----END PGP MESSAGE-----",  # wrong dash count (begin side)
        "-----END PGP MESSAGE----",  # wrong dash count (end side)
        "-----END PGP MESSAGE-----extra",  # glued trailing content
        "-----end pgp message-----",  # wrong case
        "PGP MESSAGE-----END-----",  # scrambled
    ],
)
def test_armor_malformed_end_line_is_not_detected(tmp_path, end_line):
    encoded, checksum, _end = _valid_armor_parts()
    (tmp_path / "malformed-end.asc").write_bytes(
        f"-----BEGIN PGP MESSAGE-----\n\n{encoded}\n={checksum}\n{end_line}\n".encode("ascii")
    )

    assert scan_crypto_inventory_findings(str(tmp_path)) == []


def test_armor_mismatched_label_is_not_detected(tmp_path):
    encoded, checksum, _end = _valid_armor_parts()
    (tmp_path / "mismatched-label.asc").write_bytes(
        f"-----BEGIN PGP MESSAGE-----\n\n{encoded}\n={checksum}\n"
        "-----END PGP SIGNATURE-----\n".encode("ascii")
    )

    assert scan_crypto_inventory_findings(str(tmp_path)) == []


def test_armor_trailing_junk_on_end_line_is_not_detected(tmp_path):
    encoded, checksum, _end = _valid_armor_parts()
    (tmp_path / "trailing-junk-end.asc").write_bytes(
        f"-----BEGIN PGP MESSAGE-----\n\n{encoded}\n={checksum}\n"
        "-----END PGP MESSAGE----- and then some\n".encode("ascii")
    )

    assert scan_crypto_inventory_findings(str(tmp_path)) == []


def test_armor_body_truncated_before_end_is_not_detected(tmp_path):
    # The body simply stops -- no checksum, no tail, nothing -- partway
    # through what would otherwise be a valid message.
    encoded, _checksum, _end = _valid_armor_parts()
    (tmp_path / "truncated-before-end.asc").write_bytes(
        f"-----BEGIN PGP MESSAGE-----\n\n{encoded[:32]}\n".encode("ascii")
    )

    assert scan_crypto_inventory_findings(str(tmp_path)) == []


def test_valid_looking_prefix_with_no_complete_armored_message_is_not_detected(tmp_path):
    # Only the header line and the blank separator -- a prefix that "looks
    # armored" but never becomes a complete message.
    (tmp_path / "prefix-only.asc").write_bytes(b"-----BEGIN PGP MESSAGE-----\n\n")

    assert scan_crypto_inventory_findings(str(tmp_path)) == []


def test_armor_trailing_junk_on_begin_line_is_not_detected(tmp_path):
    encoded, checksum, end = _valid_armor_parts()
    (tmp_path / "trailing-junk-begin.asc").write_bytes(
        f"-----BEGIN PGP MESSAGE----- and then some\n\n{encoded}\n={checksum}\n{end}\n".encode(
            "ascii"
        )
    )

    assert scan_crypto_inventory_findings(str(tmp_path)) == []


def test_valid_lf_armor_with_complete_checksum_and_end_is_detected(tmp_path):
    (tmp_path / "valid-lf.asc").write_bytes(_armored(_symmetric_encrypted_bytes()))

    findings = scan_crypto_inventory_findings(str(tmp_path))

    assert len(findings) == 1
    assert findings[0].rule_id == "encrypted_file:openpgp"


def test_valid_crlf_armor_with_complete_checksum_and_end_is_detected(tmp_path):
    (tmp_path / "valid-crlf.asc").write_bytes(
        _armored(_symmetric_encrypted_bytes()).replace(b"\n", b"\r\n")
    )

    findings = scan_crypto_inventory_findings(str(tmp_path))

    assert len(findings) == 1
    assert findings[0].rule_id == "encrypted_file:openpgp"


def test_valid_armor_with_optional_headers_and_complete_framing_is_detected(tmp_path):
    body = _symmetric_encrypted_bytes()
    encoded = base64.b64encode(body).decode("ascii")
    checksum = _armor_checksum_line(body)
    (tmp_path / "with-headers.asc").write_bytes(
        "-----BEGIN PGP MESSAGE-----\n"
        "Version: GnuPG v2\n"
        "Comment: HG-031 fixture\n\n"
        f"{encoded}\n"
        f"={checksum}\n"
        "-----END PGP MESSAGE-----\n".encode("ascii")
    )

    findings = scan_crypto_inventory_findings(str(tmp_path))

    assert len(findings) == 1
    assert findings[0].rule_id == "encrypted_file:openpgp"


def test_offset_match_is_not_detected(tmp_path):
    (tmp_path / "offset.gpg").write_bytes(b"XX" + _symmetric_encrypted_bytes())
    (tmp_path / "offset.asc").write_bytes(
        b"preamble\n" + _armored(_symmetric_encrypted_bytes())
    )

    assert scan_crypto_inventory_findings(str(tmp_path)) == []


def test_empty_and_short_files_are_handled_safely(tmp_path):
    (tmp_path / "empty.gpg").write_bytes(b"")
    (tmp_path / "one-byte.gpg").write_bytes(bytes([0x8C]))
    (tmp_path / "header-only.gpg").write_bytes(bytes([0x8C, 0x0D]))
    (tmp_path / "truncated-body.gpg").write_bytes(bytes([0x8C, 0x0D, 0x04, 0x09]))
    (tmp_path / "truncated-pkesk.gpg").write_bytes(bytes([0x84, 0x5E, 0x03, 0x20]))
    (tmp_path / "empty-armor.asc").write_bytes(b"-----BEGIN PGP MESSAGE-----\n")
    (tmp_path / "short-armor.asc").write_bytes(
        b"-----BEGIN PGP MESSAGE-----\n\njA0\n-----END PGP MESSAGE-----\n"
    )
    (tmp_path / "unarmored-junk.asc").write_bytes(
        b"-----BEGIN PGP MESSAGE-----\n\n!!!!not radix64!!!!\n"
    )

    # Must not raise, and must not falsely detect any of these.
    assert scan_crypto_inventory_findings(str(tmp_path)) == []


def test_binary_noise_is_handled_safely(tmp_path):
    (tmp_path / "noise.bin").write_bytes(bytes(range(256)) * 4)
    (tmp_path / "nulls.bin").write_bytes(b"\x00" * 512)
    (tmp_path / "high-bytes.bin").write_bytes(b"\xff" * 512)

    assert scan_crypto_inventory_findings(str(tmp_path)) == []


# --- 4. rule_id propagation through scanner, adapter, JSON, Markdown, CLI ---


def test_rule_id_survives_the_normalization_adapter(tmp_path):
    (tmp_path / "secret.gpg").write_bytes(_symmetric_encrypted_bytes())

    df = scan_crypto_inventory(str(tmp_path))
    findings = normalize_crypto_inventory_df(df)

    assert df.loc[0, "Rule ID"] == "encrypted_file:openpgp"
    assert len(findings) == 1
    assert findings[0].rule_id == "encrypted_file:openpgp"


def test_rule_id_reaches_json_and_markdown_output(tmp_path, capsys):
    (tmp_path / "secret.gpg").write_bytes(_symmetric_encrypted_bytes())

    assert harvestguard.main(
        ["scan", str(tmp_path), "--type", "crypto", "--json", "--quiet"]
    ) == 0
    payload = json.loads(capsys.readouterr().out)
    assert isinstance(payload, list)
    assert len(payload) == 1
    assert payload[0]["rule_id"] == "encrypted_file:openpgp"
    assert payload[0]["asset_type"] == "Encrypted File"
    assert payload[0]["source_type"] == "crypto_inventory"
    assert payload[0]["confidence"] == "High"

    assert harvestguard.main(
        ["scan", str(tmp_path), "--type", "crypto", "--markdown", "--quiet"]
    ) == 0
    report = capsys.readouterr().out
    assert "Encrypted File" in report
    assert "symmetric-key encrypted session key packet" in report
    assert "| Crypto Files Inspected | 1 |" in report


def test_rule_id_is_unset_for_other_crypto_inventory_asset_types(tmp_path):
    # An armored encrypted message and a PEM certificate in the same scan: the
    # OpenPGP rule_id must not leak onto the certificate finding.
    certificate = Path(__file__).parent / "fixtures" / "crypto_inventory" / "rsa_cert.pem"
    (tmp_path / "secret.asc").write_bytes(_armored(_symmetric_encrypted_bytes()))
    (tmp_path / "cert.pem").write_bytes(certificate.read_bytes())

    findings = {f.asset_type: f for f in scan_crypto_inventory_findings(str(tmp_path))}

    assert findings["Encrypted File"].rule_id == "encrypted_file:openpgp"
    assert findings["PEM Certificate"].rule_id is None


# --- 5. Scanner ownership: filesystem-only, crypto-only, combined -----------


def test_filesystem_only_scan_behavior_is_unchanged(tmp_path):
    # Armor: the filesystem scanner recognized this before HG-031 and still
    # does, with its own rule_id and asset type.
    (tmp_path / "secret.asc").write_bytes(_armored(_symmetric_encrypted_bytes()))

    findings = scan_filesystem_findings(str(tmp_path))
    file_findings = [f for f in findings if f.asset_type == "file"]

    assert len(file_findings) == 1
    assert file_findings[0].rule_id == "file_signature:file_level_pgp_gpg"
    assert file_findings[0].technical_metadata["Encryption"] == "File-level (PGP/GPG)"
    assert file_findings[0].confidence == "High"


def test_filesystem_only_scan_gains_no_new_binary_signature(tmp_path):
    # HG-031 adds crypto-inventory evidence, not a filesystem signature: the
    # binary `gpg --symmetric` shape is still not in the filesystem scanner's
    # signature table, so it produces no per-file filesystem record.
    (tmp_path / "secret.gpg").write_bytes(_symmetric_encrypted_bytes())

    findings = scan_filesystem_findings(str(tmp_path))

    assert [f for f in findings if f.asset_type == "file"] == []


def test_crypto_only_scan_reports_the_openpgp_finding(tmp_path):
    (tmp_path / "secret.gpg").write_bytes(_symmetric_encrypted_bytes())
    (tmp_path / "armored.asc").write_bytes(_armored(_public_key_encrypted_bytes()))

    findings = scan_crypto_inventory_findings(str(tmp_path))

    assert len(findings) == 2
    assert all(f.rule_id == "encrypted_file:openpgp" for f in findings)


def test_dedup_keeps_exactly_one_finding_and_is_order_independent(tmp_path):
    (tmp_path / "secret.asc").write_bytes(_armored(_symmetric_encrypted_bytes()))

    fs_findings = scan_filesystem_findings(str(tmp_path))
    crypto_findings = scan_crypto_inventory_findings(str(tmp_path))

    forward = _deduplicate_encrypted_file_findings(fs_findings + crypto_findings)
    reverse = _deduplicate_encrypted_file_findings(crypto_findings + fs_findings)

    for combined, label in ((forward, "forward"), (reverse, "reverse")):
        for_file = [f for f in combined if f.location.endswith("secret.asc")]
        assert len(for_file) == 1, label
        assert for_file[0].source_type == "crypto_inventory", label
        assert for_file[0].rule_id == "encrypted_file:openpgp", label


def test_dedup_is_a_noop_when_only_one_scanner_ran(tmp_path):
    (tmp_path / "secret.asc").write_bytes(_armored(_symmetric_encrypted_bytes()))

    fs_only = scan_filesystem_findings(str(tmp_path))
    crypto_only = scan_crypto_inventory_findings(str(tmp_path))

    assert _deduplicate_encrypted_file_findings(fs_only) == fs_only
    assert _deduplicate_encrypted_file_findings(crypto_only) == crypto_only


def test_dedup_does_not_drop_unrelated_filesystem_pgp_evidence(tmp_path):
    # A MESSAGE-armored file the crypto scanner does *not* claim (signed only)
    # keeps its filesystem record: dedup is per location, not per rule_id.
    (tmp_path / "encrypted.asc").write_bytes(_armored(_symmetric_encrypted_bytes()))
    (tmp_path / "signed.asc").write_bytes(_armored(bytes([0xA3, 0x01, 0x01]) + b"\x00" * 48))

    combined = _deduplicate_encrypted_file_findings(
        scan_filesystem_findings(str(tmp_path)) + scan_crypto_inventory_findings(str(tmp_path))
    )

    signed = [f for f in combined if f.location.endswith("signed.asc")]
    assert len(signed) == 1
    assert signed[0].source_type == "local_filesystem"
    assert signed[0].rule_id == "file_signature:file_level_pgp_gpg"


def test_dedup_preserves_openssl_ownership_from_hg_030(tmp_path):
    (tmp_path / "openssl.enc").write_bytes(b"Salted__" + b"\x00" * 24)
    (tmp_path / "openpgp.asc").write_bytes(_armored(_symmetric_encrypted_bytes()))

    combined = _deduplicate_encrypted_file_findings(
        scan_filesystem_findings(str(tmp_path)) + scan_crypto_inventory_findings(str(tmp_path))
    )

    by_location = {}
    for finding in combined:
        by_location.setdefault(os.path.basename(finding.location), []).append(finding)
    assert len(by_location["openssl.enc"]) == 1
    assert by_location["openssl.enc"][0].rule_id == "encrypted_file:openssl"
    assert len(by_location["openpgp.asc"]) == 1
    assert by_location["openpgp.asc"][0].rule_id == "encrypted_file:openpgp"


def test_cli_type_all_reports_each_openpgp_file_exactly_once(tmp_path, capsys):
    (tmp_path / "armored.asc").write_bytes(_armored(_symmetric_encrypted_bytes()))
    (tmp_path / "binary.gpg").write_bytes(_symmetric_encrypted_bytes())

    exit_code = harvestguard.main(
        ["scan", str(tmp_path), "--type", "all", "--json", "--quiet"]
    )

    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    for name in ("armored.asc", "binary.gpg"):
        records = [
            record
            for record in payload
            if record["location"].endswith(name)
            and record["source_type"] in {"crypto_inventory", "local_filesystem"}
        ]
        assert len(records) == 1, name
        assert records[0]["rule_id"] == "encrypted_file:openpgp", name
        assert records[0]["asset_type"] == "Encrypted File", name
    assert [r for r in payload if r["rule_id"] == "file_signature:file_level_pgp_gpg"] == []


# --- 6. Accounting: Files scanned and Crypto files inspected ---------------


def test_files_scanned_semantics_are_unchanged(tmp_path, capsys):
    (tmp_path / "secret.gpg").write_bytes(_symmetric_encrypted_bytes())
    (tmp_path / "plain.txt").write_text("harvestguard fixture text")

    assert harvestguard.main(
        ["scan", str(tmp_path), "--type", "crypto", "--summary", "--quiet"]
    ) == 0
    crypto_output = capsys.readouterr().out
    # The crypto-inventory scanner is not the filesystem scanner, so it
    # contributes nothing to Files scanned (HG-029/HG-030 semantics).
    assert "Files scanned: 0" in crypto_output

    assert harvestguard.main(
        ["scan", str(tmp_path), "--type", "filesystem", "--summary", "--quiet"]
    ) == 0
    filesystem_output = capsys.readouterr().out
    assert "Files scanned: 2" in filesystem_output
    assert "Crypto files inspected" not in filesystem_output


def test_crypto_files_inspected_counts_every_file_opened(tmp_path, capsys):
    for index in range(4):
        (tmp_path / f"ordinary_{index}.txt").write_text("harvestguard fixture text")
    (tmp_path / "secret.gpg").write_bytes(_symmetric_encrypted_bytes())

    stats: dict[str, int] = {}
    scan_crypto_inventory(str(tmp_path), stats=stats)
    assert stats["files_inspected"] == 5

    assert harvestguard.main(
        ["scan", str(tmp_path), "--type", "crypto", "--summary", "--quiet"]
    ) == 0
    assert "Crypto files inspected: 5" in capsys.readouterr().out


# --- 7. No plaintext, payload bytes, keys, or credentials in output ---------


def test_no_payload_bytes_or_plaintext_in_json_or_markdown(tmp_path, capsys):
    marker = os.urandom(16)
    (tmp_path / "secret.gpg").write_bytes(_symmetric_encrypted_bytes(marker))
    (tmp_path / "secret.asc").write_bytes(_armored(_symmetric_encrypted_bytes(marker)))

    harvestguard.main(["scan", str(tmp_path), "--type", "crypto", "--json", "--quiet"])
    json_output = capsys.readouterr().out
    harvestguard.main(["scan", str(tmp_path), "--type", "crypto", "--markdown", "--quiet"])
    markdown_output = capsys.readouterr().out

    for output in (json_output, markdown_output):
        assert marker.hex() not in output
        assert marker not in output.encode("utf-8", errors="ignore")
        assert _SALT.hex() not in output
        assert "-----BEGIN PGP MESSAGE-----" not in output


# --- 8. Real GnuPG output (skipped when gpg is unavailable) -----------------

_GPG = shutil.which("gpg")
# Deliberately not a real secret: this only has to be a string gpg accepts.
_FIXTURE_PASSPHRASE = "harvestguard-openpgp-fixture-passphrase"
_FIXTURE_PLAINTEXT = "harvestguard-openpgp-fixture-plaintext"


def _gpg_encrypted_file(tmp_path, armor: bool):
    """A real `gpg --symmetric` file in a dedicated scan-target directory."""
    home = tmp_path / "gnupghome"
    home.mkdir(mode=0o700)
    target = tmp_path / "target"
    target.mkdir()
    plaintext = tmp_path / "plain.txt"
    plaintext.write_text(_FIXTURE_PLAINTEXT + "\n")
    output = target / ("real.asc" if armor else "real.gpg")

    argv = [_GPG, "--batch", "--yes", "--passphrase", _FIXTURE_PASSPHRASE]
    if armor:
        argv.append("--armor")
    argv += ["--symmetric", "--output", str(output), str(plaintext)]
    try:
        result = subprocess.run(
            argv,
            env={**os.environ, "GNUPGHOME": str(home)},
            capture_output=True,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:  # pragma: no cover
        pytest.skip(f"gpg could not be executed: {exc}")
    if result.returncode != 0:  # pragma: no cover
        pytest.skip(f"gpg failed to produce a fixture: {result.stderr.decode(errors='replace')}")
    return target, output


@pytest.mark.skipif(_GPG is None, reason="gpg is not installed")
@pytest.mark.parametrize("armor", [False, True])
def test_real_gpg_symmetric_file_is_detected(tmp_path, armor):
    target, output = _gpg_encrypted_file(tmp_path, armor)
    data = output.read_bytes()
    if not data.startswith((bytes([0x8C]), b"-----BEGIN PGP MESSAGE-----")):  # pragma: no cover
        pytest.skip(
            "this gpg build wrote an OpenPGP shape HG-031 documents as "
            f"unsupported (leading byte 0x{data[0]:02x})"
        )

    findings = scan_crypto_inventory_findings(str(target))

    assert len(findings) == 1
    assert findings[0].rule_id == "encrypted_file:openpgp"
    assert findings[0].asset_type == "Encrypted File"
    assert findings[0].confidence == "High"
    assert "symmetric-key encrypted session key packet" in findings[0].evidence
    assert findings[0].technical_metadata["Algorithm"] == "AES-256"


@pytest.mark.skipif(_GPG is None, reason="gpg is not installed")
def test_real_gpg_output_leaks_no_plaintext_or_passphrase(tmp_path, capsys):
    target, _ = _gpg_encrypted_file(tmp_path, armor=False)

    harvestguard.main(["scan", str(target), "--type", "crypto", "--json", "--quiet"])
    json_output = capsys.readouterr().out
    harvestguard.main(["scan", str(target), "--type", "crypto", "--markdown", "--quiet"])
    markdown_output = capsys.readouterr().out

    for output in (json_output, markdown_output):
        assert _FIXTURE_PLAINTEXT not in output
        assert _FIXTURE_PASSPHRASE not in output
