from __future__ import annotations

import argparse
import base64
import binascii
import fnmatch
import json
import math
import os
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.serialization import pkcs12

from finding_adapters import normalize_crypto_inventory_df
from findings import NormalizedFinding
from scanner.crypto_detectors import (
    MAX_TEXT_BYTES,
    DetectionResult,
    DetectorExecutionError,
    FileContext,
    FileDetector,
    RootContext,
    RootDetector,
    ScanScope,
    build_registry,
    run_detectors,
)
from scanner.errors import LocalScanError

SCANNER_NAME = "crypto_inventory"
SCANNER_VERSION = "0.1.0"
_BINARY_PARSE_EXTENSIONS = {".cer", ".crt", ".der", ".jks", ".p12", ".pfx"}
_PEM_BLOCK_MARKERS = {
    "CERTIFICATE": "PEM Certificate",
    "PRIVATE KEY": "PEM Private Key",
    "ENCRYPTED PRIVATE KEY": "Encrypted PEM Private Key",
    "RSA PRIVATE KEY": "PEM Private Key",
    "DSA PRIVATE KEY": "PEM Private Key",
    "EC PRIVATE KEY": "PEM Private Key",
    "OPENSSH PRIVATE KEY": "OpenSSH Private Key",
    "PUBLIC KEY": "PEM Public Key",
}


@dataclass
class CryptoInventoryFinding:
    asset_type: str
    location: str
    algorithm: str | None = None
    key_size: int | None = None
    signature_algorithm: str | None = None
    expiration: str | None = None
    issuer: str | None = None
    subject: str | None = None
    fingerprint: str | None = None
    evidence: str = ""
    confidence: str = "Low"
    # Unset for every asset type except the findings backed by a specific,
    # nameable detection rule rather than a parsed certificate/key: the OpenSSL
    # Salted__ signature (HG-030), the OpenPGP encrypted-file structure
    # (HG-031), the native age v1 encrypted file (HG-035), the gocryptfs cipher
    # root (HG-032), the BCFKS keystore container (HG-036), and the JCEKS
    # keystore container (HG-037), encrypted PKCS#8 (HG-038), CMS/PKCS#7
    # (HG-039), and legacy encrypted PEM (HG-040). Every other asset type
    # leaves this None rather than inventing one.
    rule_id: str | None = None
    # Container metadata (HG-032/036/037/038/039/040 containers; generic rather
    # than format-specific field names so each container format can reuse them,
    # and each detector's own allowlist decides which it may populate). Unset
    # for every other asset type. Deliberately limited to what those privacy
    # contracts allow: a format name, the supported on-disk config version
    # observed, and the supported mode -- never the raw config, key material,
    # salts, MACs, KDF parameters, or nonces.
    format: str | None = None
    config_version: int | None = None
    mode: str | None = None
    errors: list[str] = field(default_factory=list)
    scanner: str = SCANNER_NAME
    scanner_version: str = SCANNER_VERSION
    observed_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    )

    def to_record(self) -> dict[str, Any]:
        return {
            "Asset Type": self.asset_type,
            "Location": self.location,
            "Algorithm": self.algorithm,
            "Key Size": self.key_size,
            "Signature Algorithm": self.signature_algorithm,
            "Expiration": self.expiration,
            "Issuer": self.issuer,
            "Subject": self.subject,
            "Fingerprint": self.fingerprint,
            "Evidence": self.evidence,
            "Confidence": self.confidence,
            "Rule ID": self.rule_id,
            "Format": self.format,
            "Config Version": self.config_version,
            "Mode": self.mode,
            "Errors": "; ".join(self.errors),
            "Scanner": self.scanner,
            "Scanner Version": self.scanner_version,
            "Observed At": self.observed_at,
        }


def scan_crypto_inventory(
    path: str,
    exclude_patterns: list[str] | None = None,
    follow_symlinks: bool = False,
    stats: dict[str, int] | None = None,
    traversal_errors: list[str] | None = None,
    detector_errors: list[str] | None = None,
) -> pd.DataFrame:
    """Recursively scan a local path for cryptographic asset evidence.

    ``stats``, when given, is populated with ``files_inspected``: the count
    of every file this scan actually visited and opened, regardless of
    whether it matched a recognized candidate shape or produced a finding
    (HG-030 crypto scan accounting). It is an optional out-of-band channel
    rather than a return-value change, so existing callers of this function
    are unaffected.

    ``traversal_errors``, when given, collects one message per subdirectory
    ``os.walk`` could not list (permission denied, unreadable, or another
    OSError) -- see ``_iter_candidate_files``. The walk continues past the
    failure; this only records that it happened, matching the same
    ``errors=`` side-channel shape ``scanner/cloud.py`` already uses for the
    same "collect, don't abort, let the caller decide how to surface it"
    reason (HG-032 Blocker 2).

    ``detector_errors``, when given, collects the one message describing an
    unexpected detector failure (HG-033). Unlike a traversal error, this stops
    the scan: a detector that raised is a defect, not a coverage gap, and the
    remaining files cannot be claimed as inspected. Findings collected before
    the failure are still returned -- including those earlier detectors produced
    for the same file the failing detector was inspecting -- so the caller
    surfaces the failure while keeping the evidence already gathered, the same
    shape as the traversal and cloud partial-finding paths. When the argument is
    omitted the exception propagates instead, so a caller that has no way to
    surface the failure never receives a truncated result that looks like a clean
    one.
    """
    findings = []
    root_path = Path(path)
    patterns = exclude_patterns or []
    files_inspected = 0
    scope = _scan_scope(root_path, patterns)

    for file_path in _iter_candidate_files(
        root_path, patterns, follow_symlinks, traversal_errors
    ):
        files_inspected += 1
        try:
            findings.extend(_scan_file(file_path, scope=scope))
        except DetectorExecutionError as exc:
            if detector_errors is None:
                raise
            # Including the evidence earlier detectors already produced for this
            # same file: one detector's defect must not discard another
            # detector's valid finding about the asset they share.
            findings.extend(exc.partial_findings)
            detector_errors.append(str(exc))
            break

    if stats is not None:
        stats["files_inspected"] = files_inspected

    return pd.DataFrame([finding.to_record() for finding in findings])


def scan_crypto_inventory_findings(
    path: str,
    exclude_patterns: list[str] | None = None,
    follow_symlinks: bool = False,
    scan_id: str | None = None,
    stats: dict[str, int] | None = None,
) -> list[NormalizedFinding]:
    traversal_errors: list[str] = []
    detector_errors: list[str] = []
    df = scan_crypto_inventory(
        path,
        exclude_patterns=exclude_patterns,
        follow_symlinks=follow_symlinks,
        stats=stats,
        traversal_errors=traversal_errors,
        detector_errors=detector_errors,
    )
    findings = normalize_crypto_inventory_df(df, scan_id=scan_id)
    scan_errors = traversal_errors + detector_errors
    if scan_errors:
        # A directory this scan could not list is a coverage gap, not a
        # clean, fully-covered result -- but the walk already continued past
        # it, so everything collected elsewhere (including a gocryptfs root
        # finding whose own markers/config were already fully validated) must
        # not be discarded. Mirrors CloudScanError: the caller (the CLI) sees
        # a scanner_errors entry and a nonzero exit, while these findings
        # still appear in the output.
        #
        # An unexpected detector failure (HG-033) reaches the caller the same
        # way and for the same reason: the scan is not a clean, complete result,
        # but the evidence collected before it must not be discarded either.
        raise LocalScanError("; ".join(scan_errors), partial_findings=findings)
    return findings


def _iter_candidate_files(
    root_path: Path,
    exclude_patterns: list[str],
    follow_symlinks: bool,
    traversal_errors: list[str] | None = None,
):
    if root_path.is_file():
        if not _is_excluded(root_path, root_path.name, exclude_patterns):
            yield root_path
        return

    def _on_walk_error(exc: OSError) -> None:
        # Recorded, never raised: os.walk continues to the next directory in
        # the walk on its own after this callback returns, so one unreadable
        # subtree does not stop the rest of the scan from being collected
        # (HG-032 Blocker 2, requirement 3).
        if traversal_errors is not None:
            traversal_errors.append(
                f"{exc.filename or root_path}: {exc.strerror or exc}"
            )

    for current_root, dirs, files in os.walk(
        root_path, onerror=_on_walk_error, followlinks=follow_symlinks
    ):
        current = Path(current_root)
        rel_root = _relative_for_match(current, root_path)
        dirs[:] = [
            d
            for d in dirs
            if (follow_symlinks or not (current / d).is_symlink())
            and not _is_excluded(current / d, _join_match_path(rel_root, d), exclude_patterns)
        ]

        for name in files:
            file_path = current / name
            rel_path = _join_match_path(rel_root, name)
            if _is_excluded(file_path, rel_path, exclude_patterns):
                continue
            if file_path.is_symlink() and not follow_symlinks:
                continue
            yield file_path


_OPENSSL_SALTED_SIGNATURE = b"Salted__"


def _looks_like_openssl_salted(data: bytes) -> bool:
    """Exact-position, binary-safe check for OpenSSL's `openssl enc -salt`
    header. `bytes.startswith` never raises regardless of length (an empty
    or truncated file safely returns False), and only matches the literal
    signature at offset 0 -- a file with the same bytes later in its content
    is not a match, matching the real format (the signature is always the
    first 8 bytes of `enc -salt` output, never embedded elsewhere)."""
    return data.startswith(_OPENSSL_SALTED_SIGNATURE)


def _openssl_salted_finding(file_path: Path) -> CryptoInventoryFinding:
    return CryptoInventoryFinding(
        asset_type="Encrypted File",
        location=str(file_path),
        evidence="Observed OpenSSL Salted__ encrypted file.",
        confidence="High",
        rule_id="encrypted_file:openssl",
    )


# --- OpenPGP encrypted-file detection (HG-031) -----------------------------
#
# Structural, never decryption: only the leading OpenPGP packet header and the
# fixed metadata fields RFC 4880 defines for it are read, and each of those
# fields is validated against the values the specification allows. The
# encrypted payload itself is never interpreted, no passphrase is requested or
# accepted, and no external tool (gpg included) is invoked.
#
# Deliberately narrow -- the two encrypted-session-key packet shapes GnuPG
# actually writes at the start of an encrypted file, verified against real
# `gpg --symmetric` and `gpg --encrypt` output:
#
#   Tag 3, version 4  Symmetric-Key Encrypted Session Key (`gpg -c`); the
#                     field-observed shape in HG-031, which begins `8c 0d 04`.
#   Tag 1, version 3  Public-Key Encrypted Session Key (`gpg -e`), which
#                     begins e.g. `84 5e 03` or `85 01 0c`.
#
# Everything else is out of scope and documented as a false negative in
# docs/DETECTION_CHARACTERIZATION.md, including RFC 9580 v6 packets, AEAD-only
# forms, partial/indeterminate packet lengths, and a file that begins with a
# bare encrypted-data packet with no session-key packet in front of it.

# Only the MESSAGE armor label carries message content. SIGNED MESSAGE,
# SIGNATURE, PUBLIC KEY BLOCK, and PRIVATE KEY BLOCK are not encrypted-file
# evidence and are deliberately absent here -- the same narrowing the HG-009
# correction applied to scanner/filesystem.py, which this must not revert.
_OPENPGP_ARMOR_HEADER = b"-----BEGIN PGP MESSAGE-----"
_OPENPGP_ARMOR_TAIL = b"-----END PGP MESSAGE-----"

# RFC 4880 section 6.1: the CRC-24 every OpenPGP armor implementation computes
# over the decoded packet stream to produce the checksum line. Poly and init
# are the values the specification fixes, transcribed verbatim; verified
# against the published CRC-24/OpenPGP reference check value (0x21CF02 for
# the ASCII string "123456789") before this was wired into the parser below.
_OPENPGP_CRC24_INIT = 0xB704CE
_OPENPGP_CRC24_POLY = 0x1864CFB
_RADIX64_ALPHABET = frozenset(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
)

_OPENPGP_TAG_PKESK = 1
_OPENPGP_TAG_SKESK = 3

# RFC 4880 section 9.2. Algorithm 0 ("plaintext or unencrypted data") is
# deliberately absent: a packet declaring it is not evidence of encryption.
_OPENPGP_SYMMETRIC_ALGORITHMS = {
    1: "IDEA",
    2: "TripleDES",
    3: "CAST5",
    4: "Blowfish",
    7: "AES-128",
    8: "AES-192",
    9: "AES-256",
    10: "Twofish",
    11: "Camellia-128",
    12: "Camellia-192",
    13: "Camellia-256",
}
# RFC 4880 section 3.7.1: the only string-to-key specifier types a version 4
# Symmetric-Key Encrypted Session Key packet may use.
_OPENPGP_S2K_SPECIFIERS = {0: "simple", 1: "salted", 3: "iterated and salted"}
# RFC 4880 section 3.7.1 also fixes each specifier's total length, and with it
# which fields the packet body is required to carry: two octets (type and hash
# algorithm) for every type, plus an 8-octet salt when salted, plus a 1-octet
# coded iteration count when iterated. A body too short to hold them is
# malformed, not encrypted-file evidence.
_OPENPGP_S2K_SPECIFIER_LENGTHS = {0: 2, 1: 2 + 8, 3: 2 + 8 + 1}
# RFC 4880 section 9.4. Validated but not reported: the hash identifier is
# checked to reject near matches, not surfaced as a claim about the file.
_OPENPGP_HASH_ALGORITHM_IDS = frozenset({1, 2, 3, 8, 9, 10, 11, 12, 13, 14})
# RFC 4880 section 5.1: version, key ID, and public-key algorithm occupy ten
# octets, and the algorithm-specific encrypted session key that must follow them
# is never empty, so a version 3 packet declaring ten octets or fewer is
# malformed for every algorithm below.
_OPENPGP_PKESK_MIN_BODY_LENGTH = 11
# RFC 4880 section 9.1 and RFC 9580 section 9.1, restricted to the algorithms
# valid for an encrypted session key; sign-only algorithms are excluded.
_OPENPGP_PUBLIC_KEY_ALGORITHMS = {
    1: "RSA",
    2: "RSA (encrypt-only)",
    16: "Elgamal",
    18: "ECDH",
    25: "X25519",
    26: "X448",
}

# A session-key packet alone is not an encrypted message -- it only names how
# the actual encrypted-data packet's session key was protected. HG-031
# correction cycle 2's Blocker 1: a supported message also requires at least
# one following, complete encrypted-data packet, restricted to the two RFC
# 4880 shapes real GnuPG output uses:
#
#   Tag 18, version 1  Sym. Encrypted Integrity Protected Data (RFC 4880
#                      section 5.13), what current GnuPG writes by default
#                      for both `gpg -c` and `gpg -e`. Version 2 is the RFC
#                      9580 AEAD form and is deliberately unsupported.
#   Tag 9              Symmetrically Encrypted Data (RFC 4880 section 5.7),
#                      the older, MDC-less shape: opaque from its first body
#                      octet onward, with no version field to check.
#
# Nothing else -- no v6/AEAD packet, no partial or indeterminate length, no
# other packet family -- counts as the required following packet.
_OPENPGP_TAG_SEIPD = 18
_OPENPGP_TAG_SED = 9
_OPENPGP_SEIPD_VERSION = 1


def _openpgp_crc24(data: bytes) -> int:
    """RFC 4880 section 6.1's CRC-24, computed over a decoded armor body so it
    can be compared against the declared checksum line."""
    crc = _OPENPGP_CRC24_INIT
    for byte in data:
        crc ^= byte << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= _OPENPGP_CRC24_POLY
        crc &= 0xFFFFFF
    return crc


def _openpgp_armor_body(data: bytes) -> bytes | None:
    """The complete decoded packet stream of an ASCII-armored OpenPGP MESSAGE's
    radix-64 body, or None when ``data`` is not complete, well-formed MESSAGE
    armor.

    RFC 4880 section 6.2 fixes this layout, and every part of it is required
    -- HG-031's correction cycle 2 established that "looks like armor" is not
    "is complete armor", so every one of these is now enforced, not merely
    the ones a truncated/malformed file happened to trip over before:

      1. the armor header line alone on the first line;
      2. optional ``Key: Value`` armor headers;
      3. the mandatory blank separator line;
      4. a radix-64 encoded packet stream, whole quantums only;
      5. a radix-64 checksum line (``=`` plus exactly four radix-64 octets)
         whose decoded value is the CRC-24 of the decoded packet stream --
         not merely a line that starts with ``=``;
      6. an armor tail line matching the *same* label as the header line,
         exactly, with nothing else on that line.

    Trailing content on the header or tail line, a body that is not preceded
    by the blank separator, a missing or incorrect checksum, a missing or
    mismatched tail line, or content the tail line does not immediately
    follow are all rejected -- this is not armor, and is not read as though
    it were.

    The first decoded byte is therefore the first byte of the first OpenPGP
    packet, which is the offset the format specification requires this check
    to read -- the armored counterpart of offset 0 in a binary file, not a
    scan for a signature at an arbitrary offset. The *whole* body is decoded
    rather than a leading prefix of it, because the decoded stream is the
    armored counterpart of a binary file's bytes: the caller's declared-length
    check is only meaningful against the complete content, since a packet
    declaring more body than the stream actually holds is truncated or
    over-declared either way. Nothing decoded here is reported; the payload is
    only ever read for the packet metadata the specification fixes at these
    offsets.

    Binary-safe: split on line boundaries as bytes, never decoded as text, so
    a file that only looks armored cannot raise.
    """
    if not data.startswith(_OPENPGP_ARMOR_HEADER):
        return None

    lines = data.split(b"\n")
    # Armor may use CRLF line endings, but nothing else may follow the header
    # line -- "-----BEGIN PGP MESSAGE----- and then some" is not armor.
    if lines[0].rstrip(b"\r") != _OPENPGP_ARMOR_HEADER:
        return None

    # The mandatory blank line after the (possibly empty) run of armor headers.
    # ":" cannot occur in the radix-64 alphabet, so a non-blank line before that
    # separator is only legal if it is an armor header.
    body_start = None
    for index, line in enumerate(lines[1:], start=1):
        if not line.strip():
            body_start = index + 1
            break
        if b":" not in line:
            return None
    if body_start is None:
        return None

    # Collect body lines until a checksum line, a blank line, or the end of
    # the file -- a checksum line is now mandatory (see docstring point 5), so
    # reaching a tail line, a blank line, or the end of the lines list without
    # first finding one means this armor is incomplete, not merely body-less.
    body_lines: list[bytes] = []
    checksum_line: bytes | None = None
    checksum_line_index: int | None = None
    for index in range(body_start, len(lines)):
        line = lines[index].rstrip(b"\r")
        if line.startswith(b"="):
            checksum_line = line
            checksum_line_index = index
            break
        if not line or line.startswith(b"-----"):
            return None
        body_lines.append(line)
    if checksum_line is None:
        return None

    # Exactly "=" plus four radix-64 octets (24 bits, the whole CRC-24) --
    # nothing shorter, longer, or containing a character outside the radix-64
    # alphabet is a valid checksum line.
    checksum_digits = checksum_line[1:]
    if len(checksum_digits) != 4 or any(c not in _RADIX64_ALPHABET for c in checksum_digits):
        return None

    # The tail line must be the very next line, matching the header's label
    # exactly, with nothing else on it -- a blank line, other content, or the
    # end of the file between the checksum and the tail is not complete armor.
    tail_index = checksum_line_index + 1
    if tail_index >= len(lines):
        return None
    if lines[tail_index].rstrip(b"\r") != _OPENPGP_ARMOR_TAIL:
        return None

    # Only a whole number of radix-64 quantums is a complete, valid body --
    # unlike a truncated *packet* (which the caller's declared-length check
    # rejects), a body whose character count is not a multiple of four is
    # malformed radix-64 itself and is never a partial-but-honest prefix.
    encoded = b"".join(body_lines)
    if not encoded or len(encoded) % 4 != 0:
        return None
    try:
        decoded = base64.b64decode(encoded, validate=True)
    except ValueError:
        # binascii.Error (a ValueError) for a body that is not valid radix-64.
        return None

    checksum_bytes = base64.b64decode(checksum_digits, validate=True)
    if int.from_bytes(checksum_bytes, "big") != _openpgp_crc24(decoded):
        return None

    return decoded


def _openpgp_packet_header(data: bytes) -> tuple[int, int, int] | None:
    """``(packet tag, body offset, declared body length)`` for the OpenPGP
    packet at offset 0 of ``data``, or None when ``data`` does not begin with a
    packet header whose body offset and declared length are both determinate.

    RFC 4880 section 4.2: the first octet of a packet has bit 7 set, bit 6
    selects the new or old header format, and the length octets that follow are
    what fix both where the packet body starts and how long the packet declares
    it to be. Partial (new-format 224..254) and indeterminate (old-format length
    type 3) lengths are rejected rather than guessed at -- neither is legal for
    the session-key packets this detection covers, and neither declares a length
    the callers below can hold their field reads inside of. Every length octet
    is bounds-checked before it is read, so a file that ends mid-header returns
    None instead of raising.
    """
    if len(data) < 2:
        return None
    first = data[0]
    if not first & 0x80:
        return None

    if first & 0x40:
        tag = first & 0x3F
        length_octet = data[1]
        if length_octet < 192:
            body_offset, body_length = 2, length_octet
        elif length_octet < 224:
            if len(data) < 3:
                return None
            body_offset = 3
            body_length = ((length_octet - 192) << 8) + data[2] + 192
        elif length_octet == 255:
            if len(data) < 6:
                return None
            body_offset = 6
            body_length = int.from_bytes(data[2:6], "big")
        else:
            return None
    else:
        tag = (first >> 2) & 0x0F
        length_type = first & 0x03
        if length_type == 3:
            return None
        length_octets = 1 << length_type
        body_offset = 1 + length_octets
        if len(data) < body_offset:
            return None
        body_length = int.from_bytes(data[1:body_offset], "big")

    return tag, body_offset, body_length


def _openpgp_body_holds(data: bytes, body_offset: int, body_length: int, needed: int) -> bool:
    """Whether the first ``needed`` octets of the packet body are both declared
    by the packet and actually present in ``data``.

    The declared length is what separates this packet's body from whatever
    follows it in the stream: a field read past the declared end is not a field
    of this packet at all, so a packet that declares a body too short to hold
    the metadata the specification requires is malformed rather than evidence.
    """
    return body_length >= needed and len(data) >= body_offset + needed


def _describe_skesk(
    data: bytes, body_offset: int, body_length: int
) -> tuple[str, str] | None:
    """Structure description and observed symmetric algorithm for a version 4
    Symmetric-Key Encrypted Session Key packet, or None.

    RFC 4880 section 5.3 fixes the body as version, symmetric algorithm, then
    a string-to-key specifier whose own first two octets are its type and hash
    algorithm. Every one of those four octets must hold a value the
    specification defines, and the declared body length must be long enough to
    hold them and the rest of the specifier the type requires, so a file that
    merely happens to start with a plausible header octet does not match.
    """
    if not _openpgp_body_holds(data, body_offset, body_length, 4):
        return None
    version, symmetric_id, s2k_id, hash_id = data[body_offset : body_offset + 4]
    if version != 4:
        return None
    symmetric = _OPENPGP_SYMMETRIC_ALGORITHMS.get(symmetric_id)
    s2k = _OPENPGP_S2K_SPECIFIERS.get(s2k_id)
    if symmetric is None or s2k is None or hash_id not in _OPENPGP_HASH_ALGORITHM_IDS:
        return None
    # The salt (salted, iterated) and coded iteration count (iterated) are
    # required fields of the specifier. Their contents are arbitrary octets and
    # are never read or reported -- only their presence inside the declared body
    # is required, which is what rejects a packet whose declared length stops
    # short of the specifier it names.
    if not _openpgp_body_holds(
        data, body_offset, body_length, 2 + _OPENPGP_S2K_SPECIFIER_LENGTHS[s2k_id]
    ):
        return None
    return (
        f"symmetric-key encrypted session key packet (packet tag 3, version 4, "
        f"symmetric algorithm {symmetric}, {s2k} string-to-key specifier)",
        symmetric,
    )


def _describe_pkesk(
    data: bytes, body_offset: int, body_length: int
) -> tuple[str, str] | None:
    """Structure description and observed public-key algorithm for a version 3
    Public-Key Encrypted Session Key packet, or None.

    RFC 4880 section 5.1 fixes the body as version, an eight-octet key ID, then
    the public-key algorithm, then the algorithm-specific encrypted session key
    -- which is never empty, so the declared body must be longer than the ten
    octets read here. The key ID is read past, never reported: naming the
    recipient of an encrypted file is out of scope for HG-031.
    """
    if not _openpgp_body_holds(data, body_offset, body_length, 10):
        return None
    if body_length < _OPENPGP_PKESK_MIN_BODY_LENGTH:
        return None
    if data[body_offset] != 3:
        return None
    algorithm = _OPENPGP_PUBLIC_KEY_ALGORITHMS.get(data[body_offset + 9])
    if algorithm is None:
        return None
    return (
        f"public-key encrypted session key packet (packet tag 1, version 3, "
        f"public-key algorithm {algorithm})",
        algorithm,
    )


def _openpgp_encrypted_data_packet_follows(packet: bytes, offset: int) -> bool:
    """Whether a supported, complete encrypted-data packet begins at
    ``offset`` in ``packet`` (see the tag/version note above
    ``_OPENPGP_TAG_SEIPD``).

    A determinate header is required, exactly as for the session-key packet
    it follows, and its declared body must be fully present -- a header with
    nothing, or too little, after it is a truncated encrypted-data packet,
    not evidence of a complete one.
    """
    header = _openpgp_packet_header(packet[offset:])
    if header is None:
        return False
    tag, body_offset, body_length = header
    if body_length < 1:
        return False
    if offset + body_offset + body_length > len(packet):
        return False
    if tag == _OPENPGP_TAG_SEIPD:
        # The body is version octet + encrypted data; a body of exactly one
        # octet is only the version, with no encrypted-data payload at all,
        # so it is not a complete encrypted-data packet (Codex correction:
        # `SKESK + D2 01 01` was accepted with no payload beyond the version
        # byte).
        if body_length < 2:
            return False
        return packet[offset + body_offset] == _OPENPGP_SEIPD_VERSION
    if tag == _OPENPGP_TAG_SED:
        return True
    return False


def _openpgp_encrypted_evidence(data: bytes) -> tuple[str, str] | None:
    """``(evidence text, observed algorithm)`` for a supported OpenPGP
    encrypted-file structure at the start of ``data``, or None.

    Binary-safe and length-safe: every read is bounds-checked, so an empty,
    truncated, or arbitrary binary file returns None instead of raising. The
    evidence text states only what was directly read out of the packet
    header -- no strength, recoverability, or coverage claim.
    """
    armored = _openpgp_armor_body(data)
    packet = data if armored is None else armored

    header = _openpgp_packet_header(packet)
    if header is None:
        return None
    tag, body_offset, body_length = header
    # `packet` is the whole packet stream in both cases -- the whole binary file,
    # or the whole decoded armor body -- so a body declared to run past its end
    # is an inconsistent (truncated or over-declared) packet rather than
    # encrypted-file evidence, however it was encoded.
    if body_offset + body_length > len(packet):
        return None
    if tag == _OPENPGP_TAG_SKESK:
        described = _describe_skesk(packet, body_offset, body_length)
    elif tag == _OPENPGP_TAG_PKESK:
        described = _describe_pkesk(packet, body_offset, body_length)
    else:
        # Any other leading packet -- compressed data (what `gpg --armor
        # --sign` writes), a signature, a public or secret key packet -- is
        # not encrypted-file evidence.
        return None
    if described is None:
        return None
    # A session-key packet alone is not a supported encrypted message: a
    # complete, supported encrypted-data packet must immediately follow it
    # (HG-031 correction cycle 2, Blocker 1).
    if not _openpgp_encrypted_data_packet_follows(packet, body_offset + body_length):
        return None

    structure, algorithm = described
    if armored is None:
        return f"Observed OpenPGP {structure} in the file's leading bytes.", algorithm
    return (
        f"Observed ASCII-armored OpenPGP MESSAGE whose first decoded packet is a "
        f"{structure}.",
        algorithm,
    )


def _openpgp_encrypted_finding(
    file_path: Path, evidence: str, algorithm: str
) -> CryptoInventoryFinding:
    return CryptoInventoryFinding(
        asset_type="Encrypted File",
        location=str(file_path),
        # Read directly out of the packet header, not inferred. Key size is
        # deliberately left unset: the packet states which algorithm protects
        # the session key, and HG-031 makes no claim beyond that.
        algorithm=algorithm,
        evidence=evidence,
        confidence="High",
        rule_id="encrypted_file:openpgp",
    )


# --- age encrypted-file detection (HG-035) ----------------------------------
#
# Structural only, exactly like the OpenSSL and OpenPGP checks above: the
# native age v1 header is parsed just far enough to confirm the format's own
# grammar -- the version line, one or more recipient stanzas, the header MAC
# line's shape, and the presence of an encrypted payload -- and nothing read
# here is ever reported. The file is never decrypted, no identity file,
# passphrase, keyring, or SSH agent is consulted, and the `age` binary is never
# invoked.
#
# Deliberately narrow: only the native (binary) age v1 format, the shape `age
# -e` writes without `--armor`. ASCII-armored age files
# (`-----BEGIN AGE ENCRYPTED FILE-----`), non-v1 versions, and CRLF line
# endings are out of scope for HG-035 and are documented as false negatives in
# docs/DETECTION_CHARACTERIZATION.md rather than guessed at.
#
# Recipient stanzas are parsed for *shape* only. The recipient type and its
# arguments are read past, never interpreted, resolved, checked for usability,
# or emitted: HG-035 makes no claim about who can decrypt a file, and naming
# recipients would be identity output the privacy contract forbids.
_AGE_V1_VERSION_LINE = b"age-encryption.org/v1\n"
_AGE_STANZA_PREFIX = b"-> "
_AGE_HEADER_MAC_PREFIX = b"--- "
# The header MAC is an HMAC-SHA-256 (32 octets) written as unpadded base64,
# which is always exactly 43 characters. Only that shape is validated: verifying
# the MAC itself requires the file key, which would mean decryption.
_AGE_HEADER_MAC_LENGTH = 43
# age wraps a stanza body at 64 base64 characters per line, and a stanza's last
# body line is always shorter than that -- being short is what marks the end of
# the body.
_AGE_STANZA_BODY_LINE_LENGTH = 64
# The payload is a 16-octet header nonce followed by at least one STREAM chunk,
# and every chunk carries a 16-octet authentication tag, so the smallest
# possible payload (an empty plaintext) is 32 octets. Only the length is
# checked; the payload is never read, decrypted, stored, or emitted.
_AGE_MIN_PAYLOAD_BYTES = 32
# Unpadded base64 (the RFC 4648 standard alphabet with no `=` padding), the
# encoding age uses for stanza bodies and for the header MAC.
_AGE_BASE64_ALPHABET = frozenset(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
)


def _age_line(data: bytes, offset: int) -> tuple[bytes, int] | None:
    """The LF-terminated line beginning at ``offset`` and the offset just past
    it, or None when no LF follows.

    An unterminated final line is not a header line, which is what rejects a
    header truncated mid-line. Binary-safe: the line is returned as bytes and
    never decoded, so a file that only looks like an age header cannot raise.
    Requiring LF is also what rejects a CRLF native header -- the trailing CR
    is left on the line, where it fails every character check below.
    """
    end = data.find(b"\n", offset)
    if end == -1:
        return None
    return data[offset:end], end + 1


def _age_stanza_arguments_are_valid(line: bytes) -> bool:
    """Whether ``line`` is structurally an age recipient-stanza line: the
    literal ``-> `` prefix followed by one or more non-empty, space-separated
    printable arguments.

    Shape only. The first argument is the recipient type and the rest are its
    arguments; none of them is interpreted, resolved, validated as a usable
    recipient, or emitted.
    """
    arguments = line[len(_AGE_STANZA_PREFIX) :].split(b" ")
    if any(not argument for argument in arguments):
        return False
    return all(0x21 <= byte <= 0x7E for argument in arguments for byte in argument)


def _age_stanza_body_end(data: bytes, offset: int) -> int | None:
    """The offset just past the wrapped base64 stanza body beginning at
    ``offset``, or None when the body is absent or does not follow the format's
    wrapping rules.

    Every full line is exactly 64 unpadded-base64 characters and the final line
    is shorter, so a line that is longer, that carries a character outside the
    alphabet, or that never terminates rejects the stanza -- which is also what
    rejects a stanza whose body is missing entirely, since the next line would
    then be another stanza or the header MAC line and neither is base64.
    HG-035 additionally requires at least one body character.

    Body characters are validated and immediately discarded: the body is never
    decoded, stored, or emitted.
    """
    body_characters = 0
    while True:
        line_and_offset = _age_line(data, offset)
        if line_and_offset is None:
            return None
        line, offset = line_and_offset
        if len(line) > _AGE_STANZA_BODY_LINE_LENGTH:
            return None
        if any(byte not in _AGE_BASE64_ALPHABET for byte in line):
            return None
        body_characters += len(line)
        if len(line) < _AGE_STANZA_BODY_LINE_LENGTH:
            return offset if body_characters else None


def _age_v1_header_end(data: bytes) -> int | None:
    """The offset just past a complete native age v1 header at offset 0 of
    ``data``, or None when ``data`` does not begin with one.

    The whole grammar is required: the exact version line at byte offset 0, one
    or more syntactically valid recipient stanzas, and a header MAC line that is
    exactly ``--- `` plus 43 unpadded-base64 characters. Every line must be
    LF-terminated. A match is only ever at offset 0 -- an age header further
    into a file is not a match, because the format puts the version line first.
    """
    if not data.startswith(_AGE_V1_VERSION_LINE):
        return None

    offset = len(_AGE_V1_VERSION_LINE)
    stanzas = 0
    while True:
        line_and_offset = _age_line(data, offset)
        if line_and_offset is None:
            return None
        line, next_offset = line_and_offset

        if line.startswith(_AGE_HEADER_MAC_PREFIX):
            # The MAC line ends the header, so a header with no recipient stanza
            # in front of it is incomplete rather than a supported match.
            if not stanzas:
                return None
            mac = line[len(_AGE_HEADER_MAC_PREFIX) :]
            if len(mac) != _AGE_HEADER_MAC_LENGTH:
                return None
            if any(byte not in _AGE_BASE64_ALPHABET for byte in mac):
                return None
            return next_offset

        if not line.startswith(_AGE_STANZA_PREFIX):
            return None
        if not _age_stanza_arguments_are_valid(line):
            return None
        body_end = _age_stanza_body_end(data, next_offset)
        if body_end is None:
            return None
        offset = body_end
        stanzas += 1


def _looks_like_age_v1_encrypted_file(data: bytes) -> bool:
    """Whether ``data`` is a supported native age v1 encrypted file: a complete,
    structurally valid header at offset 0 followed immediately by an encrypted
    payload long enough to be one (see ``_AGE_MIN_PAYLOAD_BYTES``).

    Length-safe and binary-safe throughout, so an empty, truncated, or arbitrary
    binary file returns False instead of raising. The payload is never read,
    decrypted, or emitted -- only its length is measured.
    """
    header_end = _age_v1_header_end(data)
    if header_end is None:
        return False
    return len(data) - header_end >= _AGE_MIN_PAYLOAD_BYTES


def _age_encrypted_finding(file_path: Path) -> CryptoInventoryFinding:
    return CryptoInventoryFinding(
        asset_type="Encrypted File",
        location=str(file_path),
        evidence="Observed age encrypted file.",
        confidence="High",
        rule_id="encrypted_file:age",
    )


# --- gocryptfs cipher-root detection (HG-032) -------------------------------
#
# Structural only, exactly like the OpenSSL and OpenPGP checks above: this
# reads gocryptfs.conf's stable JSON fields (Version, FeatureFlags) to confirm
# a supported standard forward-mode root, and confirms EncryptedKey/
# ScryptObject are present without ever parsing their contents. No file is
# decrypted, mounted, or unlocked, no password is requested, and gocryptfs
# itself is never invoked. One finding is emitted per validated root
# directory -- never one per ciphertext file, encrypted directory, nested
# gocryptfs.diriv, or long-name sidecar.
#
# gocryptfs.conf has no persisted "this is reverse mode" flag: a forward-mode
# and a reverse-mode config are structurally identical JSON. What actually
# distinguishes them on disk is that forward mode physically writes a
# gocryptfs.diriv file to every real directory, including the root, while
# reverse mode computes directory IVs live from the plaintext side and never
# writes one anywhere -- there is nothing on-disk for a reverse root to
# collect. Requiring a root-level gocryptfs.diriv (mandatory below regardless)
# is therefore what excludes reverse-mode roots; there is no separate content
# check to make because the config content does not encode this distinction.
#
# Config version 2 is the only version validated here: it has been
# gocryptfs's on-disk format version continuously since v1.2, and HG-032
# explicitly does not claim support for versions this repository has not
# tested against. A version this scanner has not validated produces no
# finding rather than an unverified guess.
_GOCRYPTFS_CONFIG_FILENAME = "gocryptfs.conf"
_GOCRYPTFS_DIRIV_FILENAME = "gocryptfs.diriv"
_GOCRYPTFS_SUPPORTED_VERSIONS = frozenset({2})
# The minimum stable top-level fields every gocryptfs.conf has carried since
# format version 2. Presence is required; EncryptedKey/ScryptObject are
# checked for syntactic/structural plausibility only (valid base64, expected
# sub-keys, sane positive types) -- never for cryptographic correctness, and
# no value read from either one is ever returned, stored, or reported, since
# HG-032's privacy contract forbids reporting key material, salts, or KDF
# parameters.
_GOCRYPTFS_REQUIRED_CONFIG_FIELDS = ("Version", "FeatureFlags", "EncryptedKey", "ScryptObject")
# Presence of this feature flag means filenames are stored in plaintext
# rather than encrypted -- a materially different, unsupported mode HG-032
# must not claim as a standard forward-mode root.
_GOCRYPTFS_PLAINTEXTNAMES_FLAG = "PlaintextNames"
# The stable ScryptObject keys every real gocryptfs v2 config has (Salt plus
# the three scrypt cost parameters and the derived key length). Presence and
# type are checked -- Salt must be a non-empty base64 string, the numeric
# parameters must be positive integers -- but no value is validated as a
# *correct* or *safe* scrypt parameter: that would be cryptographic
# verification, which HG-032 explicitly does not attempt. Values are never
# read into a finding or reported.
_GOCRYPTFS_SCRYPT_OBJECT_INT_KEYS = ("N", "R", "P", "KeyLen")


def _gocryptfs_config_version(config: dict) -> int | None:
    """The supported gocryptfs config version ``config`` names, or None when
    ``config`` is missing a required stable field, names an unsupported
    version, has a malformed FeatureFlags list, enables PlaintextNames, or has
    a syntactically implausible EncryptedKey/ScryptObject.

    ``config`` must already be a decoded JSON object; this only validates its
    shape and content, never the file itself. Deliberately conservative: a
    config this narrow enough to accept on the smallest tested gocryptfs v2
    fixtures, not a permissive "looks roughly right" match -- a config with
    the right top-level keys but implausible values (an empty FeatureFlags
    list, non-base64 EncryptedKey, or an empty/incomplete ScryptObject) is
    not evidence of a real gocryptfs root and must not reach `High`
    confidence.
    """
    for required_field in _GOCRYPTFS_REQUIRED_CONFIG_FIELDS:
        if required_field not in config:
            return None

    version = config.get("Version")
    if isinstance(version, bool) or not isinstance(version, int):
        return None
    if version not in _GOCRYPTFS_SUPPORTED_VERSIONS:
        return None

    feature_flags = config.get("FeatureFlags")
    if (
        not isinstance(feature_flags, list)
        or not feature_flags
        or not all(isinstance(flag, str) for flag in feature_flags)
    ):
        return None
    if _GOCRYPTFS_PLAINTEXTNAMES_FLAG in feature_flags:
        return None

    if not _gocryptfs_encrypted_key_plausible(config.get("EncryptedKey")):
        return None
    if not _gocryptfs_scrypt_object_plausible(config.get("ScryptObject")):
        return None

    return version


def _gocryptfs_encrypted_key_plausible(encrypted_key: object) -> bool:
    """Whether ``encrypted_key`` is syntactically a real gocryptfs
    EncryptedKey: a non-empty string that is valid base64 decoding to at
    least one byte. The decoded value is discarded immediately -- never
    returned, stored, logged, or reported anywhere (HG-032's privacy
    contract forbids exposing key material)."""
    if not isinstance(encrypted_key, str) or not encrypted_key:
        return False
    try:
        decoded = base64.b64decode(encrypted_key, validate=True)
    except (ValueError, TypeError):
        return False
    return len(decoded) > 0


def _gocryptfs_scrypt_object_plausible(scrypt_object: object) -> bool:
    """Whether ``scrypt_object`` has the stable keys and structurally sane
    types a real gocryptfs v2 ScryptObject has -- never a judgment about
    whether the parameters are cryptographically safe (HG-032 does not
    attempt cryptographic verification), and no value from it is ever
    returned, stored, or reported."""
    if not isinstance(scrypt_object, dict):
        return False
    salt = scrypt_object.get("Salt")
    if not isinstance(salt, str) or not salt:
        return False
    try:
        if len(base64.b64decode(salt, validate=True)) == 0:
            return False
    except (ValueError, TypeError):
        return False
    for key in _GOCRYPTFS_SCRYPT_OBJECT_INT_KEYS:
        value = scrypt_object.get(key)
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            return False
    return True


def _gocryptfs_root_finding(context: RootContext) -> CryptoInventoryFinding | None:
    """A gocryptfs root finding for ``context``'s candidate root (the directory
    holding the ``gocryptfs.conf`` marker file the scanner discovered), or None
    when that directory is not a validated, supported forward-mode cipher root.

    The marker file's already-read bytes are decoded and validated here; nothing
    about them is reported beyond the derived version number. No directory is
    listed or walked: the only other path consulted is the fixed-name
    ``gocryptfs.diriv`` sibling in the same root.
    """
    config_path = context.marker_path
    # A regular file, not a symlink -- checked explicitly here (independent of
    # the caller's own symlink handling) because the structural contract
    # requires a *regular* file named exactly gocryptfs.conf.
    if config_path.is_symlink():
        return None

    # A copied/orphaned gocryptfs.conf with no root gocryptfs.diriv, and a
    # reverse-mode root (which never has one at all -- see module note above),
    # both stop here. `has_regular_sibling` requires a genuine regular file,
    # matching gocryptfs.conf's own check above rather than following a symlink.
    if not context.has_regular_sibling(_GOCRYPTFS_DIRIV_FILENAME):
        return None

    # gocryptfs.conf's own decode boundary, deliberately not the shared text
    # view: this is strict UTF-8 of the whole marker file, with no NUL
    # pre-filter and no ASCII fallback, because JSON parsing follows.
    data = context.marker.data
    if len(data) > MAX_TEXT_BYTES:
        return None
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    try:
        config = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(config, dict):
        return None

    version = _gocryptfs_config_version(config)
    if version is None:
        return None

    root_path = context.root_path
    return CryptoInventoryFinding(
        asset_type="Encrypted Filesystem",
        location=str(root_path),
        evidence="Observed supported gocryptfs cipher-root structure.",
        confidence="High",
        rule_id="encrypted_filesystem:gocryptfs",
        format="gocryptfs",
        config_version=version,
        mode="forward",
    )


# --- NSS SQL database-set detection (HG-041) --------------------------------
#
# One aggregate finding for one lexical directory that holds the supported
# canonical Mozilla NSS SQL database-set layout:
#
#   cert9.db  key4.db  pkcs11.txt
#
# The bounded evidence claim is exactly: *this lexical directory contains the
# supported canonical NSS SQL database-set layout and a structurally recognized
# NSS internal-module configuration stanza.* It is deliberately not a claim that
# either database is internally valid SQLite/NSS data, that any certificate or
# key exists, that a private key could be unlocked, that trust is correct, or
# that any application currently uses the directory.
#
# `pkcs11.txt` is the only marker. `cert9.db` and `key4.db` are fixed-name
# supporting siblings: presence/eligibility checked through
# `RootContext.has_eligible_regular_sibling` and never opened, read, parsed,
# locked, or counted as inspected files. Nothing here initializes NSS, loads a
# PKCS #11 module, uses sqlite3 (CLI, library, or Python module), runs certutil /
# modutil / pk12util, requests or reads a password, or resolves the marker's
# `configdir` value.
#
# Legacy DBM layouts (cert8.db/key3.db/secmod.db) and prefixed/renamed database
# sets are deliberate false negatives, as is a marker reached through a symlink:
# an alias to a pkcs11.txt is not aggregate-root evidence, with or without
# --follow-symlinks.
_NSS_MARKER_FILENAME = "pkcs11.txt"
_NSS_CERT_DB_FILENAME = "cert9.db"
_NSS_KEY_DB_FILENAME = "key4.db"

# The four record names one supported stanza must carry, keyed by their
# ASCII-lowercased spelling: field-name comparison is ASCII case-insensitive.
_NSS_RECORD_LIBRARY = "library"
_NSS_RECORD_NAME = "name"
_NSS_RECORD_PARAMETERS = "parameters"
_NSS_RECORD_NSS = "nss"
_NSS_REQUIRED_RECORDS = frozenset(
    {_NSS_RECORD_LIBRARY, _NSS_RECORD_NAME, _NSS_RECORD_PARAMETERS, _NSS_RECORD_NSS}
)

# The only two module names accepted, compared case-sensitively after trimming
# and collapsing internal ASCII whitespace runs to one space. The `#`-less
# spelling is accepted because both forms occur in the wild; no other name is.
_NSS_INTERNAL_MODULE_NAMES = frozenset(
    {"NSS Internal PKCS #11 Module", "NSS Internal PKCS 11 Module"}
)

# The exact `parameters=` key required, and the exact `NSS=` top-level argument
# and flag tokens required. All compared ASCII case-insensitively as whole
# tokens: `notconfigdir`, `myconfigdir`, `configdirectory`, `notinternal`, and
# `criticality` are not matches.
_NSS_CONFIGDIR_KEY = "configdir"
_NSS_FLAGS_KEY = "flags"
_NSS_REQUIRED_FLAGS = frozenset({"internal", "critical"})

# ASCII whitespace only -- str.strip() would also strip Unicode whitespace,
# which this grammar does not recognize.
_NSS_ASCII_WHITESPACE = " \t\n\r\v\f"
_NSS_INLINE_WHITESPACE = (" ", "\t")
_NSS_QUOTES = ("'", '"')
# The three delimiter pairs the NSS= top-level tokenizer tracks on one stack, so
# a cross-nested form such as `([)]` is malformed rather than tolerated.
_NSS_CLOSING_DELIMITERS = {")": "(", "}": "{", "]": "["}
_NSS_ASCII_LOWER = str.maketrans(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"
)
_NSS_WHITESPACE_RUN = re.compile("[ \t\v\f\r\n]+")


def _nss_ascii_lower(value: str) -> str:
    """``value`` with A-Z mapped to a-z and every other character untouched --
    ASCII case folding, not ``str.lower()``'s Unicode case folding, so no
    non-ASCII character can be folded into an accepted record name, parameter
    key, or flag token."""
    return value.translate(_NSS_ASCII_LOWER)


class _NssStanza:
    """One `library=`-rooted stanza being accumulated by the single-pass parser.

    ``rejected`` is set when a duplicate required record appears: the contract is
    explicit that a duplicate rejects the stanza rather than resolving
    first-wins or last-wins, even when both values are identical.
    """

    __slots__ = ("records", "rejected")

    def __init__(self, library_value: str):
        self.records: dict[str, str] = {_NSS_RECORD_LIBRARY: library_value}
        self.rejected = False

    def add(self, key: str, value: str) -> None:
        if key in self.records:
            self.rejected = True
            return
        self.records[key] = value


def _nss_marker_has_supported_internal_module(text: str) -> bool:
    """Whether ``text`` -- the marker's existing bounded text view -- contains at
    least one stanza satisfying the supported NSS internal-module grammar.

    One left-to-right pass, line-oriented, no recursive descent, no backtracking
    over earlier lines. Splitting on ``\\n`` and trimming ASCII whitespace is what
    accepts both LF and CRLF and a present-or-absent final newline; empty lines
    and ``#`` comment lines are ignored and never terminate a stanza; a
    ``library=`` record always starts a new one, even mid-stanza; and records
    before the first ``library=`` are discarded, so required records can never be
    assembled across stanzas.
    """
    stanza: _NssStanza | None = None
    for raw_line in text.split("\n"):
        line = raw_line.strip(_NSS_ASCII_WHITESPACE)
        if not line or line.startswith("#"):
            continue
        separator = line.find("=")
        if separator == -1:
            # Not a record at all under this grammar: ignored, and (like an
            # unknown record name) it cannot satisfy a required record.
            continue
        key = _nss_ascii_lower(line[:separator])
        value = line[separator + 1 :]
        if key == _NSS_RECORD_LIBRARY:
            if stanza is not None and _nss_stanza_matches(stanza):
                return True
            stanza = _NssStanza(value)
        elif stanza is not None and key in _NSS_REQUIRED_RECORDS:
            stanza.add(key, value)
        # Anything else -- an unknown record name, or any record before the first
        # `library=` -- is ignored.
    return stanza is not None and _nss_stanza_matches(stanza)


def _nss_stanza_matches(stanza: _NssStanza) -> bool:
    """Whether one accumulated stanza is the supported NSS internal-module
    stanza: every required record present exactly once, an empty ``library``
    value (a stanza naming an external library is a different thing and not
    recognized), one of the two approved module names, exactly one non-empty
    ``configdir`` parameter, and exactly one unquoted top-level ``Flags``
    argument carrying both ``internal`` and ``critical``."""
    if stanza.rejected:
        return False
    records = stanza.records
    if not _NSS_REQUIRED_RECORDS.issubset(records):
        return False
    if records[_NSS_RECORD_LIBRARY].strip(_NSS_ASCII_WHITESPACE):
        return False
    module_name = _NSS_WHITESPACE_RUN.sub(
        " ", records[_NSS_RECORD_NAME].strip(_NSS_ASCII_WHITESPACE)
    )
    if module_name not in _NSS_INTERNAL_MODULE_NAMES:
        return False
    if not _nss_parameters_have_configdir(records[_NSS_RECORD_PARAMETERS]):
        return False
    return _nss_arguments_have_required_flags(records[_NSS_RECORD_NSS])


def _nss_split_parameter_arguments(value: str) -> list[str] | None:
    """``parameters=``'s arguments, split on ASCII space or tab outside quotes,
    or None when a quote is left unmatched at end of value (which rejects the
    stanza).

    A quote opens a quoted region that the next occurrence of the same quote
    character closes -- there is no escape syntax, and backslash is an ordinary
    character. Quote characters are kept in the token here so the whole-value
    quoting rule can be checked on the argument that matters.
    """
    arguments: list[str] = []
    current: list[str] = []
    quote: str | None = None
    for char in value:
        if quote is not None:
            current.append(char)
            if char == quote:
                quote = None
            continue
        if char in _NSS_INLINE_WHITESPACE:
            if current:
                arguments.append("".join(current))
                current = []
            continue
        if char in _NSS_QUOTES:
            quote = char
        current.append(char)
    if quote is not None:
        return None
    if current:
        arguments.append("".join(current))
    return arguments


def _nss_unquote_whole_value(value: str) -> str | None:
    """``value`` with a matching outer quote pair removed, or None when it is a
    mixed quoted/unquoted form this grammar rejects.

    A quote may only enclose an **entire** value: it must begin immediately after
    the ``=`` and its match must be the final character, and (since no escape
    syntax exists) it cannot appear inside. ``abc'd ef'`` and ``'abc'd`` are
    therefore rejected rather than partially unquoted.
    """
    if not value:
        return value
    first = value[0]
    if first in _NSS_QUOTES:
        if len(value) < 2 or value[-1] != first or first in value[1:-1]:
            return None
        return value[1:-1]
    if any(quote in value for quote in _NSS_QUOTES):
        return None
    return value


def _nss_parameters_have_configdir(value: str) -> bool:
    """Whether ``parameters=`` carries exactly one exact-key ``configdir``
    argument with a non-empty normalized value.

    The value itself is opaque: it is not required to start with ``sql:``, not
    resolved, not expanded, not normalized to a filesystem path, not compared to
    the scanned root, not followed, and never emitted. Only its presence,
    uniqueness, and non-emptiness are evidence. Every other syntactically valid
    argument is ignored.
    """
    arguments = _nss_split_parameter_arguments(value)
    if arguments is None:
        return False
    configdir: str | None = None
    for argument in arguments:
        separator = argument.find("=")
        if separator == -1:
            continue
        if _nss_ascii_lower(argument[:separator]) != _NSS_CONFIGDIR_KEY:
            continue
        if configdir is not None:
            # A duplicate configdir rejects the stanza -- no first-wins or
            # last-wins resolution.
            return False
        unquoted = _nss_unquote_whole_value(argument[separator + 1 :])
        if unquoted is None:
            return False
        configdir = unquoted
    return bool(configdir)


def _nss_split_top_level_arguments(value: str) -> list[str] | None:
    """``NSS=``'s top-level arguments, or None when the value is malformed.

    One left-to-right pass with one quote state and one delimiter stack holding
    the exact opening characters of ``()``, ``{}``, and ``[]``. Top level means
    the quote state is none *and* the stack is empty, so only whitespace there
    splits arguments: whitespace inside quotes or inside any nesting stays part
    of the current argument, and a ``Flags=`` sequence inside either can never
    become a top-level argument.

    Malformed -- and therefore stanza-rejecting -- is a closing delimiter that
    does not match the most recent opening one (including cross-nested ``([)]``,
    ``{(})``, and ``[(])``), a closing delimiter with an empty stack, an
    unmatched quote at end of value, and a non-empty stack at end of value.
    Backslash has no escape meaning. Memory is bounded by the length of the
    already bounded marker text view.
    """
    arguments: list[str] = []
    current: list[str] = []
    quote: str | None = None
    stack: list[str] = []
    for char in value:
        if quote is not None:
            current.append(char)
            if char == quote:
                quote = None
            continue
        if char in _NSS_QUOTES:
            quote = char
            current.append(char)
            continue
        if char in _NSS_CLOSING_DELIMITERS:
            if not stack or stack[-1] != _NSS_CLOSING_DELIMITERS[char]:
                return None
            stack.pop()
            current.append(char)
            continue
        if char in ("(", "{", "["):
            stack.append(char)
            current.append(char)
            continue
        if char in _NSS_INLINE_WHITESPACE and not stack:
            if current:
                arguments.append("".join(current))
                current = []
            continue
        current.append(char)
    if quote is not None or stack:
        return None
    if current:
        arguments.append("".join(current))
    return arguments


def _nss_arguments_have_required_flags(value: str) -> bool:
    """Whether ``NSS=`` carries exactly one top-level ``Flags`` argument whose
    unquoted, comma-separated tokens include both ``internal`` and ``critical``.

    Quote characters are never stripped from a ``Flags`` value, so
    ``Flags="internal,critical"`` and ``Flags='internal,critical'`` do not
    satisfy this. Flag tokens are compared as whole tokens after trimming, so
    ``notinternal``, ``internally``, and ``criticality`` are not matches, while
    additional exact tokens alongside the two required ones are allowed. Other
    top-level arguments (``trustOrder``, ``cipherOrder``, ``slotParams``, ...)
    may appear in any order and are neither interpreted nor emitted.
    """
    arguments = _nss_split_top_level_arguments(value)
    if arguments is None:
        return False
    flags: frozenset[str] | None = None
    for argument in arguments:
        separator = argument.find("=")
        if separator == -1:
            continue
        if _nss_ascii_lower(argument[:separator]) != _NSS_FLAGS_KEY:
            continue
        if flags is not None:
            # A duplicate top-level Flags argument rejects the stanza.
            return False
        flags = frozenset(
            _nss_ascii_lower(token.strip(_NSS_ASCII_WHITESPACE))
            for token in argument[separator + 1 :].split(",")
        )
    return flags is not None and _NSS_REQUIRED_FLAGS.issubset(flags)


def _nss_sql_database_set_finding(
    context: RootContext,
) -> CryptoInventoryFinding | None:
    """The aggregate NSS finding for ``context``'s candidate root (the directory
    holding the ``pkcs11.txt`` marker the scanner discovered), or None when that
    directory is not a supported canonical NSS SQL database set.

    No directory is listed or walked, and the two supporting siblings are only
    presence/eligibility checked -- never opened, parsed, or validated. The
    marker's own already-read text view is the only content read.
    """
    marker_path = context.marker_path
    # A genuine regular file named exactly pkcs11.txt. Checked independently of
    # the caller's symlink policy: a symlink alias to a pkcs11.txt is not
    # aggregate-root evidence with --follow-symlinks, without it, or when scanned
    # directly.
    if marker_path.is_symlink() or not marker_path.is_file():
        return None

    # Both canonical databases must be present, in this same lexical directory,
    # as genuine regular non-symlink files the user did not exclude. Parent and
    # child directories are never searched for a missing component, and an
    # excluded sibling behaves exactly as a missing one.
    if not context.has_eligible_regular_sibling(_NSS_CERT_DB_FILENAME):
        return None
    if not context.has_eligible_regular_sibling(_NSS_KEY_DB_FILENAME):
        return None

    # The shared bounded text view: a marker too large to decode, binary, or
    # not decodable as UTF-8/ASCII has no text evidence and cannot match. The
    # physical read already happened for this candidate file; only the parsing
    # is bounded here.
    text = context.marker.text
    if text is None:
        return None
    if not _nss_marker_has_supported_internal_module(text):
        return None

    return CryptoInventoryFinding(
        asset_type="NSS Cryptographic Database Set",
        location=str(context.root_path),
        evidence="Supported NSS SQL database set detected",
        confidence="High",
        rule_id="nss:sql_database_set",
        format="NSS SQL",
    )


# --- BCFKS keystore detection (HG-036) --------------------------------------
#
# Structural only, exactly like the OpenSSL, OpenPGP, age, and gocryptfs checks
# above: the file's outer DER container is walked just far enough to confirm the
# Bouncy Castle `ObjectStore` shape the BCFKS provider writes, and nothing read
# here is ever reported. The store is never decrypted, no password is requested
# or accepted, no entry is enumerated, and Java, `keytool`, Bouncy Castle, and
# OpenSSL are never invoked.
#
# The supported shape, transcribed from the Bouncy Castle ASN.1 sources
# (`org.bouncycastle.asn1.bc.ObjectStore`, `EncryptedObjectStoreData`,
# `ObjectStoreIntegrityCheck`, `PbkdMacIntegrityCheck`) and confirmed against
# real stores written by the provider's `engineStore(OutputStream, char[])`
# path:
#
#   ObjectStore ::= SEQUENCE {
#       storeData        EncryptedObjectStoreData ::= SEQUENCE {
#           encryptionAlgorithm  AlgorithmIdentifier,
#           encryptedContent     OCTET STRING },
#       integrityCheck   PbkdMacIntegrityCheck ::= SEQUENCE {
#           macAlgorithm         AlgorithmIdentifier,
#           pbkdAlgorithm        AlgorithmIdentifier,
#           mac                  OCTET STRING } }
#
# Deliberately narrow. The unencrypted `ObjectStoreData` form and the
# signature-integrity form (an explicit `[0] SignatureCheck` in place of the
# PBKD MAC) are out of scope for HG-036 and produce no finding rather than a
# lower-confidence guess; both are documented as false negatives in
# docs/DETECTION_CHARACTERIZATION.md.
#
# What the outer container does *not* prove is equally load-bearing: entry
# aliases, entry types, certificates, and private-key material all live inside
# the encrypted store data, so a BCFKS finding is a container-structure
# observation and never a truststore-versus-keystore claim.

_DER_TAG_OCTET_STRING = 0x04
_DER_TAG_OBJECT_IDENTIFIER = 0x06
_DER_TAG_SEQUENCE = 0x30
# Identifier-octet fields: the two class bits, the constructed bit, and the low
# five bits holding the tag number (0x1F, the high-tag-number form, is rejected
# outright by the header reader below).
_DER_TAG_CLASS_MASK = 0xC0
_DER_TAG_CLASS_UNIVERSAL = 0x00
_DER_TAG_CONSTRUCTED = 0x20
_DER_TAG_NUMBER_MASK = 0x1F
# Universal tag numbers whose content encoding X.690 constrains, and which the
# primitive check below therefore validates. Numbers absent from this list --
# OCTET STRING, the string types, the time types -- carry content this reader
# deliberately does not interpret.
_DER_UNIVERSAL_END_OF_CONTENTS = 0x00
_DER_UNIVERSAL_BOOLEAN = 0x01
_DER_UNIVERSAL_INTEGER = 0x02
_DER_UNIVERSAL_BIT_STRING = 0x03
_DER_UNIVERSAL_NULL = 0x05
_DER_UNIVERSAL_OBJECT_IDENTIFIER = 0x06
_DER_UNIVERSAL_ENUMERATED = 0x0A
_DER_UNIVERSAL_RELATIVE_OID = 0x0D
_DER_UNIVERSAL_RESERVED = 0x0F
# The universal types X.690 encodes as constructed: EXTERNAL, EMBEDDED PDV,
# SEQUENCE, SET, and CHARACTER STRING. DER requires every other universal type,
# the string and time types included, to use the primitive form.
_DER_UNIVERSAL_CONSTRUCTED_TAG_NUMBERS = frozenset({0x08, 0x0B, 0x10, 0x11, 0x1D})
# DER admits exactly two BOOLEAN encodings, in one content octet.
_DER_BOOLEAN_CONTENT_LENGTH = 1
_DER_BOOLEAN_VALUES = frozenset({0x00, 0xFF})
# A BIT STRING's leading octet counts the unused bits in its final octet.
_DER_MAX_UNUSED_BITS = 7
# DER long-form length octets this reader accepts. Four octets addresses any
# file this scanner could read; a longer count is rejected rather than parsed,
# so a declared length can never exceed what the file itself can hold.
_DER_MAX_LENGTH_OCTETS = 4
# The identifier octet plus the largest length field above: the only prefix the
# cheap candidate gate needs to read.
_DER_MAX_HEADER_BYTES = 2 + _DER_MAX_LENGTH_OCTETS
# An AlgorithmIdentifier is an OID plus at most one parameters field.
_DER_ALGORITHM_IDENTIFIER_MAX_ELEMENTS = 2
# How deep the reader walks a constructed parameters field before treating the
# nesting itself as malformed. Real BCFKS parameters (PBES2/PBKDF2 and scrypt
# shapes) nest four or five levels; the bound is what keeps a hostile file from
# choosing this reader's recursion depth.
_DER_MAX_NESTING_DEPTH = 12
_BCFKS_ENCRYPTED_STORE_DATA_ELEMENTS = 2
_BCFKS_INTEGRITY_CHECK_ELEMENTS = 3
_BCFKS_OBJECT_STORE_ELEMENTS = 2


@dataclass(frozen=True)
class _DerElement:
    """One DER tag/length/value triple located inside an already-read buffer.

    Offsets only -- the value bytes are never copied out, decoded, or retained,
    which is what keeps the privacy boundary structural: there is no path from
    this reader to a finding field that could carry an ASN.1 fragment,
    ciphertext, MAC, salt, or KDF parameter.
    """

    tag: int
    content_start: int
    content_end: int

    @property
    def content_length(self) -> int:
        return self.content_end - self.content_start


def _der_header(data: bytes, offset: int, limit: int) -> tuple[int, int, int] | None:
    """``(tag, content offset, declared content length)`` for the DER element at
    ``offset``, or None when no well-formed definite-length header fits within
    ``limit``.

    Length-safe and binary-safe: every octet is bounds-checked before it is
    read, so a truncated or arbitrary binary file returns None instead of
    raising. Deliberately strict, because these rejections are what separate a
    real BCFKS store from a near-match:

    - a multi-byte (high) tag number is rejected -- nothing in the supported
      structure uses one;
    - the indefinite form (``0x80``) and the reserved form (``0xFF``) are
      rejected: neither is legal DER;
    - a long form declaring more than ``_DER_MAX_LENGTH_OCTETS`` octets is
      rejected rather than parsed;
    - the length must use its minimal encoding -- a padded or needlessly long
      form is a corrupted length, not a valid alternative spelling.
    """
    # The buffer's own end is always a limit, whatever the caller passed: the
    # candidate gate below reads a short prefix rather than the whole file, so
    # "fits within limit" must never be able to mean "past the end of `data`".
    limit = min(limit, len(data))
    if offset + 2 > limit:
        return None
    tag = data[offset]
    if tag & 0x1F == 0x1F:
        return None
    length_octet = data[offset + 1]
    content_start = offset + 2
    if length_octet < 0x80:
        return tag, content_start, length_octet
    count = length_octet & 0x7F
    if count == 0 or count > _DER_MAX_LENGTH_OCTETS:
        # 0x80 is the indefinite form and 0xFF is reserved; both are illegal in
        # DER, and a longer count could only declare a length no file here can
        # hold.
        return None
    content_start += count
    if content_start > limit:
        return None
    length = int.from_bytes(data[offset + 2 : content_start], "big")
    if data[offset + 2] == 0 or length < 0x80:
        # Non-minimal: a leading zero octet, or a long form used for a length
        # the short form encodes.
        return None
    return tag, content_start, length


def _der_read(data: bytes, offset: int, limit: int) -> _DerElement | None:
    """The complete DER element at ``offset``, or None when its header is
    malformed or its declared content runs past ``limit``.

    A declared length that overruns the buffer is what rejects a truncated store
    and a corrupted length octet alike: the element is not present, so it is not
    evidence.
    """
    limit = min(limit, len(data))
    header = _der_header(data, offset, limit)
    if header is None:
        return None
    tag, content_start, length = header
    content_end = content_start + length
    if content_end > limit:
        return None
    return _DerElement(tag, content_start, content_end)


def _der_children(data: bytes, element: _DerElement) -> list[_DerElement] | None:
    """The immediate children of a constructed ``element``, or None when its
    content is not an exact sequence of well-formed DER elements.

    Exact consumption is required: content left over after the last child, or a
    child whose declared length runs past the parent's own end, means the
    encoding is inconsistent rather than merely unfamiliar. Only one level is
    read per call, so validation walks the fixed, shallow BCFKS structure below
    and never recurses into the encrypted content.
    """
    children: list[_DerElement] = []
    offset = element.content_start
    while offset < element.content_end:
        child = _der_read(data, offset, element.content_end)
        if child is None:
            return None
        children.append(child)
        offset = child.content_end
    return children


def _der_has_valid_subidentifiers(data: bytes, element: _DerElement) -> bool:
    """Whether ``element``'s content is a sequence of complete, minimally
    encoded base-128 subidentifiers -- the encoding rule shared by
    OBJECT IDENTIFIER and RELATIVE-OID.

    Two rules do the work, and both are what separate a real identifier from
    arbitrary bytes wearing the tag:

    - every subidentifier must terminate, so the final content octet must have
      its continuation bit clear -- a payload ending mid-subidentifier (``0x80``
      alone, say) is malformed rather than merely unfamiliar;
    - no subidentifier may begin with ``0x80``, which is a leading zero group
      and therefore a non-minimal encoding DER forbids.

    The encoding is checked, never the value: which OID a store used is not
    decoded, compared against a table, or reported.
    """
    at_subidentifier_start = True
    for offset in range(element.content_start, element.content_end):
        octet = data[offset]
        if at_subidentifier_start and octet == 0x80:
            return False
        at_subidentifier_start = not octet & 0x80
    # True only if the last octet ended its subidentifier.
    return at_subidentifier_start


def _der_is_object_identifier(data: bytes, element: _DerElement) -> bool:
    """Whether ``element`` is a well-formed, non-empty OBJECT IDENTIFIER."""
    if element.tag != _DER_TAG_OBJECT_IDENTIFIER or element.content_length == 0:
        return False
    return _der_has_valid_subidentifiers(data, element)


def _der_is_minimal_integer(data: bytes, element: _DerElement) -> bool:
    """Whether an INTEGER or ENUMERATED element uses DER's minimal two's
    complement encoding: at least one content octet, and no redundant leading
    padding octet.

    A leading ``0x00`` is legal only to clear a high bit that would otherwise
    make the value negative, and a leading ``0xFF`` only to set one. Any other
    leading octet is padding, which DER forbids -- the magnitude itself is
    never decoded or reported.
    """
    if element.content_length == 0:
        return False
    if element.content_length == 1:
        return True
    first = data[element.content_start]
    second = data[element.content_start + 1]
    return not (first == 0x00 and not second & 0x80) and not (first == 0xFF and second & 0x80)


def _der_is_bit_string(data: bytes, element: _DerElement) -> bool:
    """Whether a BIT STRING element is encoded as DER requires: a leading
    unused-bit count of at most seven, zero when the string is empty, and unused
    trailing bits actually set to zero. The bits themselves are never read as a
    value."""
    if element.content_length == 0:
        return False
    unused = data[element.content_start]
    if unused > _DER_MAX_UNUSED_BITS:
        return False
    if element.content_length == 1:
        return unused == 0
    return not data[element.content_end - 1] & ((1 << unused) - 1)


def _der_has_valid_tag_form(element: _DerElement) -> bool:
    """Whether ``element``'s identifier octet uses the form its tag permits.

    Only the universal class is constrained: a context, application, or private
    tag means whatever the enclosing specification says it means, and HG-036
    interprets no parameters field. Within the universal class, DER fixes which
    types are constructed and which are primitive, so a constructed OCTET STRING
    or a primitive SEQUENCE is a corrupted encoding. End-of-contents and the
    reserved number never appear as elements at all.
    """
    if element.tag & _DER_TAG_CLASS_MASK != _DER_TAG_CLASS_UNIVERSAL:
        return True
    number = element.tag & _DER_TAG_NUMBER_MASK
    if number in (_DER_UNIVERSAL_END_OF_CONTENTS, _DER_UNIVERSAL_RESERVED):
        return False
    constructed = bool(element.tag & _DER_TAG_CONSTRUCTED)
    return constructed == (number in _DER_UNIVERSAL_CONSTRUCTED_TAG_NUMBERS)


def _der_is_valid_primitive(data: bytes, element: _DerElement) -> bool:
    """Whether a primitive ``element`` carries content its universal tag allows.

    ``_der_read`` proves only that a primitive's header parsed and its declared
    content fits inside its parent -- it says nothing about whether the content
    is legal for that tag. A NULL with content octets, a two-octet BOOLEAN, a
    BOOLEAN holding ``0x01``, a zero-length INTEGER, and a padded one are all
    length-consistent and all invalid DER, and none of them may help a
    near-match earn a High-confidence BCFKS finding.

    Bounded: each check reads at most the element's own content octets, and no
    content octet is decoded into a value or retained. Tags outside the
    universal class, and universal types whose content DER does not constrain
    (OCTET STRING, the string and time types), are accepted on their length
    alone -- this reader interprets no parameters field.
    """
    if element.tag & _DER_TAG_CLASS_MASK != _DER_TAG_CLASS_UNIVERSAL:
        return True
    number = element.tag & _DER_TAG_NUMBER_MASK
    if number == _DER_UNIVERSAL_BOOLEAN:
        return (
            element.content_length == _DER_BOOLEAN_CONTENT_LENGTH
            and data[element.content_start] in _DER_BOOLEAN_VALUES
        )
    if number in (_DER_UNIVERSAL_INTEGER, _DER_UNIVERSAL_ENUMERATED):
        return _der_is_minimal_integer(data, element)
    if number == _DER_UNIVERSAL_BIT_STRING:
        return _der_is_bit_string(data, element)
    if number == _DER_UNIVERSAL_NULL:
        return element.content_length == 0
    if number in (_DER_UNIVERSAL_OBJECT_IDENTIFIER, _DER_UNIVERSAL_RELATIVE_OID):
        return element.content_length > 0 and _der_has_valid_subidentifiers(data, element)
    return True


def _der_is_well_formed(data: bytes, element: _DerElement, depth: int = 0) -> bool:
    """Whether ``element`` and everything nested inside it is well-formed DER.

    Two gaps ``_der_read`` leaves open, both of which would otherwise let a
    store carrying malformed DER inside its encryption, MAC, or KDF parameters
    earn a High-confidence finding:

    - a constructed element's content is itself a sequence of DER elements that
      ``_der_read`` never looked at, so a SEQUENCE whose own length is
      consistent while its children are truncated passes the header check and
      must be rejected here;
    - a primitive element's content is never checked against what its tag
      permits, so a nonempty NULL or an invalid BOOLEAN is equally
      length-consistent and equally malformed.

    Nesting deeper than ``_DER_MAX_NESTING_DEPTH`` is treated as not
    well-formed rather than walked: nothing in the supported structure needs
    that depth. Structure only -- no content octet is decoded or retained.
    """
    if not _der_has_valid_tag_form(element):
        return False
    if not element.tag & _DER_TAG_CONSTRUCTED:
        return _der_is_valid_primitive(data, element)
    if depth >= _DER_MAX_NESTING_DEPTH:
        return False
    children = _der_children(data, element)
    if children is None:
        return False
    return all(_der_is_well_formed(data, child, depth + 1) for child in children)


def _der_is_algorithm_identifier(data: bytes, element: _DerElement) -> bool:
    """Whether ``element`` is structurally an X.509 ``AlgorithmIdentifier``: a
    SEQUENCE whose first child is a well-formed OBJECT IDENTIFIER, followed by
    at most one parameters element that is itself well-formed DER.

    Shape only. The OID's value is never decoded, compared against a table, or
    reported, and the parameters field is never interpreted -- HG-036 claims
    the container's structure, not which cipher, MAC, or key-derivation
    function a particular store happened to use, nor which salt, iteration
    count, or IV it carries. But an uninterpreted field still has to be
    *encoded* correctly: parameters holding truncated or inconsistent nested
    DER make the file a near-match, not a supported store.
    """
    if element.tag != _DER_TAG_SEQUENCE:
        return False
    children = _der_children(data, element)
    if children is None:
        return False
    if not 1 <= len(children) <= _DER_ALGORITHM_IDENTIFIER_MAX_ELEMENTS:
        return False
    if not _der_is_object_identifier(data, children[0]):
        return False
    return all(_der_is_well_formed(data, parameters) for parameters in children[1:])


def _der_is_non_empty_octet_string(element: _DerElement) -> bool:
    """Whether ``element`` is a non-empty OCTET STRING. The octets themselves
    are never read: an empty encrypted-content or MAC field is a malformed
    store, and a populated one is only ever measured."""
    return element.tag == _DER_TAG_OCTET_STRING and element.content_length > 0


def _is_bcfks_encrypted_object_store_data(data: bytes, element: _DerElement) -> bool:
    """Whether ``element`` matches Bouncy Castle's ``EncryptedObjectStoreData``:
    a SEQUENCE of exactly an ``AlgorithmIdentifier`` and a non-empty
    OCTET STRING of encrypted content.

    Requiring the first child to itself be an AlgorithmIdentifier is what
    separates this from the same two-element shape an
    ``EncryptedPrivateKeyInfo`` has, and requiring exactly two children is what
    rejects the unsupported unencrypted ``ObjectStoreData`` form, whose first
    child is a version INTEGER.
    """
    if element.tag != _DER_TAG_SEQUENCE:
        return False
    children = _der_children(data, element)
    if children is None or len(children) != _BCFKS_ENCRYPTED_STORE_DATA_ELEMENTS:
        return False
    return _der_is_algorithm_identifier(data, children[0]) and _der_is_non_empty_octet_string(
        children[1]
    )


def _is_bcfks_pbkd_mac_integrity_check(data: bytes, element: _DerElement) -> bool:
    """Whether ``element`` matches Bouncy Castle's ``PbkdMacIntegrityCheck``: a
    SEQUENCE of exactly a MAC ``AlgorithmIdentifier``, a key-derivation-function
    identifier (itself AlgorithmIdentifier-shaped), and a non-empty MAC
    OCTET STRING.

    The alternative ``ObjectStoreIntegrityCheck`` arm -- an explicit ``[0]``
    context tag holding a ``SignatureCheck`` -- fails the SEQUENCE requirement
    here, which is exactly how the unsupported signature-integrity form produces
    no finding.
    """
    if element.tag != _DER_TAG_SEQUENCE:
        return False
    children = _der_children(data, element)
    if children is None or len(children) != _BCFKS_INTEGRITY_CHECK_ELEMENTS:
        return False
    return (
        _der_is_algorithm_identifier(data, children[0])
        and _der_is_algorithm_identifier(data, children[1])
        and _der_is_non_empty_octet_string(children[2])
    )


def _looks_like_bcfks_object_store(data: bytes) -> bool:
    """Whether ``data`` is a supported BCFKS ``ObjectStore``: a complete DER
    SEQUENCE beginning at byte offset 0, consuming the whole file with no
    trailing bytes, holding exactly an ``EncryptedObjectStoreData`` and a
    ``PbkdMacIntegrityCheck``.

    Content only -- never the filename, the extension, entropy, or file size.
    Offset 0 and full consumption are both required, so supported BCFKS bytes
    embedded at a nonzero offset in some larger file are not a match: the format
    puts the store's own SEQUENCE header first and nothing after its end.

    Length-safe and binary-safe throughout, so an empty, truncated, or arbitrary
    binary file returns False instead of raising.
    """
    store = _der_read(data, 0, len(data))
    if store is None or store.tag != _DER_TAG_SEQUENCE:
        return False
    if store.content_end != len(data):
        return False
    elements = _der_children(data, store)
    if elements is None or len(elements) != _BCFKS_OBJECT_STORE_ELEMENTS:
        return False
    store_data, integrity_check = elements
    return _is_bcfks_encrypted_object_store_data(
        data, store_data
    ) and _is_bcfks_pbkd_mac_integrity_check(data, integrity_check)


def _bcfks_finding(file_path: Path) -> CryptoInventoryFinding:
    return CryptoInventoryFinding(
        asset_type="Java Keystore",
        location=str(file_path),
        evidence="Observed supported BCFKS keystore structure.",
        confidence="High",
        rule_id="java_keystore:bcfks",
        format="BCFKS",
    )


# --- JCEKS keystore detection (HG-037) --------------------------------------
#
# Header-structure only, and deliberately smaller than the BCFKS reader above:
# the file's fixed 12-byte top-level header is read, its declared version and
# entry count are range-checked, and the file's own length is checked against
# the minimum a JCEKS store can occupy. Nothing read here is ever reported. No
# password is requested or accepted, the keyed SHA-1 digest is neither
# recomputed nor verified nor reported, no entry record is parsed, no Java
# object is instantiated or deserialized, and `java`, `keytool`, and every other
# external process are never invoked.
#
# The supported shape, transcribed from OpenJDK's `JceKeyStore`
# (`com.sun.crypto.provider.JceKeyStore`, `engineLoad`/`engineStore`/
# `engineProbe`):
#
#   magic        uint32be = 0xCECECECE   (JKS, by contrast, uses 0xFEEDFEED)
#   version      int32be  in {1, 2}
#   entry count  int32be  >= 0
#   ... entry records ...
#   digest       20-byte keyed SHA-1 over the store
#
# OpenJDK's own `engineProbe()` identifies a JCEKS stream from the magic value
# alone. HG-037 adds the version, count, and length checks on top of that so a
# near-match is rejected, and stops there: `engineLoad()` goes on to deserialize
# `SealedObject` data for secret-key entries, and reproducing that merely to
# name the container would be both unnecessary and unsafe.
#
# What the header does *not* prove is why confidence is Medium rather than High:
# aliases, entry types, certificates, secret keys, and private-key material all
# live in the entry records this detector does not read, so a JCEKS finding is a
# container-header observation and never a keystore-versus-truststore claim, an
# entry claim, or an authenticated-store claim.

_JCEKS_MAGIC = b"\xce\xce\xce\xce"
_JCEKS_SUPPORTED_VERSIONS = frozenset({1, 2})
# magic + version + entry count, the fixed prefix every JCEKS store begins with.
_JCEKS_HEADER_BYTES = 12
# The trailing keyed SHA-1 digest `engineStore` appends. Its length is the only
# thing used here -- the digest itself is never read, recomputed, verified, or
# reported, all of which would require the store password.
_JCEKS_DIGEST_BYTES = 20
# The smallest a JCEKS store can be: the fixed header plus that digest, which is
# exactly the size of an empty store written by keytool.
_JCEKS_MIN_BYTES = _JCEKS_HEADER_BYTES + _JCEKS_DIGEST_BYTES


def _looks_like_jceks_keystore(data: bytes) -> bool:
    """Whether ``data`` has the JCEKS top-level header and a plausible container
    length.

    Content only -- the filename and extension are not consulted, so a
    ``.jceks`` name is never evidence and misleading ``.p12``/``.der``/``.jks``
    bytes are classified by what they are. Length-safe and binary-safe: an
    empty, truncated, or arbitrary binary file returns False instead of raising.

    Five conditions, each of which is what rejects one class of near-match:

    1. enough bytes for the fixed top-level header;
    2. the big-endian JCEKS magic at offset 0, which is what separates JCEKS
       from JKS (``0xFEEDFEED``) and from a binary that merely resembles it;
    3. a supported format version, 1 or 2;
    4. a nonnegative signed 32-bit entry count;
    5. a file large enough to hold the header and the trailing integrity
       material, which rejects an obviously truncated container.

    Deliberately not checked: the digest is not verified (that needs the store
    password), and no entry record is parsed. Both are out of scope, and the
    residual false-positive room they leave is why the finding is Medium
    confidence.
    """
    if len(data) < _JCEKS_HEADER_BYTES:
        return False
    if data[:4] != _JCEKS_MAGIC:
        return False
    version = int.from_bytes(data[4:8], "big", signed=True)
    if version not in _JCEKS_SUPPORTED_VERSIONS:
        return False
    # Signed, exactly as `DataInputStream.readInt()` reads it: a top bit set is a
    # negative count, which no store `engineStore` wrote can have.
    entry_count = int.from_bytes(data[8:12], "big", signed=True)
    if entry_count < 0:
        return False
    return len(data) >= _JCEKS_MIN_BYTES


def _jceks_finding(file_path: Path) -> CryptoInventoryFinding:
    return CryptoInventoryFinding(
        asset_type="Java Keystore",
        location=str(file_path),
        evidence="JCEKS keystore header detected",
        confidence="Medium",
        rule_id="java_keystore:jceks",
        format="JCEKS",
    )


# --- Encrypted PKCS#8 private-key detection (HG-038) ------------------------
#
# PKCS#8 `EncryptedPrivateKeyInfo` (RFC 5958) is exactly two fields:
#
#     EncryptedPrivateKeyInfo ::= SEQUENCE {
#         encryptionAlgorithm  AlgorithmIdentifier,
#         encryptedData        OCTET STRING
#     }
#
# The claim HG-038 makes is that this outer structure is present, and nothing
# more. The encrypted bytes are opaque: they are never decrypted, and never
# read as anything but a length. No password is requested, accepted, read from
# the environment, guessed, or derived; `serialization.load_pem_private_key` and
# every other key-loading API is deliberately not consulted, so a failed load's
# exception is never the detection signal; and `openssl`, `java`, `keytool`, and
# every other external process are never invoked.
#
# The outer AlgorithmIdentifier describes the cipher, KDF, salt, IV, and
# iteration count the writer chose. It is validated as DER and then discarded --
# none of those values, and no OID, reaches a finding. The only format-specific
# metadata the detector emits is `Format: PKCS#8`.
#
# The DER reader is the one BCFKS already uses (`_der_read`, `_der_children`,
# `_der_is_algorithm_identifier`, `_der_is_non_empty_octet_string`), unchanged:
# bounded nesting, definite and minimally encoded lengths only, no high-tag-
# number expansion, no unbounded allocation, and no recursion into the encrypted
# OCTET STRING. Malformed or truncated input returns False rather than raising.

_PKCS8_ENCRYPTED_PEM_LABEL = "ENCRYPTED PRIVATE KEY"
_PKCS8_ENCRYPTED_PEM_BEGIN = f"-----BEGIN {_PKCS8_ENCRYPTED_PEM_LABEL}-----"
_PKCS8_ENCRYPTED_PEM_END = f"-----END {_PKCS8_ENCRYPTED_PEM_LABEL}-----"
_PKCS8_ENCRYPTED_ELEMENTS = 2


def _looks_like_encrypted_pkcs8(data: bytes) -> bool:
    """Whether ``data`` is a complete DER ``EncryptedPrivateKeyInfo``: a
    SEQUENCE beginning at byte offset 0, consuming the whole buffer with no
    trailing bytes, holding exactly an ``AlgorithmIdentifier`` and a non-empty
    primitive OCTET STRING.

    Content only -- never the filename, the extension, entropy, or file size.
    Offset 0 and full consumption are both required, so encrypted PKCS#8 bytes
    embedded at a nonzero offset inside some larger file are not a match.

    Length-safe and binary-safe throughout, so an empty, truncated, or arbitrary
    binary buffer returns False instead of raising. The constructed OCTET STRING
    form is rejected by ``_der_is_non_empty_octet_string``, which compares the
    full identifier octet, and the indefinite and non-minimal length forms are
    rejected by ``_der_header``.
    """
    outer = _der_read(data, 0, len(data))
    if outer is None or outer.tag != _DER_TAG_SEQUENCE:
        return False
    if outer.content_end != len(data):
        return False
    elements = _der_children(data, outer)
    if elements is None or len(elements) != _PKCS8_ENCRYPTED_ELEMENTS:
        return False
    algorithm, encrypted_data = elements
    return _der_is_algorithm_identifier(data, algorithm) and _der_is_non_empty_octet_string(
        encrypted_data
    )


def _pkcs8_encrypted_pem_bodies(text: str) -> list[bytes]:
    """The decoded DER body of every complete, well-formed
    ``ENCRYPTED PRIVATE KEY`` PEM block in ``text``.

    A block counts only when both labels appear as **exact boundary lines** --
    the line, with only leading/trailing whitespace stripped, equals the label
    exactly, so ``prefix-----BEGIN ENCRYPTED PRIVATE KEY-----`` or
    ``-----END ENCRYPTED PRIVATE KEY-----suffix`` is not a boundary and cannot
    start or close a block. ``str.splitlines()`` recognizes LF, CRLF, and bare
    CR line endings alike, so this is not tied to one line-ending convention.
    Unrelated text on its own lines before, between, or after a block is still
    fine -- it is simply never a boundary line.

    A block also counts only when the base64 between the boundaries decodes
    under strict validation -- a header with no footer, a truncated block, or
    an invalid base64 body yields nothing, so a malformed PEM cannot reach the
    structural check and cannot earn a High-confidence finding. ``text`` is the
    scanner's existing bounded text view (see ``decode_text``), so this adds no
    new size boundary.

    The decoded bytes are returned for structural validation only; they are
    never retained in a finding.
    """
    lines = text.splitlines()
    bodies: list[bytes] = []
    index = 0
    while index < len(lines):
        if lines[index].strip() != _PKCS8_ENCRYPTED_PEM_BEGIN:
            index += 1
            continue
        end_index = None
        for candidate in range(index + 1, len(lines)):
            if lines[candidate].strip() == _PKCS8_ENCRYPTED_PEM_END:
                end_index = candidate
                break
        if end_index is None:
            # A header with no matching footer is an incomplete block, not an
            # encrypted private key.
            return bodies
        body = "".join("".join(lines[index + 1 : end_index]).split())
        index = end_index + 1
        if not body:
            continue
        try:
            bodies.append(base64.b64decode(body, validate=True))
        except (ValueError, binascii.Error):
            # Invalid base64 is a malformed block, which produces no finding.
            continue
    return bodies


def _pkcs8_encrypted_finding(file_path: Path) -> CryptoInventoryFinding:
    return CryptoInventoryFinding(
        asset_type="Encrypted PKCS#8 Private Key",
        location=str(file_path),
        evidence="Encrypted PKCS#8 private-key structure detected",
        confidence="High",
        rule_id="private_key:pkcs8_encrypted",
        format="PKCS#8",
    )


# --- CMS / PKCS#7 encrypted-object detection (HG-039) -----------------------
#
# RFC 5652 wraps every CMS content type in one outer structure:
#
#     ContentInfo ::= SEQUENCE {
#         contentType  ContentType,
#         content      [0] EXPLICIT ANY DEFINED BY contentType }
#
# HG-039 supports exactly two contentType values, `id-envelopedData` and
# `id-encryptedData`, and validates the structure each one carries:
#
#     EnvelopedData ::= SEQUENCE {
#         version              CMSVersion,
#         originatorInfo   [0] IMPLICIT OriginatorInfo OPTIONAL,
#         recipientInfos       RecipientInfos,
#         encryptedContentInfo EncryptedContentInfo,
#         unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL }
#
#     EncryptedData ::= SEQUENCE {
#         version              CMSVersion,
#         encryptedContentInfo EncryptedContentInfo,
#         unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL }
#
#     EncryptedContentInfo ::= SEQUENCE {
#         contentType                 ContentType,
#         contentEncryptionAlgorithm  AlgorithmIdentifier,
#         encryptedContent        [0] IMPLICIT OCTET STRING OPTIONAL }
#
# The claim is that this structure is present and carries embedded encrypted
# bytes, and nothing more. Which recipients exist, whether their certificates
# are valid, who can decrypt, whether a signature verifies, and which cipher,
# KDF, salt, or IV was chosen are all outside it: recipient infos are checked
# for presence and well-formedness and never decoded, and the encrypted content
# is only ever measured. No password, private key, secret key, or recipient
# certificate is requested or accepted, nothing is decrypted, no signature is
# verified, no certificate or chain is validated, `openssl` and every other
# external process are never invoked, and no network call is made.
#
# Two distinctions do the separating work, and both are structural:
#
#   - the outer OID must be *exactly* one of the two supported values, so a
#     PKCS#7 certificate bundle, a degenerate or ordinary SignedData, a CMS
#     Data object, and a DigestedData object are all valid ContentInfos that
#     produce no finding -- the `CMS`/`PKCS7` label and the CMS container shape
#     are never themselves evidence of encryption;
#   - `encryptedContent` must be present and non-empty, so a detached object
#     (whose ciphertext lives elsewhere) is a deliberate false negative rather
#     than a claim about bytes this scanner never saw.
#
# The DER reader is the one BCFKS and encrypted PKCS#8 already use, unchanged:
# definite and minimally encoded lengths only, bounded nesting, no high-tag-
# number expansion, no unbounded allocation, and no recursion into the
# encrypted content. Indefinite-length (streaming) BER CMS is therefore outside
# the supported subset and fails closed; that boundary is documented in
# docs/DETECTION_CHARACTERIZATION.md rather than closed by weakening the reader.
#
# The two content types are distinguished by `asset_type`, `rule_id`, and
# evidence wording rather than by a new metadata field: the only format-specific
# metadata either rule emits is `Format: CMS/PKCS#7`. Adding a generic
# `Content Type` field would have put a new key into every existing
# crypto-inventory finding's technical metadata and JSON export, which is a
# change to established report semantics that HG-039 does not need -- the issue
# permits exactly this alternative.

_DER_TAG_INTEGER = 0x02
_DER_TAG_SET = 0x31
# Context-specific class, constructed: the explicit `[0]` ContentInfo wrapper
# and the implicit `[0]`/`[1]` optional fields inside the CMS structures.
_DER_TAG_CONTEXT_0_CONSTRUCTED = 0xA0
_DER_TAG_CONTEXT_1_CONSTRUCTED = 0xA1
# Context-specific class, primitive: `encryptedContent`, an implicitly tagged
# OCTET STRING, which DER requires to be primitive. The constructed (chunked)
# BER form is outside the supported subset.
_DER_TAG_CONTEXT_0_PRIMITIVE = 0x80

# The two supported `contentType` values, as their DER OID content octets:
# id-envelopedData (1.2.840.113549.1.7.3) and id-encryptedData
# (1.2.840.113549.1.7.6). Compared as bytes, used internally only -- neither
# these values nor any OID read from a scanned file is ever emitted.
_CMS_OID_ENVELOPED_DATA = bytes((0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x03))
_CMS_OID_ENCRYPTED_DATA = bytes((0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x06))

# Internal content-type discriminators. They select which finding to build; they
# are not a metadata value and are never written into a finding.
_CMS_ENVELOPED_DATA = "EnvelopedData"
_CMS_ENCRYPTED_DATA = "EncryptedData"

_CMS_CONTENT_INFO_ELEMENTS = 2
_CMS_CONTENT_WRAPPER_ELEMENTS = 1
_CMS_ENCRYPTED_CONTENT_INFO_ELEMENTS = 3
# RFC 5652 fixes EncryptedData's version: 0 with no unprotected attributes, 2
# when they are present.
_CMS_ENCRYPTED_DATA_VERSION_WITHOUT_ATTRIBUTES = 0
_CMS_ENCRYPTED_DATA_VERSION_WITH_ATTRIBUTES = 2
_CMS_VERSION_CONTENT_LENGTH = 1

# The RFC 7468 textual labels that carry a CMS `ContentInfo`. Both are accepted;
# neither is evidence of anything on its own, since the decoded body still has
# to pass the full structural check below.
_CMS_PEM_LABELS = ("CMS", "PKCS7")
_CMS_PEM_BEGIN_LINES = {f"-----BEGIN {label}-----": label for label in _CMS_PEM_LABELS}


def _der_oid_equals(data: bytes, element: _DerElement, oid: bytes) -> bool:
    """Whether ``element`` is a well-formed OBJECT IDENTIFIER whose content
    octets are exactly ``oid``.

    A byte comparison against a fixed constant, not a decode: the identifier is
    never turned into a dotted string, looked up in a table, retained, or
    reported. An OID that merely starts with the supported arc, or that carries
    extra octets, is a different identifier and does not match.
    """
    if not _der_is_object_identifier(data, element):
        return False
    return data[element.content_start : element.content_end] == oid


def _cms_encrypted_content_info_valid(data: bytes, element: _DerElement) -> bool:
    """Whether ``element`` is a supported ``EncryptedContentInfo``: a SEQUENCE of
    exactly a content-type OBJECT IDENTIFIER, an ``AlgorithmIdentifier``, and a
    present, non-empty ``[0]`` ``encryptedContent``.

    All three fields are required. The inner content type and the content-
    encryption algorithm are validated as encodings and then discarded -- which
    cipher, mode, KDF, salt, IV, or nonce a writer chose is never decoded or
    reported. The ciphertext is measured, never read: an empty
    ``encryptedContent`` is a malformed object, and an absent one is a detached
    object, and neither is a match.
    """
    if element.tag != _DER_TAG_SEQUENCE:
        return False
    children = _der_children(data, element)
    if children is None or len(children) != _CMS_ENCRYPTED_CONTENT_INFO_ELEMENTS:
        return False
    content_type, algorithm, encrypted_content = children
    if not _der_is_object_identifier(data, content_type):
        return False
    if not _der_is_algorithm_identifier(data, algorithm):
        return False
    if encrypted_content.tag != _DER_TAG_CONTEXT_0_PRIMITIVE:
        return False
    return encrypted_content.content_length > 0


def _cms_enveloped_data_valid(data: bytes, element: _DerElement) -> bool:
    """Whether ``element`` is a supported ``EnvelopedData`` body.

    The fields are walked in the order RFC 5652 declares them: a minimally
    encoded INTEGER version, an optional implicit ``[0]`` ``originatorInfo``, a
    non-empty ``RecipientInfos`` SET, an ``EncryptedContentInfo``, and an
    optional implicit ``[1]`` ``unprotectedAttrs``. Nothing may follow.

    ``RecipientInfos`` is checked for being a constructed SET holding at least
    one well-formed element and is deliberately not decoded further: recipient
    identities, issuer and serial numbers, subject key identifiers, encrypted
    content-encryption keys, KEK and password-recipient details, and originator
    certificates are all things this detector must never read into a finding,
    and the cheapest way to guarantee that is not to parse them at all.
    """
    if element.tag != _DER_TAG_SEQUENCE:
        return False
    children = _der_children(data, element)
    if children is None:
        return False
    index = 0
    if index >= len(children) or not _cms_version_valid(data, children[index]):
        return False
    index += 1
    if index < len(children) and children[index].tag == _DER_TAG_CONTEXT_0_CONSTRUCTED:
        # originatorInfo: permitted, and never interpreted.
        index += 1
    if index >= len(children) or children[index].tag != _DER_TAG_SET:
        return False
    recipients = _der_children(data, children[index])
    if not recipients:
        # None (the SET's content is not an exact sequence of DER elements) or
        # empty (RecipientInfos is SIZE (1..MAX)).
        return False
    index += 1
    if index >= len(children) or not _cms_encrypted_content_info_valid(
        data, children[index]
    ):
        return False
    index += 1
    if index < len(children) and children[index].tag == _DER_TAG_CONTEXT_1_CONSTRUCTED:
        # unprotectedAttrs: permitted, and never interpreted.
        index += 1
    return index == len(children)


def _cms_encrypted_data_valid(data: bytes, element: _DerElement) -> bool:
    """Whether ``element`` is a supported ``EncryptedData`` body: a minimally
    encoded INTEGER version, an ``EncryptedContentInfo``, and an optional
    implicit ``[1]`` ``unprotectedAttrs``, with nothing following.

    RFC 5652 fixes the version against the presence of those attributes -- 0
    without them, 2 with them -- so the two are checked together. The version is
    the one value this detector compares rather than merely validates, and it is
    not reported either.
    """
    if element.tag != _DER_TAG_SEQUENCE:
        return False
    children = _der_children(data, element)
    if children is None:
        return False
    index = 0
    if index >= len(children) or not _cms_version_valid(data, children[index]):
        return False
    version = children[index]
    index += 1
    if index >= len(children) or not _cms_encrypted_content_info_valid(
        data, children[index]
    ):
        return False
    index += 1
    has_attributes = (
        index < len(children) and children[index].tag == _DER_TAG_CONTEXT_1_CONSTRUCTED
    )
    if has_attributes:
        index += 1
    if index != len(children):
        return False
    expected = (
        _CMS_ENCRYPTED_DATA_VERSION_WITH_ATTRIBUTES
        if has_attributes
        else _CMS_ENCRYPTED_DATA_VERSION_WITHOUT_ATTRIBUTES
    )
    return (
        version.content_length == _CMS_VERSION_CONTENT_LENGTH
        and data[version.content_start] == expected
    )


def _cms_version_valid(data: bytes, element: _DerElement) -> bool:
    """Whether ``element`` is a minimally encoded INTEGER, the encoding every
    ``CMSVersion`` field uses. The magnitude is not read here -- only
    ``EncryptedData`` constrains its version value, and it does so itself."""
    return element.tag == _DER_TAG_INTEGER and _der_is_minimal_integer(data, element)


def _cms_encrypted_content_type(data: bytes) -> str | None:
    """Which supported CMS encrypted-content type ``data`` is a complete
    ``ContentInfo`` for, or None.

    Content only -- never the filename, the extension, entropy, or file size.
    Offset 0 and full consumption are both required, so a supported CMS object
    embedded at a nonzero offset inside a larger binary file is not a match: the
    format puts the ContentInfo's own SEQUENCE header first and nothing after
    its end.

    Length-safe and binary-safe throughout, so an empty, truncated, or arbitrary
    binary buffer returns None instead of raising.
    """
    outer = _der_read(data, 0, len(data))
    if outer is None or outer.tag != _DER_TAG_SEQUENCE:
        return None
    if outer.content_end != len(data):
        return None
    children = _der_children(data, outer)
    if children is None or len(children) != _CMS_CONTENT_INFO_ELEMENTS:
        return None
    content_type, wrapper = children
    if wrapper.tag != _DER_TAG_CONTEXT_0_CONSTRUCTED:
        return None
    wrapped = _der_children(data, wrapper)
    if wrapped is None or len(wrapped) != _CMS_CONTENT_WRAPPER_ELEMENTS:
        return None
    content = wrapped[0]
    if content.tag != _DER_TAG_SEQUENCE:
        return None
    if _der_oid_equals(data, content_type, _CMS_OID_ENVELOPED_DATA):
        return _CMS_ENVELOPED_DATA if _cms_enveloped_data_valid(data, content) else None
    if _der_oid_equals(data, content_type, _CMS_OID_ENCRYPTED_DATA):
        return _CMS_ENCRYPTED_DATA if _cms_encrypted_data_valid(data, content) else None
    # Every other content type -- id-data, id-signedData, id-digestedData,
    # id-authenticatedData, and anything else -- is a valid ContentInfo that is
    # not encrypted-content evidence.
    return None


def _cms_pem_bodies(text: str) -> list[bytes]:
    """The decoded body of every complete, well-formed ``CMS`` or ``PKCS7`` PEM
    block in ``text``.

    The same hardened boundary rules HG-038 established for encrypted PKCS#8: a
    block counts only when both labels appear as **exact boundary lines** -- the
    line, with only leading/trailing whitespace stripped, equals the label
    exactly -- so ``prefix-----BEGIN CMS-----`` or ``-----END CMS-----suffix``
    is not a boundary and can neither open nor close a block. The BEGIN and END
    labels must be the *same* label, so a ``CMS`` header closed by a ``PKCS7``
    footer is an incomplete block rather than a match.
    ``str.splitlines()`` recognizes LF, CRLF, and bare CR line endings alike, so
    this is not tied to one line-ending convention, and unrelated explanatory
    text on its own lines before, between, or after a block is simply never a
    boundary line.

    A block also counts only when the base64 between the boundaries decodes
    under strict validation, so a header with no footer, a truncated block, or
    an invalid base64 body yields nothing and cannot reach the structural check.
    ``text`` is the scanner's existing bounded text view (see ``decode_text``),
    so this adds no new size boundary.

    The decoded bytes are returned for structural validation only; they are
    never retained in a finding.
    """
    lines = text.splitlines()
    bodies: list[bytes] = []
    index = 0
    while index < len(lines):
        label = _CMS_PEM_BEGIN_LINES.get(lines[index].strip())
        if label is None:
            index += 1
            continue
        end_line = f"-----END {label}-----"
        end_index = None
        for candidate in range(index + 1, len(lines)):
            if lines[candidate].strip() == end_line:
                end_index = candidate
                break
        if end_index is None:
            # A header with no matching footer is an incomplete block, not a
            # CMS object.
            return bodies
        body = "".join("".join(lines[index + 1 : end_index]).split())
        index = end_index + 1
        if not body:
            continue
        try:
            bodies.append(base64.b64decode(body, validate=True))
        except (ValueError, binascii.Error):
            # Invalid base64 is a malformed block, which produces no finding.
            continue
    return bodies


def _cms_content_types(context: FileContext) -> list[str]:
    """Every supported CMS encrypted-content type observed in one file: from the
    file's own bytes read as binary DER, and from each complete textual
    ``CMS``/``PKCS7`` block it carries.

    Both encodings are checked in one pass so the two rule detectors share the
    work and neither reads the file again -- the bytes and the text view both
    come from the shared context's single read.
    """
    observed: list[str] = []
    content_type = _cms_encrypted_content_type(context.data)
    if content_type is not None:
        observed.append(content_type)
    text = context.text
    if text is not None:
        observed.extend(
            found
            for found in (
                _cms_encrypted_content_type(body) for body in _cms_pem_bodies(text)
            )
            if found is not None
        )
    return observed


def _cms_enveloped_data_finding(file_path: Path) -> CryptoInventoryFinding:
    return CryptoInventoryFinding(
        asset_type="CMS/PKCS#7 Enveloped Data",
        location=str(file_path),
        evidence="CMS/PKCS#7 EnvelopedData encrypted-content structure detected",
        confidence="High",
        rule_id="cms:enveloped_data",
        format="CMS/PKCS#7",
    )


def _cms_encrypted_data_finding(file_path: Path) -> CryptoInventoryFinding:
    return CryptoInventoryFinding(
        asset_type="CMS/PKCS#7 Encrypted Data",
        location=str(file_path),
        evidence="CMS/PKCS#7 EncryptedData encrypted-content structure detected",
        confidence="High",
        rule_id="cms:encrypted_data",
        format="CMS/PKCS#7",
    )



# --- Legacy encrypted PEM private-key detection (HG-040) --------------------
#
# Traditional OpenSSL-style encrypted PEM private keys:
#
#     -----BEGIN RSA PRIVATE KEY-----
#     Proc-Type: 4,ENCRYPTED
#     DEK-Info: <cipher>,<hex-IV>
#
#     <base64 ciphertext>
#     -----END RSA PRIVATE KEY-----
#
# Same form for DSA/EC. Claim is structural only: complete traditional
# private-key PEM block with Proc-Type: 4,ENCRYPTED, valid DEK-Info, and
# non-empty strict-base64 body. No password, decryption, key-load API, or
# external process. Replaces the pre-HG-040 exception-driven path for these
# blocks. Encrypted PKCS#8 remains HG-038; OpenSSH remains its own path.

_LEGACY_ENCRYPTED_PEM_LABELS = ("RSA PRIVATE KEY", "DSA PRIVATE KEY", "EC PRIVATE KEY")
_LEGACY_PROC_TYPE_VALUE = "4,ENCRYPTED"
_HEX_IV_CHARS = frozenset("0123456789abcdefABCDEF")


def _legacy_pem_header_lines(block_lines: list[str]) -> tuple[list[str], list[str]] | None:
    if not block_lines:
        return None
    lines = list(block_lines)
    while lines and lines[-1] == "":
        lines.pop()
    if not lines:
        return None
    blank = None
    for index, line in enumerate(lines):
        if line.strip() == "":
            blank = index
            break
    if blank is None:
        return None
    headers = [line.strip() for line in lines[:blank] if line.strip()]
    body_lines = [line.strip() for line in lines[blank + 1 :] if line.strip()]
    return headers, body_lines


def _legacy_proc_type_ok(headers: list[str]) -> bool:
    values = []
    for line in headers:
        if line.lower().startswith("proc-type:"):
            values.append(line.split(":", 1)[1].strip())
    return len(values) == 1 and values[0] == _LEGACY_PROC_TYPE_VALUE


def _legacy_dek_info_ok(headers: list[str]) -> bool:
    values = []
    for line in headers:
        if line.lower().startswith("dek-info:"):
            values.append(line.split(":", 1)[1].strip())
    if len(values) != 1:
        return False
    value = values[0]
    if any(ch in value for ch in ("\n", "\r", "\x00")):
        return False
    if value.count(",") != 1:
        return False
    cipher, iv = value.split(",", 1)
    if not cipher or any(ch.isspace() for ch in cipher):
        return False
    if not iv or len(iv) % 2 != 0:
        return False
    return all(ch in _HEX_IV_CHARS for ch in iv)


def _legacy_encrypted_pem_body_ok(body_lines: list[str]) -> bool:
    if not body_lines:
        return False
    body = "".join(body_lines)
    if not body:
        return False
    try:
        decoded = base64.b64decode(body, validate=True)
    except (ValueError, binascii.Error):
        return False
    return len(decoded) > 0


def _looks_like_legacy_encrypted_pem_block(block_lines: list[str]) -> bool:
    parts = _legacy_pem_header_lines(block_lines)
    if parts is None:
        return False
    headers, body_lines = parts
    return (
        _legacy_proc_type_ok(headers)
        and _legacy_dek_info_ok(headers)
        and _legacy_encrypted_pem_body_ok(body_lines)
    )


def _block_owned_by_legacy_encrypted_pem(block: str) -> bool:
    """True when a full traditional PEM private-key block is HG-040-owned.

    Shared ownership predicate used by both the dedicated detector path and
    the generic ``_parse_pem_private_keys`` skip. Header *names* (``Proc-Type``,
    ``DEK-Info``) are matched case-insensitively, matching the detector grammar,
    so a block the detector accepts cannot also fall through to a contradictory
    ``PEM Private Key`` / ``Encrypted PEM Private Key`` / ``Malformed …``
    finding. Only structurally complete HG-040 blocks return True; partial or
    invalid headers are left for other paths.
    """
    lines = block.splitlines()
    if not lines:
        return False
    interior = list(lines)
    if interior and interior[0].strip().startswith("-----BEGIN "):
        interior = interior[1:]
    if interior and interior[-1].strip().startswith("-----END "):
        interior = interior[:-1]
    return _looks_like_legacy_encrypted_pem_block(interior)


def _legacy_encrypted_pem_blocks(text: str) -> list[list[str]]:
    """Interior lines of complete traditional encrypted PEM blocks.

    Exact boundary lines only (HG-038 style): prefix/suffix contamination is
    rejected; BEGIN/END labels must match; LF and CRLF are accepted.
    """
    lines = text.splitlines()
    blocks: list[list[str]] = []
    index = 0
    begin_by_line = {
        f"-----BEGIN {label}-----": label for label in _LEGACY_ENCRYPTED_PEM_LABELS
    }
    while index < len(lines):
        label = begin_by_line.get(lines[index].strip())
        if label is None:
            index += 1
            continue
        end_line = f"-----END {label}-----"
        end_index = None
        for candidate in range(index + 1, len(lines)):
            if lines[candidate].strip() == end_line:
                end_index = candidate
                break
        if end_index is None:
            return blocks
        interior = lines[index + 1 : end_index]
        index = end_index + 1
        if _looks_like_legacy_encrypted_pem_block(interior):
            blocks.append(interior)
    return blocks


def _legacy_encrypted_pem_finding(file_path: Path) -> CryptoInventoryFinding:
    return CryptoInventoryFinding(
        asset_type="Encrypted Legacy PEM Private Key",
        location=str(file_path),
        evidence="Legacy PEM encrypted private-key structure detected",
        confidence="High",
        rule_id="private_key:legacy_pem_encrypted",
        format="Legacy PEM",
    )


# --- Detector registry (HG-033) --------------------------------------------
#
# The static, explicit registry of every crypto-inventory detector family. It
# adds no detection capability: each entry wraps a check this scanner already
# performed, in the order it already performed them, and `priority` is what
# makes the intentional precedence between them a declaration rather than the
# order of `if` statements in one function.
#
# Precedence that is intentional and load-bearing (each covered by a regression
# test):
#
#   10 OpenSSL Salted__ ahead of every extension-based branch, so a Salted__
#      file saved as secret.p12 is Encrypted File evidence rather than a
#      malformed PKCS#12 (HG-030).
#   20 OpenPGP structure ahead of the same branches *and* ahead of the shared
#      candidate gate, since a binary OpenPGP file has no recognized extension
#      and no "-----BEGIN " text for the gate to admit it by (HG-031).
#   25 age encrypted file ahead of the same branches and the gate, for the same
#      reason: a native age file has no recognized extension and no
#      "-----BEGIN " text, and valid age content saved as secret.p12 must be
#      classified from its content rather than as a malformed container
#      (HG-035).
#   30 gocryptfs root ahead of the file-format branches and the gate for the
#      same reason -- gocryptfs.conf is plain JSON -- and terminal for its
#      marker file either way, so a rejected marker never falls through into
#      PEM/DER/PKCS#12 parsing (HG-032).
#   31 NSS SQL database set immediately after the gocryptfs root and ahead of
#      every file-format branch and the shared gate: pkcs11.txt is plain text
#      with no recognized extension and no "-----BEGIN " content. Unlike
#      gocryptfs it declares `owns_marker=False`, so only a *validated* root is
#      terminal for the marker; a rejected pkcs11.txt falls through so a
#      defensible certificate or private key inside it is still reported
#      (HG-041).
#   35 BCFKS ahead of JKS, PKCS#12, and DER, and ahead of the shared gate: a
#      BCFKS store is structurally identified from its own bytes, so a valid
#      store saved as truststore.p12 or certs.der must be classified as the
#      keystore it is rather than as a malformed PKCS#12 or DER certificate
#      (HG-036).
#   37 JCEKS ahead of JKS, PKCS#12, and DER, and ahead of the shared gate, for
#      the same reason as BCFKS: a JCEKS store is identified from its own
#      header, so a valid store named `store`, `store.bin`, `truststore.p12`,
#      or `certs.der` must be classified as the keystore it is rather than
#      missed by the extension gate or reported as a malformed PKCS#12 or DER
#      certificate. Distinct from JKS at 40, which is a different format with a
#      different magic and keeps its own detector and rule id (HG-037).
#   45 Encrypted PKCS#8 ahead of PKCS#12 and DER, and ahead of the shared gate,
#      for the same reason again: an EncryptedPrivateKeyInfo is identified from
#      its own structure, so a valid encrypted key named `key`, `key.bin`,
#      `key.p8`, `key.der`, `key.crt`, or `key.p12` must be classified from its
#      content rather than missed by the extension gate or reported as a
#      malformed DER certificate or PKCS#12. The issue that added it (HG-038)
#      suggested 55, between PKCS#12 and DER; 45 is the narrow adjustment the
#      registry mechanics require, because `pkcs12:container` claims a `.p12` or
#      `.pfx` file terminally on its *extension* alone, and the required
#      misleading-extension coverage includes exactly those two names. No real
#      PKCS#12 file is taken from it: a PFX's first element is a version
#      INTEGER, which can never satisfy the AlgorithmIdentifier requirement
#      here, and this detector reads no extension at all (HG-038).
#   46/47 The two CMS/PKCS#7 encrypted-object rules, after the keystore and
#      encrypted-PKCS#8 detectors and ahead of extension-gated PKCS#12, generic
#      DER certificate parsing, and generic PEM handling, and ahead of the
#      shared gate: a supported ContentInfo is identified from its own bytes, so
#      a valid object named `message`, `message.bin`, `message.p7m`,
#      `message.p7b`, `message.der`, `message.cer`, or `message.p12` must be
#      classified from its content rather than missed by the extension gate or
#      reported as a malformed DER certificate or PKCS#12. No real PKCS#12,
#      keystore, or encrypted PKCS#8 file is taken from the detectors above:
#      each requires an outer content type or element shape a CMS ContentInfo
#      cannot have, and neither CMS detector reads an extension at all. The two
#      run in the recommended semantic order, EnvelopedData before EncryptedData,
#      and both share one structural pass over the file (HG-039). A single
#      binary file's outer content type can only be one or the other, but a
#      textual file may carry a separate block of each -- both are supported
#      content types, so both claims must survive even though the priority-46
#      detector is terminal: it reports the EncryptedData finding itself
#      alongside its own whenever the shared pass observed both, since the
#      dispatch loop would otherwise never reach cms:encrypted_data's own
#      detect() for that file.
#   40-60 JKS, encrypted PKCS#8, CMS, PKCS#12, and DER: mutually exclusive in
#      practice, but each terminal for the file it claims, which is what keeps a
#      keystore or container from also being read as PEM text.
#   70 certificate:pem -- non-terminal text detector for CERTIFICATE blocks.
#   75 private_key:legacy_pem_encrypted -- traditional Proc-Type/DEK-Info
#      encrypted PEM private keys (HG-040), non-terminal, after certificate PEM
#      and before generic private-key PEM, without changing PKCS#12, encrypted
#      PKCS#8, or CMS. Exact BEGIN/END boundaries, validated Proc-Type/DEK-Info,
#      and non-empty strict-base64 body; no password or decryption.
#   80-90 Remaining text detectors (generic PEM private keys, SSH public keys),
#      deliberately non-terminal: one PEM file may legitimately hold a
#      certificate, a private key, and an SSH public key, and all three are
#      reported.
#
# Detectors that are terminal stop further matching for that file; non-terminal
# detectors (certificate PEM, legacy encrypted PEM, private-key PEM, SSH public
# key) may coexist. Nothing here relies on a general "first detector wins" rule.


def _openssl_candidate(context: FileContext) -> bool:
    return _looks_like_openssl_salted(
        context.leading_bytes(len(_OPENSSL_SALTED_SIGNATURE))
    )


def _detect_openssl_salted(context: FileContext) -> DetectionResult:
    return DetectionResult.match([_openssl_salted_finding(context.path)])


def _openpgp_candidate(context: FileContext) -> bool:
    """The cheap leading-byte gate for the OpenPGP detector, equivalent to the
    conditions ``_openpgp_encrypted_evidence`` itself requires before it can
    return anything: either a first octet with bit 7 set (the start of any
    OpenPGP packet header, with at least one length octet after it) or the
    literal ASCII-armor MESSAGE header. A file matching neither could only ever
    produce None, so skipping it changes no result."""
    leading = context.leading_bytes(len(_OPENPGP_ARMOR_HEADER))
    if leading.startswith(_OPENPGP_ARMOR_HEADER):
        return True
    return len(leading) >= 2 and bool(leading[0] & 0x80)


def _detect_openpgp_encrypted(context: FileContext) -> DetectionResult:
    # The full bytes are required, not a prefix: the declared-length check that
    # rejects a truncated or over-declared packet is only meaningful against the
    # complete packet stream (see _openpgp_encrypted_evidence).
    evidence = _openpgp_encrypted_evidence(context.data)
    if evidence is None:
        return DetectionResult.no_match()
    return DetectionResult.match([_openpgp_encrypted_finding(context.path, *evidence)])


def _age_candidate(context: FileContext) -> bool:
    """The cheap leading-byte gate for the age detector: the exact native age v1
    version line at byte offset 0, which is the one condition
    ``_looks_like_age_v1_encrypted_file`` itself requires before it can return
    True. Content only -- never the filename, the extension, entropy, or a
    broader text heuristic."""
    return context.leading_bytes(len(_AGE_V1_VERSION_LINE)) == _AGE_V1_VERSION_LINE


def _detect_age_encrypted(context: FileContext) -> DetectionResult:
    # The full bytes are required, not a prefix: the header runs to its MAC line
    # and the payload-length check is only meaningful against the whole file.
    if not _looks_like_age_v1_encrypted_file(context.data):
        return DetectionResult.no_match()
    return DetectionResult.match([_age_encrypted_finding(context.path)])


def _detect_gocryptfs_root(context: RootContext) -> DetectionResult:
    finding = _gocryptfs_root_finding(context)
    if finding is None:
        # A file literally named gocryptfs.conf that failed root validation
        # (missing sibling diriv, malformed/empty/unsupported config, reverse
        # or plaintextnames mode) is not a supported cipher root and not
        # evidence of any other crypto asset type either -- this detector owns
        # it, terminally, rather than letting it fall through into the
        # PEM/DER/PKCS#12 detectors.
        return DetectionResult.claim()
    return DetectionResult.match([finding])


def _detect_nss_sql_database_set(context: RootContext) -> DetectionResult:
    finding = _nss_sql_database_set_finding(context)
    if finding is None:
        # Conditional ownership (HG-041): unlike the gocryptfs root detector,
        # this one does not own a file merely because it is named pkcs11.txt. A
        # rejected marker is a normal non-match, so later detectors still get to
        # inspect it -- an arbitrary pkcs11.txt holding a supported certificate
        # or private key must not have that defensible evidence suppressed.
        return DetectionResult.no_match()
    # A validated root, by contrast, is terminal for its marker: the aggregate
    # finding is the NSS evidence for this directory, and the marker must not
    # also be reported as some other asset.
    return DetectionResult.match([finding], terminal=True)


def _bcfks_candidate(context: FileContext) -> bool:
    """The cheap binary gate for the BCFKS detector: the file begins with a
    well-formed definite-length DER SEQUENCE header whose declared content ends
    exactly at the end of the file.

    That is the one condition ``_looks_like_bcfks_object_store`` requires before
    it can return True, so a file failing it could only ever produce a non-match
    -- which is what keeps every ordinary file (text, an archive, an image, a
    PEM bundle) out of the ASN.1 path below after reading at most six bytes and
    comparing one length. Content only: the extension is not consulted at all,
    here or in the detector, so it is never evidence and a ``.bcfks`` name alone
    cannot produce a finding.
    """
    prefix = context.leading_bytes(_DER_MAX_HEADER_BYTES)
    header = _der_header(prefix, 0, len(prefix))
    if header is None:
        return False
    tag, content_start, length = header
    return tag == _DER_TAG_SEQUENCE and content_start + length == len(context.data)


def _detect_bcfks(context: FileContext) -> DetectionResult:
    # The full bytes are required, not a prefix: the structure runs to the end of
    # the file, and the "no trailing bytes" requirement is only meaningful
    # against the whole file.
    if not _looks_like_bcfks_object_store(context.data):
        return DetectionResult.no_match()
    return DetectionResult.match([_bcfks_finding(context.path)])


def _jceks_candidate(context: FileContext) -> bool:
    """The cheap leading-byte gate for the JCEKS detector: the JCEKS magic at
    offset 0.

    That is the one condition ``_looks_like_jceks_keystore`` requires before it
    can return True, so a file failing it could only ever produce a non-match --
    and it costs four bytes. Content only, and deliberately not behind
    ``_passes_candidate_gate``: that gate admits files by extension, so a valid
    store named ``store`` or ``store.bin`` would never reach this detector.
    Neither this predicate nor the detector consults the extension at all, so a
    ``.jceks`` name alone cannot produce a finding.
    """
    return context.leading_bytes(len(_JCEKS_MAGIC)) == _JCEKS_MAGIC


def _detect_jceks(context: FileContext) -> DetectionResult:
    # The full bytes are required, not a prefix: the minimum-size check is a
    # statement about the whole file. The bytes are already in the shared
    # context, so this is not an extra read.
    if not _looks_like_jceks_keystore(context.data):
        return DetectionResult.no_match()
    return DetectionResult.match([_jceks_finding(context.path)])


def _pkcs8_encrypted_candidate(context: FileContext) -> bool:
    """The cheap gate for the encrypted-PKCS#8 detector: either the file begins
    with a definite-length DER SEQUENCE header whose declared content ends
    exactly at the end of the file (the DER form), or its text view contains the
    exact ``ENCRYPTED PRIVATE KEY`` opening label (the PEM form).

    Those are the only two shapes ``_detect_pkcs8_encrypted`` can match, so a
    file failing both could only ever produce a non-match. Content only: the
    extension is not consulted here or in the detector, so a ``.p8``, ``.pk8``,
    ``.key``, ``.der``, or ``.pem`` name alone can never produce a finding, and
    a valid key named ``key`` or ``key.bin`` is still classified from its bytes.
    Deliberately not behind ``_passes_candidate_gate``, which admits files by
    extension and would drop exactly those unextensioned DER keys.
    """
    prefix = context.leading_bytes(_DER_MAX_HEADER_BYTES)
    header = _der_header(prefix, 0, len(prefix))
    if header is not None:
        tag, content_start, length = header
        if tag == _DER_TAG_SEQUENCE and content_start + length == len(context.data):
            return True
    text = context.text
    return text is not None and _PKCS8_ENCRYPTED_PEM_BEGIN in text


def _detect_pkcs8_encrypted(context: FileContext) -> DetectionResult:
    # The full bytes are required, not a prefix: the structure runs to the end of
    # the file and the "no trailing bytes" requirement is only meaningful against
    # the whole file. The bytes are already in the shared context, so this is not
    # an extra read.
    if _looks_like_encrypted_pkcs8(context.data):
        return DetectionResult.match([_pkcs8_encrypted_finding(context.path)])
    text = context.text
    if text is not None and any(
        _looks_like_encrypted_pkcs8(body) for body in _pkcs8_encrypted_pem_bodies(text)
    ):
        # One finding per file, not per block: several encrypted PKCS#8 blocks in
        # one file are one encrypted-private-key container asset at one location,
        # and the finding carries no per-block detail that could distinguish them.
        return DetectionResult.match([_pkcs8_encrypted_finding(context.path)])
    return DetectionResult.no_match()


# Where the shared CMS structural pass caches its result for one file, so the
# two CMS rule detectors validate the same bytes once between them rather than
# once each.
_CMS_MEMO_KEY = "cms_content_types"


def _cms_candidate(context: FileContext) -> bool:
    """The cheap gate for both CMS detectors: either the file begins with a
    definite-length DER SEQUENCE header whose declared content ends exactly at
    the end of the file (the binary ContentInfo form), or its text view contains
    an exact supported opening boundary line (the textual form).

    Those are the only two shapes the CMS detectors can match, so a file failing
    both could only ever produce a non-match. Content only: the extension is not
    consulted here or in either detector, so a ``.p7m``, ``.p7e``, ``.p7b``,
    ``.p7c``, ``.cms``, or ``.der`` name alone can never produce a finding, and
    a valid object named ``message`` or ``message.bin`` is still classified from
    its bytes. Deliberately not behind ``_passes_candidate_gate``, which admits
    files by extension and would drop exactly those unextensioned objects.
    """
    prefix = context.leading_bytes(_DER_MAX_HEADER_BYTES)
    header = _der_header(prefix, 0, len(prefix))
    if header is not None:
        tag, content_start, length = header
        if tag == _DER_TAG_SEQUENCE and content_start + length == len(context.data):
            return True
    text = context.text
    return text is not None and any(line in text for line in _CMS_PEM_BEGIN_LINES)


def _cms_observed_content_types(context: FileContext) -> list[str]:
    """The supported CMS encrypted-content types this file carries, computed
    once per file and shared by both CMS detectors through the context memo."""
    observed = context.memo.get(_CMS_MEMO_KEY)
    if observed is None:
        observed = _cms_content_types(context)
        context.memo[_CMS_MEMO_KEY] = observed
    return observed


def _detect_cms_enveloped_data(context: FileContext) -> DetectionResult:
    # The full bytes are required, not a prefix: the ContentInfo runs to the end
    # of the file and the "no trailing bytes" requirement is only meaningful
    # against the whole file. The bytes are already in the shared context, so
    # this is not an extra read.
    observed = _cms_observed_content_types(context)
    if _CMS_ENVELOPED_DATA not in observed:
        return DetectionResult.no_match()
    # One finding per file per content type, not per block: several supported
    # blocks of the *same* type in one file are one encrypted-object asset at
    # one location, and neither finding carries per-block detail that could
    # distinguish them.
    findings = [_cms_enveloped_data_finding(context.path)]
    if _CMS_ENCRYPTED_DATA in observed:
        # Both content types can genuinely coexist in one physical file (most
        # plausibly two separate textual blocks). Both CMS detectors are
        # terminal -- required so a match here is not also re-read as PKCS#12,
        # DER, or generic PEM -- but the shared dispatch loop stops entirely at
        # the first terminal match, priority 46 before 47, so
        # cms:encrypted_data's own detect() would never run for a file this
        # detector already claimed. Reporting both observed claims here, from
        # this one shared structural pass, is what keeps the EncryptedData
        # finding from being silently lost rather than solving it with a
        # second read or a finding unrelated to what was actually observed.
        # cms:encrypted_data's own detect() is unchanged: it is unreachable in
        # this case precisely because this detector is terminal, and it still
        # runs and matches normally whenever EnvelopedData is absent.
        findings.append(_cms_encrypted_data_finding(context.path))
    return DetectionResult.match(findings)


def _detect_cms_encrypted_data(context: FileContext) -> DetectionResult:
    if _CMS_ENCRYPTED_DATA not in _cms_observed_content_types(context):
        return DetectionResult.no_match()
    return DetectionResult.match([_cms_encrypted_data_finding(context.path)])


def _jks_candidate(context: FileContext) -> bool:
    return _passes_candidate_gate(context) and _looks_like_jks(context.leading_bytes(4))


def _detect_jks(context: FileContext) -> DetectionResult:
    return DetectionResult.match(
        [
            CryptoInventoryFinding(
                asset_type="Java Keystore",
                location=context.location,
                evidence="JKS magic header detected",
                confidence="Medium",
                errors=["JKS entry parsing is not implemented in the MVP scanner"],
            )
        ]
    )


def _pkcs12_candidate(context: FileContext) -> bool:
    return _passes_candidate_gate(context) and context.suffix in {".p12", ".pfx"}


def _detect_pkcs12(context: FileContext) -> DetectionResult:
    # A match even when the container parsed cleanly but held nothing
    # reportable: this detector is declared terminal, so a .p12/.pfx file it
    # claimed is not then read as DER or PEM text.
    return DetectionResult.match(_parse_pkcs12(context.path, context.data))


def _der_candidate(context: FileContext) -> bool:
    return _passes_candidate_gate(context) and _looks_like_der_candidate(
        context.path, context.leading_bytes(len(b"-----BEGIN "))
    )


def _detect_der_certificate(context: FileContext) -> DetectionResult:
    findings = _parse_der_certificate(context.path, context.data)
    if not findings:
        # Unreachable today (the parser always returns either a certificate or a
        # malformed-certificate finding), but a non-match here falls through to
        # the text detectors exactly as the pre-HG-033 dispatch did.
        return DetectionResult.no_match()
    return DetectionResult.match(findings)


def _legacy_encrypted_pem_candidate(context: FileContext) -> bool:
    text = context.text
    if text is None:
        return False
    begin_lines = {f"-----BEGIN {label}-----" for label in _LEGACY_ENCRYPTED_PEM_LABELS}
    return any(line.strip() in begin_lines for line in text.splitlines())


def _detect_legacy_encrypted_pem(context: FileContext) -> DetectionResult:
    text = context.text
    if text is None:
        return DetectionResult.no_match()
    if not _legacy_encrypted_pem_blocks(text):
        return DetectionResult.no_match()
    # One finding per file (same-rule collapse), non-terminal so certificates
    # and other PEM assets in the same file can still be reported.
    return DetectionResult.match([_legacy_encrypted_pem_finding(context.path)])


def _text_candidate(context: FileContext) -> bool:
    return _passes_candidate_gate(context) and context.text is not None


def _detect_pem_certificates(context: FileContext) -> DetectionResult:
    return DetectionResult.match(_parse_pem_certificates(context.path, context.text))


def _detect_pem_private_keys(context: FileContext) -> DetectionResult:
    return DetectionResult.match(
        _parse_pem_private_keys(context.path, context.text, context.data)
    )


def _detect_ssh_public_keys(context: FileContext) -> DetectionResult:
    return DetectionResult.match(_parse_ssh_public_keys(context.path, context.text))


# The safe metadata allowlist for a successfully parsed certificate, shared by
# the three detectors that emit one.
_CERTIFICATE_METADATA_KEYS = frozenset(
    {
        "Algorithm",
        "Key Size",
        "Signature Algorithm",
        "Expiration",
        "Issuer",
        "Subject",
        "Fingerprint",
    }
)
_KEY_METADATA_KEYS = frozenset({"Algorithm", "Key Size", "Fingerprint"})

CRYPTO_DETECTORS = build_registry(
    [
        FileDetector(
            detector_id="encrypted_file:openssl",
            priority=10,
            candidate=_openssl_candidate,
            detect=_detect_openssl_salted,
            evidence="Observed OpenSSL Salted__ encrypted file.",
            confidence="High",
            terminal=True,
            rule_id="encrypted_file:openssl",
            verification_rationale=(
                "Exact-position match on the 8-byte header `openssl enc -salt` "
                "writes; the protected content is never read or decrypted."
            ),
        ),
        FileDetector(
            detector_id="encrypted_file:openpgp",
            priority=20,
            candidate=_openpgp_candidate,
            detect=_detect_openpgp_encrypted,
            evidence="Observed OpenPGP encrypted-session-key packet structure.",
            confidence="High",
            terminal=True,
            rule_id="encrypted_file:openpgp",
            metadata_keys=frozenset({"Algorithm"}),
            verification_rationale=(
                "Leading OpenPGP packet header and the fixed RFC 4880 metadata "
                "fields it declares, each validated against the values the "
                "specification allows; the encrypted payload is never "
                "interpreted and gpg is never invoked."
            ),
        ),
        FileDetector(
            detector_id="encrypted_file:age",
            priority=25,
            candidate=_age_candidate,
            detect=_detect_age_encrypted,
            evidence="Observed age encrypted file.",
            confidence="High",
            terminal=True,
            rule_id="encrypted_file:age",
            verification_rationale=(
                "Exact native age v1 version line at offset 0 plus the format's "
                "own header grammar -- recipient stanza shape, header MAC line "
                "shape, and the presence of an encrypted payload; the header MAC "
                "is not verified, no recipient is interpreted, and the payload is "
                "never read or decrypted."
            ),
        ),
        RootDetector(
            detector_id="encrypted_filesystem:gocryptfs",
            priority=30,
            marker_filename=_GOCRYPTFS_CONFIG_FILENAME,
            detect=_detect_gocryptfs_root,
            evidence="Observed supported gocryptfs cipher-root structure.",
            confidence="High",
            rule_id="encrypted_filesystem:gocryptfs",
            metadata_keys=frozenset({"Format", "Config Version", "Mode"}),
            owns_marker=True,
            verification_rationale=(
                "Root-level gocryptfs.conf and gocryptfs.diriv both present as "
                "regular files, plus the config's stable version and feature "
                "flags; never mounted, unlocked, or decrypted, and no key "
                "material, salt, or KDF parameter is read into the finding."
            ),
        ),
        RootDetector(
            detector_id="nss:sql_database_set",
            priority=31,
            marker_filename=_NSS_MARKER_FILENAME,
            detect=_detect_nss_sql_database_set,
            evidence="Supported NSS SQL database set detected",
            confidence="High",
            rule_id="nss:sql_database_set",
            metadata_keys=frozenset({"Format"}),
            owns_marker=False,
            verification_rationale=(
                "Canonical cert9.db, key4.db, and pkcs11.txt all present in one "
                "lexical directory -- the two databases presence/eligibility "
                "checked as genuine regular non-symlink files the scan did not "
                "exclude, never opened -- plus a structurally recognized NSS "
                "internal-module stanza in the marker; no NSS or SQLite tool or "
                "library is invoked, no password is requested or accepted, no "
                "certificate or key is enumerated, and the marker's configdir is "
                "neither resolved nor reported."
            ),
        ),
        FileDetector(
            detector_id="java_keystore:bcfks",
            priority=35,
            candidate=_bcfks_candidate,
            detect=_detect_bcfks,
            evidence="Observed supported BCFKS keystore structure.",
            confidence="High",
            terminal=True,
            rule_id="java_keystore:bcfks",
            metadata_keys=frozenset({"Format"}),
            verification_rationale=(
                "Exact structural match on the Bouncy Castle ObjectStore outer "
                "container -- an EncryptedObjectStoreData and a "
                "PbkdMacIntegrityCheck, consuming the whole file -- read from "
                "the file's own bytes; the store is never decrypted, no "
                "password is accepted, and no entry, alias, or certificate "
                "inside it is read."
            ),
        ),
        FileDetector(
            detector_id="java_keystore:jceks",
            priority=37,
            candidate=_jceks_candidate,
            detect=_detect_jceks,
            evidence="JCEKS keystore header detected",
            confidence="Medium",
            terminal=True,
            rule_id="java_keystore:jceks",
            metadata_keys=frozenset({"Format"}),
            verification_rationale=(
                "JCEKS magic at offset 0 plus the format's own top-level header "
                "fields -- a supported version and a nonnegative entry count -- "
                "and a file large enough for the header and trailing integrity "
                "material; the store is never opened or decrypted, no password "
                "is accepted, the keyed digest is neither verified nor reported, "
                "and no entry, alias, certificate, or serialized Java object "
                "inside it is read."
            ),
        ),
        FileDetector(
            detector_id="java_keystore:jks_magic",
            priority=40,
            candidate=_jks_candidate,
            detect=_detect_jks,
            evidence="JKS magic header detected",
            confidence="Medium",
            terminal=True,
            verification_rationale="Magic header only; entries are not parsed.",
        ),
        FileDetector(
            detector_id="private_key:pkcs8_encrypted",
            priority=45,
            candidate=_pkcs8_encrypted_candidate,
            detect=_detect_pkcs8_encrypted,
            evidence="Encrypted PKCS#8 private-key structure detected",
            confidence="High",
            terminal=True,
            rule_id="private_key:pkcs8_encrypted",
            metadata_keys=frozenset({"Format"}),
            verification_rationale=(
                "Complete PKCS#8 EncryptedPrivateKeyInfo structure read from the "
                "file's own bytes -- a DER SEQUENCE at offset 0 consuming the "
                "whole file, exactly an AlgorithmIdentifier and a non-empty "
                "primitive OCTET STRING, decoded from a complete PEM block when "
                "PEM-encoded; no password is requested or accepted, nothing is "
                "decrypted, no key-loading API is consulted, and the encryption "
                "algorithm, KDF, salt, IV, iteration count, and encrypted bytes "
                "are never reported."
            ),
        ),
        FileDetector(
            detector_id="cms:enveloped_data",
            priority=46,
            candidate=_cms_candidate,
            detect=_detect_cms_enveloped_data,
            evidence="CMS/PKCS#7 EnvelopedData encrypted-content structure detected",
            confidence="High",
            terminal=True,
            rule_id="cms:enveloped_data",
            metadata_keys=frozenset({"Format"}),
            verification_rationale=(
                "Complete RFC 5652 ContentInfo read from the file's own bytes -- "
                "a DER SEQUENCE at offset 0 consuming the whole object, an outer "
                "content type that is exactly id-envelopedData, an explicit [0] "
                "wrapper holding one EnvelopedData SEQUENCE, a non-empty "
                "RecipientInfos SET, and an EncryptedContentInfo whose "
                "encryptedContent is present and non-empty -- decoded from a "
                "complete CMS/PKCS7 textual block when textually encoded; no "
                "password, private key, or recipient certificate is accepted, "
                "nothing is decrypted, no signature or certificate is validated, "
                "and no recipient identity, algorithm, KDF, IV, OID, encrypted "
                "key, or ciphertext byte is reported."
            ),
        ),
        FileDetector(
            detector_id="cms:encrypted_data",
            priority=47,
            candidate=_cms_candidate,
            detect=_detect_cms_encrypted_data,
            evidence="CMS/PKCS#7 EncryptedData encrypted-content structure detected",
            confidence="High",
            terminal=True,
            rule_id="cms:encrypted_data",
            metadata_keys=frozenset({"Format"}),
            verification_rationale=(
                "Complete RFC 5652 ContentInfo read from the file's own bytes -- "
                "a DER SEQUENCE at offset 0 consuming the whole object, an outer "
                "content type that is exactly id-encryptedData, an explicit [0] "
                "wrapper holding one EncryptedData SEQUENCE, the CMS version the "
                "specification fixes for the unprotected attributes present, and "
                "an EncryptedContentInfo whose encryptedContent is present and "
                "non-empty -- decoded from a complete CMS/PKCS7 textual block "
                "when textually encoded; no password or key is accepted, nothing "
                "is decrypted, and no algorithm, KDF, IV, OID, or ciphertext byte "
                "is reported."
            ),
        ),
        FileDetector(
            detector_id="pkcs12:container",
            priority=50,
            candidate=_pkcs12_candidate,
            detect=_detect_pkcs12,
            evidence="PKCS#12 container parsed",
            confidence="High",
            terminal=True,
            metadata_keys=_CERTIFICATE_METADATA_KEYS,
            verification_rationale=(
                "Container parsed with no password; a container requiring one is "
                "reported as malformed rather than attempted."
            ),
        ),
        FileDetector(
            detector_id="certificate:der",
            priority=60,
            candidate=_der_candidate,
            detect=_detect_der_certificate,
            evidence="DER Certificate parsed successfully",
            confidence="High",
            terminal=True,
            metadata_keys=_CERTIFICATE_METADATA_KEYS,
            verification_rationale="Structural DER X.509 parse of the file's bytes.",
        ),
        FileDetector(
            detector_id="certificate:pem",
            priority=70,
            candidate=_text_candidate,
            detect=_detect_pem_certificates,
            evidence="PEM Certificate parsed successfully",
            confidence="High",
            metadata_keys=_CERTIFICATE_METADATA_KEYS,
            verification_rationale="Structural PEM X.509 parse of each CERTIFICATE block.",
        ),
        FileDetector(
            detector_id="private_key:legacy_pem_encrypted",
            priority=75,
            candidate=_legacy_encrypted_pem_candidate,
            detect=_detect_legacy_encrypted_pem,
            evidence="Legacy PEM encrypted private-key structure detected",
            confidence="High",
            terminal=False,
            rule_id="private_key:legacy_pem_encrypted",
            metadata_keys=frozenset({"Format"}),
            verification_rationale=(
                "Complete traditional PEM private-key block with exact BEGIN/END "
                "boundaries, Proc-Type: 4,ENCRYPTED, a syntactically valid "
                "DEK-Info cipher and hex IV, and a non-empty strict-base64 body; "
                "no password is accepted, nothing is decrypted, and cipher/IV/"
                "ciphertext are never reported. Priority 75 places this after "
                "certificate PEM and before generic private-key PEM, without "
                "changing PKCS#12, encrypted PKCS#8, or CMS behavior."
            ),
        ),
        FileDetector(
            detector_id="private_key:pem",
            priority=80,
            candidate=_text_candidate,
            detect=_detect_pem_private_keys,
            evidence="PEM block BEGIN <label>",
            confidence="High",
            metadata_keys=_KEY_METADATA_KEYS,
            verification_rationale=(
                "PEM/OpenSSH private-key block parsed with no passphrase. "
                "Traditional Proc-Type encrypted blocks are owned by "
                "private_key:legacy_pem_encrypted (HG-040); encrypted PKCS#8 "
                "is owned by private_key:pkcs8_encrypted (HG-038)."
            ),
        ),
        FileDetector(
            detector_id="public_key:ssh",
            priority=90,
            candidate=_text_candidate,
            detect=_detect_ssh_public_keys,
            evidence="OpenSSH public key prefix <type>",
            confidence="High",
            metadata_keys=_KEY_METADATA_KEYS,
            verification_rationale="OpenSSH public-key line parsed from its prefix.",
        ),
    ]
)


def _scan_file(
    file_path: Path,
    detectors: tuple | None = None,
    scope: ScanScope | None = None,
) -> list[CryptoInventoryFinding]:
    """Every finding the detector registry produces for one file the scanner's
    traversal already selected.

    One read per file, shared by every detector through the file context -- the
    same single read this function performed before HG-033. An unreadable file
    (permission denied, vanished or replaced mid-scan) produces no findings and
    no evidence, unchanged.

    ``scope`` carries this scan's target and exclusion rules so an aggregate root
    detector's fixed-name supporting-sibling check respects the user's
    ``--exclude`` patterns (HG-041). It adds no traversal and no read: the scope
    object only answers "would this scan have excluded that path".
    """
    context = FileContext(file_path, scope=scope)
    if not context.readable():
        return []
    return run_detectors(context, detectors or CRYPTO_DETECTORS)


def _parse_pem_certificates(file_path: Path, text: str) -> list[CryptoInventoryFinding]:
    findings = []
    blocks = _extract_pem_blocks(text, "CERTIFICATE")
    for block in blocks:
        try:
            cert = x509.load_pem_x509_certificate(block.encode("ascii"))
            findings.append(_finding_from_certificate("PEM Certificate", file_path, cert))
        except (ValueError, TypeError) as exc:
            findings.append(
                CryptoInventoryFinding(
                    asset_type="Malformed PEM Certificate",
                    location=str(file_path),
                    evidence="PEM certificate block detected but parsing failed",
                    confidence="Low",
                    errors=[str(exc)],
                )
            )
    return findings


def _parse_der_certificate(file_path: Path, data: bytes) -> list[CryptoInventoryFinding]:
    try:
        cert = x509.load_der_x509_certificate(data)
    except ValueError:
        return [
            CryptoInventoryFinding(
                asset_type="Malformed DER Certificate",
                location=str(file_path),
                evidence="DER-like certificate file extension detected but parsing failed",
                confidence="Low",
                errors=["Unable to parse DER certificate"],
            )
        ]
    return [_finding_from_certificate("DER Certificate", file_path, cert)]


def _parse_pem_private_keys(
    file_path: Path, text: str, data: bytes
) -> list[CryptoInventoryFinding]:
    findings = []
    for label, asset_type in _PEM_BLOCK_MARKERS.items():
        # CERTIFICATE, OPENSSH PRIVATE KEY, and PUBLIC KEY are owned by other
        # detectors. ENCRYPTED PRIVATE KEY joined them in HG-038: the dedicated
        # `private_key:pkcs8_encrypted` detector validates that structure
        # directly and terminally, so a supported block never reaches this
        # function and cannot be reported twice. A block that detector rejected
        # is a malformed PKCS#8 candidate, and the exception a passwordless load
        # raises for it is not evidence of anything -- that exception-driven
        # classification is precisely what HG-038 replaced -- so it is left
        # unreported rather than turned into a High-confidence encrypted-key
        # claim here. Traditional Proc-Type: 4,ENCRYPTED blocks for RSA/DSA/EC
        # labels are owned by HG-040 and skipped below.
        if label in {
            "CERTIFICATE",
            "OPENSSH PRIVATE KEY",
            "PUBLIC KEY",
            _PKCS8_ENCRYPTED_PEM_LABEL,
        }:
            continue
        for block in _extract_pem_blocks(text, label):
            # Traditional Proc-Type encrypted blocks are owned by HG-040.
            # Use the shared semantic predicate so casing variants the detector
            # accepts cannot also produce a generic private-key finding.
            if label in _LEGACY_ENCRYPTED_PEM_LABELS and _block_owned_by_legacy_encrypted_pem(
                block
            ):
                continue
            encrypted = "ENCRYPTED" in label or "Proc-Type: 4,ENCRYPTED" in block
            try:
                key = serialization.load_pem_private_key(block.encode("ascii"), password=None)
                algorithm, key_size = _key_algorithm_and_size(key)
                findings.append(
                    CryptoInventoryFinding(
                        asset_type=asset_type,
                        location=str(file_path),
                        algorithm=algorithm,
                        key_size=key_size,
                        fingerprint=_public_key_fingerprint(key.public_key()),
                        evidence=f"PEM block BEGIN {label}",
                        confidence="High",
                    )
                )
            except (TypeError, ValueError) as exc:
                if encrypted:
                    algorithm = _algorithm_from_pem_label(label)
                    findings.append(
                        CryptoInventoryFinding(
                            asset_type="Encrypted PEM Private Key",
                            location=str(file_path),
                            algorithm=algorithm,
                            evidence=f"Encrypted PEM block BEGIN {label}",
                            confidence="High",
                            errors=[
                                "Private key is encrypted; key metadata requires a passphrase",
                            ],
                        )
                    )
                else:
                    findings.append(
                        CryptoInventoryFinding(
                            asset_type=f"Malformed {asset_type}",
                            location=str(file_path),
                            evidence=f"PEM block BEGIN {label} detected but parsing failed",
                            confidence="Low",
                            errors=[str(exc)],
                        )
                    )

    if "BEGIN OPENSSH PRIVATE KEY" in text and not any(
        finding.asset_type == "OpenSSH Private Key" for finding in findings
    ):
        try:
            key = serialization.load_ssh_private_key(data, password=None)
            algorithm, key_size = _key_algorithm_and_size(key)
            findings.append(
                CryptoInventoryFinding(
                    asset_type="OpenSSH Private Key",
                    location=str(file_path),
                    algorithm=algorithm,
                    key_size=key_size,
                    fingerprint=_public_key_fingerprint(key.public_key()),
                    evidence="OpenSSH private key block detected",
                    confidence="High",
                )
            )
        except (TypeError, ValueError) as exc:
            findings.append(
                CryptoInventoryFinding(
                    asset_type="Encrypted OpenSSH Private Key",
                    location=str(file_path),
                    evidence="OpenSSH private key block detected",
                    confidence="Medium",
                    errors=[str(exc)],
                )
            )

    return findings


def _parse_ssh_public_keys(file_path: Path, text: str) -> list[CryptoInventoryFinding]:
    findings = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith(("ssh-rsa ", "ssh-ed25519 ", "ecdsa-sha2-")):
            continue
        try:
            key = serialization.load_ssh_public_key(stripped.encode("utf-8"))
            algorithm, key_size = _key_algorithm_and_size(key)
            findings.append(
                CryptoInventoryFinding(
                    asset_type="OpenSSH Public Key",
                    location=str(file_path),
                    algorithm=algorithm,
                    key_size=key_size,
                    fingerprint=_public_key_fingerprint(key),
                    evidence=f"OpenSSH public key prefix {stripped.split()[0]}",
                    confidence="High",
                )
            )
        except ValueError as exc:
            findings.append(
                CryptoInventoryFinding(
                    asset_type="Malformed OpenSSH Public Key",
                    location=str(file_path),
                    evidence="OpenSSH public key prefix detected but parsing failed",
                    confidence="Low",
                    errors=[str(exc)],
                )
            )
    return findings


def _parse_pkcs12(file_path: Path, data: bytes) -> list[CryptoInventoryFinding]:
    try:
        key, cert, additional_certs = pkcs12.load_key_and_certificates(data, password=None)
    except ValueError as exc:
        return [
            CryptoInventoryFinding(
                asset_type="Malformed PKCS#12",
                location=str(file_path),
                evidence="PKCS#12 file extension detected but parsing failed",
                confidence="Low",
                errors=[str(exc)],
            )
        ]

    findings = []
    if cert is not None:
        finding = _finding_from_certificate("PKCS#12 Certificate", file_path, cert)
        finding.evidence = "PKCS#12 container certificate parsed"
        findings.append(finding)
    for extra_cert in additional_certs or []:
        finding = _finding_from_certificate("PKCS#12 Certificate", file_path, extra_cert)
        finding.evidence = "PKCS#12 additional certificate parsed"
        findings.append(finding)
    if key is not None:
        algorithm, key_size = _key_algorithm_and_size(key)
        findings.append(
            CryptoInventoryFinding(
                asset_type="PKCS#12 Private Key",
                location=str(file_path),
                algorithm=algorithm,
                key_size=key_size,
                fingerprint=_public_key_fingerprint(key.public_key()),
                evidence="PKCS#12 private key parsed",
                confidence="High",
            )
        )

    return findings


def _finding_from_certificate(
    asset_type: str, file_path: Path, cert: x509.Certificate
) -> CryptoInventoryFinding:
    public_key = cert.public_key()
    algorithm, key_size = _key_algorithm_and_size(public_key)
    return CryptoInventoryFinding(
        asset_type=asset_type,
        location=str(file_path),
        algorithm=algorithm,
        key_size=key_size,
        signature_algorithm=_signature_algorithm(cert),
        expiration=_certificate_expiration(cert),
        issuer=cert.issuer.rfc4514_string(),
        subject=cert.subject.rfc4514_string(),
        fingerprint=cert.fingerprint(hashes.SHA256()).hex(),
        evidence=f"{asset_type} parsed successfully",
        confidence="High",
    )


def _key_algorithm_and_size(key: object) -> tuple[str, int | None]:
    if isinstance(key, (rsa.RSAPrivateKey, rsa.RSAPublicKey)):
        return "RSA", key.key_size
    if isinstance(key, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)):
        return f"EC ({key.curve.name})", key.key_size
    if isinstance(key, (dsa.DSAPrivateKey, dsa.DSAPublicKey)):
        return "DSA", key.key_size
    if isinstance(key, (ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey)):
        return "Ed25519", 256
    if isinstance(key, (ed448.Ed448PrivateKey, ed448.Ed448PublicKey)):
        return "Ed448", 456
    return key.__class__.__name__, None


def _public_key_fingerprint(public_key: object) -> str | None:
    try:
        encoded = public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    except (TypeError, ValueError):
        return None
    digest = hashes.Hash(hashes.SHA256())
    digest.update(encoded)
    return digest.finalize().hex()


def _signature_algorithm(cert: x509.Certificate) -> str:
    if cert.signature_hash_algorithm is not None:
        return cert.signature_hash_algorithm.name
    return cert.signature_algorithm_oid._name


def _certificate_expiration(cert: x509.Certificate) -> str:
    try:
        expires = cert.not_valid_after_utc
    except AttributeError:
        expires = cert.not_valid_after.replace(tzinfo=timezone.utc)
    return expires.replace(microsecond=0).isoformat()


def _extract_pem_blocks(text: str, label: str) -> list[str]:
    begin = f"-----BEGIN {label}-----"
    end = f"-----END {label}-----"
    blocks = []
    start = 0
    while True:
        begin_index = text.find(begin, start)
        if begin_index == -1:
            return blocks
        end_index = text.find(end, begin_index)
        if end_index == -1:
            blocks.append(text[begin_index:])
            return blocks
        block_end = end_index + len(end)
        blocks.append(text[begin_index:block_end])
        start = block_end


_CANDIDATE_GATE_MEMO_KEY = "could_contain_crypto_asset"


def _passes_candidate_gate(context: FileContext) -> bool:
    """The shared candidate gate every file-format detector below priority 40
    sits behind, memoized per file.

    Unchanged from the single pre-HG-033 gate call in ``_scan_file``: the same
    conditions, evaluated once per file rather than once per detector, so adding
    a gated detector cannot turn the gate's 5 MB substring scan into repeated
    work. Detectors above the gate (OpenSSL, OpenPGP, gocryptfs) deliberately do
    not consult it -- their formats have no recognized extension and no
    ``-----BEGIN `` text for it to admit them by.
    """
    cached = context.memo.get(_CANDIDATE_GATE_MEMO_KEY)
    if cached is None:
        cached = _could_contain_crypto_asset(context.path, context.data)
        context.memo[_CANDIDATE_GATE_MEMO_KEY] = cached
    return cached


def _could_contain_crypto_asset(file_path: Path, data: bytes) -> bool:
    suffix = file_path.suffix.lower()
    if _looks_like_openssl_salted(data):
        return True
    if suffix in _BINARY_PARSE_EXTENSIONS:
        return True
    if _looks_like_jks(data):
        return True
    if b"-----BEGIN " in data[:MAX_TEXT_BYTES]:
        return True
    if data.startswith((b"ssh-rsa ", b"ssh-ed25519 ", b"ecdsa-sha2-")):
        return True
    return False


def _looks_like_der_candidate(file_path: Path, data: bytes) -> bool:
    return file_path.suffix.lower() in {".cer", ".crt", ".der"} and not data.startswith(
        b"-----BEGIN "
    )


def _looks_like_jks(data: bytes) -> bool:
    return data.startswith(b"\xfe\xed\xfe\xed")


def _algorithm_from_pem_label(label: str) -> str | None:
    if label.startswith("RSA"):
        return "RSA"
    if label.startswith("DSA"):
        return "DSA"
    if label.startswith("EC"):
        return "EC"
    if label == "OPENSSH PRIVATE KEY":
        return "OpenSSH"
    return None


def _relative_for_match(path: Path, root_path: Path) -> str:
    try:
        rel = path.relative_to(root_path)
    except ValueError:
        return path.name
    return "" if str(rel) == "." else rel.as_posix()


def _join_match_path(prefix: str, name: str) -> str:
    return name if not prefix else f"{prefix}/{name}"


def _is_excluded(path: Path, match_path: str, patterns: list[str]) -> bool:
    return any(
        fnmatch.fnmatch(path.name, pattern) or fnmatch.fnmatch(match_path, pattern)
        for pattern in patterns
    )


def _scan_scope(root_path: Path, patterns: list[str]) -> ScanScope:
    """This scan's scope rules, for the aggregate supporting-sibling eligibility
    check (HG-041).

    Both callables are the traversal's own: ``_relative_for_match`` produces the
    same root-relative POSIX match path ``_iter_candidate_files`` assigns a file
    it encounters -- and, when the scan target is a single file, the sibling's
    bare basename, since a sibling of the target is not relative to the target
    and no parent prefix, absolute path, or ``..`` segment is introduced -- and
    ``_is_excluded`` is the same matcher, over the same patterns. There is no
    second exclusion grammar.
    """
    return ScanScope(
        target_path=root_path,
        match_path_for=lambda path: _relative_for_match(path, root_path),
        is_excluded=lambda path, match_path: _is_excluded(path, match_path, patterns),
    )


def _clean_json_value(value: object) -> object:
    if isinstance(value, CryptoInventoryFinding):
        return asdict(value)
    if isinstance(value, float) and math.isnan(value):
        return None
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return value


def _records_for_json(df: pd.DataFrame) -> list[dict[str, object]]:
    return [
        {key: _clean_json_value(value) for key, value in record.items()}
        for record in df.to_dict(orient="records")
    ]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Scan a directory for cryptographic assets.")
    parser.add_argument("path", help="File or directory to scan")
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        help="Glob pattern to exclude; may be supplied more than once",
    )
    parser.add_argument(
        "--follow-symlinks",
        action="store_true",
        help="Follow symbolic links during recursive scans",
    )
    args = parser.parse_args(argv)

    df = scan_crypto_inventory(
        args.path,
        exclude_patterns=args.exclude,
        follow_symlinks=args.follow_symlinks,
    )
    print(json.dumps(_records_for_json(df), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
