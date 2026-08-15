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
import yaml
from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
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
    argument with a non-empty normalized value, and every other argument is
    itself a syntactically valid ``key=value`` token.

    Every argument must have a non-empty key before its first ``=`` and a value
    that passes the same whole-value quoting rule ``configdir`` itself is held
    to -- a bare token with no ``=`` at all (``BROKEN``), an empty key
    (``=x``), or a mixed quoted/unquoted value on *any* argument
    (``other=abc'def'``) is malformed and rejects the stanza, exactly as an
    invalid ``configdir`` value would. A syntactically valid argument under a
    different key is still ignored: HarvestGuard does not care what it says,
    only that ``parameters=`` as a whole is well-formed.

    The ``configdir`` value itself is opaque: it is not required to start with
    ``sql:``, not resolved, not expanded, not normalized to a filesystem path,
    not compared to the scanned root, not followed, and never emitted. Only its
    presence, uniqueness, and non-emptiness are evidence.
    """
    arguments = _nss_split_parameter_arguments(value)
    if arguments is None:
        return False
    configdir: str | None = None
    for argument in arguments:
        separator = argument.find("=")
        if separator <= 0:
            # No "=" at all, or an empty key before it: not a valid key=value
            # token under this grammar, so parameters= -- and therefore the
            # stanza -- is malformed rather than merely carrying an argument
            # HG-041 doesn't care about.
            return False
        unquoted = _nss_unquote_whole_value(argument[separator + 1 :])
        if unquoted is None:
            return False
        if _nss_ascii_lower(argument[:separator]) != _NSS_CONFIGDIR_KEY:
            continue
        if configdir is not None:
            # A duplicate configdir rejects the stanza -- no first-wins or
            # last-wins resolution.
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
    entire value is unquoted and whose comma-separated tokens include both
    ``internal`` and ``critical``.

    The whole selected ``Flags`` value is rejected outright if a single or
    double quote character appears anywhere in it -- wrapping the entire
    value (``Flags="internal,critical"``), wrapping one token
    (``Flags=internal,'critical'``), or trailing after the two required
    tokens (``Flags=internal,critical,"extra"``) are all rejected the same
    way, not only the whole-value-wrapped form. Flag tokens are otherwise
    compared as whole tokens after trimming, so ``notinternal``,
    ``internally``, and ``criticality`` are not matches, while additional
    exact unquoted tokens alongside the two required ones are allowed. Other
    top-level arguments (``trustOrder``, ``cipherOrder``, ``slotParams``, ...)
    may appear in any order and are neither interpreted nor emitted.
    """
    arguments = _nss_split_top_level_arguments(value)
    if arguments is None:
        return False
    flags_value: str | None = None
    for argument in arguments:
        separator = argument.find("=")
        if separator == -1:
            continue
        if _nss_ascii_lower(argument[:separator]) != _NSS_FLAGS_KEY:
            continue
        if flags_value is not None:
            # A duplicate top-level Flags argument rejects the stanza.
            return False
        flags_value = argument[separator + 1 :]
    if flags_value is None:
        return False
    if any(quote in flags_value for quote in _NSS_QUOTES):
        return False
    tokens = frozenset(
        _nss_ascii_lower(token.strip(_NSS_ASCII_WHITESPACE)) for token in flags_value.split(",")
    )
    return _NSS_REQUIRED_FLAGS.issubset(tokens)


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


# --- Java trusted-certificate-only store detection (HG-042) -----------------
#
# HG-037/the generic JKS detector stop at the container header, which is why
# both are Medium confidence and why neither can say anything about entries.
# HG-042 reads the *complete* declared entry table of a JKS or JCEKS store and
# classifies it only when every declared entry is a supported trusted-
# certificate entry. That is a strictly structural observation:
#
#   a structurally supported JKS or JCEKS store contains only supported
#   trusted-certificate entries
#
# and deliberately *not* "this file is a truststore". A certificate-only store
# may never be configured as one, and an operational truststore may hold
# private-key entries, secret-key entries, or nothing at all. Runtime role
# cannot be established from these bytes, so the asset type says what was
# observed -- `Java Trusted-Certificate-Only Store` -- and the interpretation
# stays with the reader.
#
# The entry framing below is OpenJDK's own store/load grammar
# (`sun.security.provider.JavaKeyStore` and
# `com.sun.crypto.provider.JceKeyStore`): a 4-byte entry tag, a
# `DataOutputStream.writeUTF` alias, an 8-byte creation timestamp, then for a
# version-2 store a `writeUTF` certificate type, and finally a 4-byte
# certificate length and that many DER bytes. Version 1 has no certificate-type
# field at all -- the type is implicitly X.509 -- which is the one framing
# difference between the two supported versions.
#
# What this detector never does is what keeps it safe: no password is requested
# or accepted, the trailing keyed digest is length-checked and never read,
# recomputed, or verified, a tag-1 private-key body is never parsed, a JCEKS
# tag-3 `SealedObject` is never deserialized, and neither Java nor keytool nor
# any other external process is invoked. A single private-key, secret-key, or unrecognized
# entry ends classification immediately and hands the file back to the generic
# keystore detectors unchanged.

_JKS_MAGIC = b"\xfe\xed\xfe\xed"
# magic + version + entry count: the fixed prefix both formats share.
_JAVA_KEYSTORE_HEADER_BYTES = 12
# The trailing keyed digest `engineStore` appends. Only its length is used --
# structural evidence that the store was written whole. Verifying it would
# require the store password, which HG-042 never accepts.
_JAVA_KEYSTORE_TRAILER_BYTES = 20
_JAVA_KEYSTORE_SUPPORTED_VERSIONS = frozenset({1, 2})
# The entry tag HG-042 accepts. Tag 1 (private key) and JCEKS tag 3 (secret
# key) are recognized only well enough to disqualify the store; their payloads
# are never touched.
_JAVA_KEYSTORE_TAG_TRUSTED_CERTIFICATE = 2
# The only version-2 certificate type in scope, compared as raw bytes. The
# characters of `X.509` encode identically under Java modified UTF and ASCII,
# so the comparison is exact once the field's UTF framing has been validated.
# Any other type -- however valid to Java -- is a deliberate no-match.
_JAVA_KEYSTORE_X509_CERTIFICATE_TYPE = b"X.509"
# The smallest a supported trusted-certificate entry can be, per version, used
# to reject an infeasible declared entry count *before* iterating it:
#
#   v1: tag 4 + alias length field 2 + alias 0 + timestamp 8
#       + certificate length 4 + certificate 1 = 19
#   v2: the same plus certificate-type length field 2 + `X.509` 5 = 26
#
# These are feasibility bounds only; a one-byte certificate still fails the DER
# X.509 parse below.
_JAVA_KEYSTORE_MIN_TRUSTED_CERTIFICATE_ENTRY_BYTES = {1: 19, 2: 26}


def _is_canonical_java_modified_utf(encoded: bytes) -> bool:
    """Whether ``encoded`` is exactly what ``DataOutputStream.writeUTF`` emits.

    Deliberately stricter than a permissive ``DataInputStream.readUTF``: HG-042's
    High-confidence structural claim rests on the field being *canonically*
    encoded, so a byte sequence some reader would tolerate but no writer emits is
    a no-match rather than an accepted alias. That makes the strictness an
    intentional false-negative boundary, not a decoding bug.

    Iterative and single-pass over the already-bounded slice, with no recursion,
    no allocation, no normalization, no malformed-sequence replacement, no
    CESU-8 conversion, and no escape semantics -- a byte-state validator only.
    The decoded string is never produced, so nothing here can retain, log, or
    leak an alias.

    The grammar, over Java UTF-16 ``char`` code units rather than Unicode scalar
    values:

    - one byte: ``0x01``-``0x7F`` (raw ``0x00`` is not canonical);
    - ``C0 80``: the only encoding of U+0000, and the only valid sequence
      beginning with ``C0``; every ``C1`` lead is overlong and rejected;
    - two bytes: ``C2``-``DF`` then one ``80``-``BF`` continuation
      (U+0080-U+07FF);
    - three bytes: ``E0``-``EF`` then two ``80``-``BF`` continuations
      (U+0800-U+FFFF), with ``E0`` requiring ``A0``-``BF`` second byte so an
      overlong form is rejected.

    Surrogate code units are encoded individually by ``writeUTF``, so an
    isolated high or low surrogate is accepted as one canonical three-byte
    sequence and a pair is accepted as two; they are never combined or
    normalized. No four-byte ordinary-UTF-8 sequence is accepted.
    """
    index = 0
    length = len(encoded)
    while index < length:
        first = encoded[index]
        if 0x01 <= first <= 0x7F:
            index += 1
        elif first == 0xC0:
            # The single canonical two-byte form beginning with C0 is the
            # encoded NUL; C0 followed by anything else is overlong.
            if index + 1 >= length or encoded[index + 1] != 0x80:
                return False
            index += 2
        elif 0xC2 <= first <= 0xDF:
            if index + 1 >= length or not 0x80 <= encoded[index + 1] <= 0xBF:
                return False
            index += 2
        elif 0xE0 <= first <= 0xEF:
            if index + 2 >= length:
                return False
            second = encoded[index + 1]
            if not 0x80 <= second <= 0xBF or not 0x80 <= encoded[index + 2] <= 0xBF:
                return False
            if first == 0xE0 and second < 0xA0:
                return False
            index += 3
        else:
            # Raw 0x00, a standalone C1 lead, a standalone continuation byte
            # (0x80-0xBF), and every 0xF0-0xFF lead land here.
            return False
    return True


def _read_java_modified_utf_field(
    data: bytes, offset: int, limit: int
) -> tuple[int, bytes] | None:
    """One ``writeUTF`` field read from ``data`` at ``offset``: the cursor just
    past it and its encoded bytes, or None when the field is truncated or not
    canonically encoded.

    The 2-byte prefix is an *encoded-byte* length, never a character count, and
    nothing is allocated from it: exactly that many bytes must be available
    inside ``limit`` before the slice is taken, and the whole declared slice is
    consumed or the field is rejected.
    """
    if limit - offset < 2:
        return None
    encoded_length = int.from_bytes(data[offset : offset + 2], "big", signed=False)
    offset += 2
    if limit - offset < encoded_length:
        return None
    encoded = data[offset : offset + encoded_length]
    if not _is_canonical_java_modified_utf(encoded):
        return None
    return offset + encoded_length, encoded


def _is_der_x509_certificate(payload: bytes) -> bool:
    """Whether ``payload`` parses as a DER X.509 certificate.

    A boolean structural validation step and nothing more: the parsed
    certificate is discarded immediately, so no subject, issuer, serial number,
    SAN, fingerprint, validity period, or DER byte can reach a finding.

    Only ``ValueError`` -- the documented, stable exception
    ``load_der_x509_certificate`` raises for malformed input across this
    repository's supported ``cryptography>=41.0.0`` range, and the same
    exception the existing generic DER certificate parser
    (``_parse_der_certificate`` below) already catches for this identical
    call -- is treated as an expected parse failure and becomes a plain
    no-match. Anything else is not a certificate-shaped input problem and must
    propagate into the existing sanitized ``DetectorExecutionError`` /
    ``LocalScanError`` path rather than being silently absorbed here.
    """
    try:
        x509.load_der_x509_certificate(payload)
    except ValueError:
        return False
    return True


def _read_trusted_certificate_entry(
    data: bytes, offset: int, limit: int, version: int
) -> int | None:
    """The cursor just past one supported trusted-certificate entry, or None
    when the entry at ``offset`` is not one.

    Cursor-based and bounds-checked before every read, skip, and slice, with
    ``limit`` already excluding the reserved trailer, so a declared length can
    never reach past the entry table. Returning None is the single disqualifying
    outcome for the whole store: a private-key tag, a JCEKS secret-key tag, an
    unknown tag, a malformed alias or certificate type, a non-X.509 version-2
    type, a nonpositive or oversized certificate length, and a certificate that
    is not valid DER X.509 all end classification here without the payload
    being parsed, decrypted, or deserialized.
    """
    if limit - offset < 4:
        return None
    tag = int.from_bytes(data[offset : offset + 4], "big", signed=True)
    if tag != _JAVA_KEYSTORE_TAG_TRUSTED_CERTIFICATE:
        return None
    offset += 4
    alias_field = _read_java_modified_utf_field(data, offset, limit)
    if alias_field is None:
        return None
    # Only the cursor is taken. The alias bytes are validated in place and then
    # dropped -- never decoded, normalized, compared, retained, or emitted.
    offset = alias_field[0]
    if limit - offset < 8:
        return None
    # The 8-byte creation timestamp, skipped after bounds validation.
    offset += 8
    if version == 2:
        certificate_type_field = _read_java_modified_utf_field(data, offset, limit)
        if certificate_type_field is None:
            return None
        offset, certificate_type = certificate_type_field
        if certificate_type != _JAVA_KEYSTORE_X509_CERTIFICATE_TYPE:
            return None
    if limit - offset < 4:
        return None
    # Signed, exactly as `DataInputStream.readInt()` reads it, so a top-bit-set
    # length is negative rather than enormous.
    certificate_length = int.from_bytes(data[offset : offset + 4], "big", signed=True)
    offset += 4
    if certificate_length <= 0:
        return None
    if certificate_length > limit - offset:
        return None
    if not _is_der_x509_certificate(data[offset : offset + certificate_length]):
        return None
    return offset + certificate_length


def _looks_like_trusted_certificate_only_store(data: bytes, magic: bytes) -> bool:
    """Whether ``data`` is a complete JKS/JCEKS store (per ``magic``) whose every
    declared entry is a supported trusted-certificate entry.

    Content only -- the filename is never consulted, so ``cacerts`` is not
    privileged and identical bytes classify identically under any name. Bounded
    by the already-loaded buffer, length-safe, and binary-safe: an empty,
    truncated, or arbitrary binary file returns False rather than raising.

    Every condition below is what rejects one class of near-match:

    1. the format's magic at offset 0;
    2. a supported version, 1 or 2;
    3. a positive declared entry count -- an empty store carries no
       trusted-certificate evidence and is not classified;
    4. an entry count feasible within the bytes remaining once the 20-byte
       trailer is reserved, checked before any entry is read;
    5. every declared entry parsing as a supported trusted-certificate entry;
    6. exactly the 20-byte trailer remaining afterwards, so a truncated,
       overlong, or appended-to store is rejected.
    """
    if len(data) < _JAVA_KEYSTORE_HEADER_BYTES:
        return False
    if data[:4] != magic:
        return False
    version = int.from_bytes(data[4:8], "big", signed=True)
    if version not in _JAVA_KEYSTORE_SUPPORTED_VERSIONS:
        return False
    # Signed, as `readInt()` reads it: a negative count is not a store any
    # `engineStore` wrote, and zero entries is a deliberate no-match.
    entry_count = int.from_bytes(data[8:12], "big", signed=True)
    if entry_count <= 0:
        return False
    # The entry table ends where the reserved trailer begins. Everything below
    # is bounded by this, never by the file length.
    limit = len(data) - _JAVA_KEYSTORE_TRAILER_BYTES
    offset = _JAVA_KEYSTORE_HEADER_BYTES
    if limit < offset:
        return False
    minimum_entry_bytes = _JAVA_KEYSTORE_MIN_TRUSTED_CERTIFICATE_ENTRY_BYTES[version]
    # Integer division rather than multiplication, and before the loop: a
    # declared count of billions is rejected here without a single entry read
    # and without allocating anything proportional to it.
    if entry_count > (limit - offset) // minimum_entry_bytes:
        return False
    for _ in range(entry_count):
        next_offset = _read_trusted_certificate_entry(data, offset, limit, version)
        if next_offset is None:
            return False
        offset = next_offset
    return offset == limit


def _java_truststore_finding(file_path: Path, store_format: str) -> CryptoInventoryFinding:
    return CryptoInventoryFinding(
        asset_type="Java Trusted-Certificate-Only Store",
        location=str(file_path),
        evidence=f"{store_format} trusted-certificate-only store structure detected",
        confidence="High",
        rule_id=f"java_truststore:{store_format.lower()}",
        format=store_format,
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


# --- OpenSSH host identity (HG-043) -----------------------------------------
#
# Three bounded, file-local observations (Issue #88): a supported unencrypted
# private key at an exact canonical OpenSSH host-key basename; one supported
# OpenSSH public-key record at the corresponding canonical basename; and one
# structurally parsed OpenSSH certificate whose encoded type is HOST. None of
# this pairs a private candidate with a public candidate, reads a sibling
# file, resolves `sshd_config`/`HostKey`, or verifies a certificate signature
# -- see the module-level detector functions below for the exact boundary
# each one enforces.

_OPENSSH_PRIVATE_RULE_ID = "openssh_host_identity:private_key"
_OPENSSH_PUBLIC_RULE_ID = "openssh_host_identity:public_key"
_OPENSSH_HOST_CERTIFICATE_RULE_ID = "openssh_host_identity:host_certificate"

_OPENSSH_HOST_PRIVATE_BASENAMES = {
    "ssh_host_rsa_key": "RSA",
    "ssh_host_ecdsa_key": "ECDSA",
    "ssh_host_ed25519_key": "Ed25519",
}
_OPENSSH_HOST_PUBLIC_BASENAMES = {
    "ssh_host_rsa_key.pub": "RSA",
    "ssh_host_ecdsa_key.pub": "ECDSA",
    "ssh_host_ed25519_key.pub": "Ed25519",
}

# Exactly the curves the existing minimum-dependency OpenSSH parser supports
# (Issue #88 Section 3). A parsed ECDSA key on any other curve is no-match.
_OPENSSH_ACCEPTED_CURVES = frozenset({"secp256r1", "secp384r1", "secp521r1"})

_OPENSSH_PLAIN_ALGORITHM_TOKENS = frozenset(
    {
        b"ssh-rsa",
        b"ecdsa-sha2-nistp256",
        b"ecdsa-sha2-nistp384",
        b"ecdsa-sha2-nistp521",
        b"ssh-ed25519",
    }
)
_OPENSSH_CERT_ALGORITHM_TOKENS = frozenset(
    {
        b"ssh-rsa-cert-v01@openssh.com",
        b"ecdsa-sha2-nistp256-cert-v01@openssh.com",
        b"ecdsa-sha2-nistp384-cert-v01@openssh.com",
        b"ecdsa-sha2-nistp521-cert-v01@openssh.com",
        b"ssh-ed25519-cert-v01@openssh.com",
    }
)
# The same five tokens, decoded, for the one caller that works in `str` rather
# than `bytes`: the pre-HG-043 generic SSH public-key parser below. Kept as a
# single source of truth so the two representations cannot drift apart.
_OPENSSH_CERT_ALGORITHM_TOKENS_TEXT = frozenset(
    token.decode("ascii") for token in _OPENSSH_CERT_ALGORITHM_TOKENS
)

_OPENSSH_METADATA_KEYS = frozenset({"Algorithm", "Key Size"})


def _openssh_host_identity_key_family(key: object) -> str | None:
    """The HG-043 key family ("RSA", "ECDSA", or "Ed25519") for an already
    parsed key, certified key, or certificate signing key, or None when its
    class or (for ECDSA) curve falls outside the frozen boundary Issue #88
    Section 3 declares -- DSA, Ed448, and every ECDSA curve except
    secp256r1/secp384r1/secp521r1 are all HG-043 no-match, not a supported
    family with unusual metadata.
    """
    if isinstance(key, (rsa.RSAPrivateKey, rsa.RSAPublicKey)):
        return "RSA"
    if isinstance(key, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)):
        if key.curve.name in _OPENSSH_ACCEPTED_CURVES:
            return "ECDSA"
        return None
    if isinstance(key, (ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey)):
        return "Ed25519"
    return None


def _openssh_host_identity_metadata(key: object, family: str) -> tuple[str, int]:
    """The frozen Algorithm/Key Size pair (Issue #88 Section 3) for ``key``,
    already confirmed to belong to ``family`` by
    ``_openssh_host_identity_key_family``."""
    if family == "RSA":
        return "RSA", key.key_size
    if family == "ECDSA":
        return f"EC ({key.curve.name})", key.key_size
    return "Ed25519", 256


# The four private-key PEM/OpenSSH labels HG-043 itself may classify (Issue
# #88 Section 7).
_OPENSSH_PRIVATE_KEY_LABELS = (
    "OPENSSH PRIVATE KEY",
    "PRIVATE KEY",
    "RSA PRIVATE KEY",
    "EC PRIVATE KEY",
)

# Every private-key/certificate/public-key PEM or OpenSSH BEGIN label the
# whole-file framing check (Issue #88 Section 8, step 6) must recognize as a
# second identity when it appears anywhere in the stripped content, not only
# the four labels HG-043 itself accepts.
_OPENSSH_ANY_IDENTITY_BEGIN_LABELS = (
    "OPENSSH PRIVATE KEY",
    "PRIVATE KEY",
    "ENCRYPTED PRIVATE KEY",
    "RSA PRIVATE KEY",
    "DSA PRIVATE KEY",
    "EC PRIVATE KEY",
    "PUBLIC KEY",
    "CERTIFICATE",
)

# Permitted outer whitespace bytes for private-candidate whole-file framing
# (Issue #88 Section 8): SP, HT, LF, CR, VT, FF -- exactly these six, no other
# byte value.
_OPENSSH_OUTER_WHITESPACE = bytes((0x20, 0x09, 0x0A, 0x0D, 0x0B, 0x0C))


def _openssh_private_key_block(data: bytes) -> tuple[str, bytes] | None:
    """The (label, complete stripped one-block bytes) a private candidate's
    whole-file framing (Issue #88 Section 8) resolves to, or None when
    ``data`` does not satisfy that framing.

    Outer permitted whitespace is stripped from both ends first. What remains
    must begin with exactly one accepted BEGIN line, must contain the
    matching END line for that same label, that END line must terminate the
    remaining content exactly (nothing, not even whitespace, follows it --
    already guaranteed by the outer strip), and no second BEGIN marker for
    any private-key/certificate/public-key PEM/OpenSSH identity may appear
    anywhere in the stripped content. The full stripped block -- never a
    truncated substring -- is what the caller passes to the parser.
    """
    stripped = data.strip(_OPENSSH_OUTER_WHITESPACE)
    if not stripped:
        return None
    label = None
    for candidate_label in _OPENSSH_PRIVATE_KEY_LABELS:
        begin_line = f"-----BEGIN {candidate_label}-----".encode("ascii")
        if stripped.startswith(begin_line):
            label = candidate_label
            break
    if label is None:
        return None
    end_marker = f"-----END {label}-----".encode("ascii")
    end_index = stripped.find(end_marker)
    if end_index == -1:
        return None
    if end_index + len(end_marker) != len(stripped):
        return None
    for other_label in _OPENSSH_ANY_IDENTITY_BEGIN_LABELS:
        other_begin = f"-----BEGIN {other_label}-----".encode("ascii")
        occurrences = stripped.count(other_begin)
        expected = 1 if other_label == label else 0
        if occurrences != expected:
            return None
    return label, stripped


def _openssh_load_host_private_key(label: str, block: bytes) -> object | None:
    """Parse ``block`` (the complete stripped one-block bytes
    ``_openssh_private_key_block`` returned for ``label``) with the exact
    parser Issue #88 Section 7 assigns to that label, password-less.

    Returns the parsed key, or None for every no-match Section 13 declares
    expected for that parser -- absent, encrypted, unsupported, or (for the
    two traditional PEM labels) not the algorithm class that label's own
    grammar requires. Any other exception is not caught here and propagates
    to the shared detector-error boundary; this function never uses a
    catch-all exception clause.
    """
    if label == "OPENSSH PRIVATE KEY":
        try:
            return serialization.load_ssh_private_key(block, password=None)
        except (ValueError, TypeError, UnsupportedAlgorithm):
            return None
    try:
        key = serialization.load_pem_private_key(block, password=None)
    except (ValueError, TypeError, UnsupportedAlgorithm):
        return None
    if label == "RSA PRIVATE KEY" and not isinstance(key, rsa.RSAPrivateKey):
        return None
    if label == "EC PRIVATE KEY" and not isinstance(key, ec.EllipticCurvePrivateKey):
        return None
    return key


def _openssh_host_private_key_candidate(context: FileContext) -> bool:
    return context.name in _OPENSSH_HOST_PRIVATE_BASENAMES


def _detect_openssh_host_private_key(context: FileContext) -> DetectionResult:
    expected_family = _OPENSSH_HOST_PRIVATE_BASENAMES[context.name]
    block = _openssh_private_key_block(context.data)
    if block is None:
        return DetectionResult.no_match()
    label, block_bytes = block
    key = _openssh_load_host_private_key(label, block_bytes)
    if key is None:
        return DetectionResult.no_match()
    family = _openssh_host_identity_key_family(key)
    if family is None or family != expected_family:
        return DetectionResult.no_match()
    algorithm, key_size = _openssh_host_identity_metadata(key, family)
    return DetectionResult.match(
        [
            CryptoInventoryFinding(
                asset_type="OpenSSH Host Private Key Candidate",
                location=context.location,
                algorithm=algorithm,
                key_size=key_size,
                evidence=(
                    "Supported private key observed at canonical OpenSSH "
                    "host-key filename"
                ),
                confidence="Medium",
                rule_id=_OPENSSH_PRIVATE_RULE_ID,
            )
        ],
        terminal=True,
    )


_OPENSSH_ONE_RECORD_RE = re.compile(rb"\A([^ \t]+)[ \t]+([^ \t]+)(?:[ \t].*)?\Z", re.DOTALL)


def _openssh_one_record_fields(data: bytes) -> tuple[bytes, bytes] | None:
    """The (algorithm token, base64 blob) fields of the single OpenSSH
    public-key or certificate record in ``data``, once every requirement of
    the shared outer one-record grammar (Issue #88 Sections 10-11) has been
    checked, or None when ``data`` does not satisfy that grammar.

    The trailing comment field, when present, is deliberately not returned:
    the grammar forbids decoding, retaining, or emitting comment bytes, so
    this helper does not hand them back to its caller at all.
    """
    body = data
    if body.endswith(b"\r\n"):
        body = body[:-2]
    elif body.endswith(b"\n"):
        body = body[:-1]
    if b"\r" in body or b"\n" in body:
        return None
    record = body.strip(b" \t")
    if not record:
        return None
    match = _OPENSSH_ONE_RECORD_RE.match(record)
    if match is None:
        return None
    return match.group(1), match.group(2)


def _openssh_host_public_key_candidate(context: FileContext) -> bool:
    return context.name in _OPENSSH_HOST_PUBLIC_BASENAMES


def _detect_openssh_host_public_key(context: FileContext) -> DetectionResult:
    expected_family = _OPENSSH_HOST_PUBLIC_BASENAMES[context.name]
    fields = _openssh_one_record_fields(context.data)
    if fields is None:
        return DetectionResult.no_match()
    algorithm_token, base64_blob = fields
    if algorithm_token not in _OPENSSH_PLAIN_ALGORITHM_TOKENS:
        return DetectionResult.no_match()
    try:
        key = serialization.load_ssh_public_key(algorithm_token + b" " + base64_blob)
    except (ValueError, UnsupportedAlgorithm):
        return DetectionResult.no_match()
    family = _openssh_host_identity_key_family(key)
    if family is None or family != expected_family:
        return DetectionResult.no_match()
    algorithm, key_size = _openssh_host_identity_metadata(key, family)
    return DetectionResult.match(
        [
            CryptoInventoryFinding(
                asset_type="OpenSSH Host Public Key Candidate",
                location=context.location,
                algorithm=algorithm,
                key_size=key_size,
                evidence=(
                    "Supported SSH public key observed at canonical OpenSSH "
                    "host-public-key filename"
                ),
                confidence="Medium",
                rule_id=_OPENSSH_PUBLIC_RULE_ID,
            )
        ],
        terminal=True,
    )


def _openssh_host_certificate_candidate(context: FileContext) -> bool:
    """Whether ``context`` is worth handing to ``_detect_openssh_host_certificate``.

    Deliberately reuses ``_openssh_one_record_fields`` -- the same shared
    one-record grammar parser ``detect`` itself calls -- rather than a
    separate leading-bytes prefix check, so this gate can never reject a
    record ``detect`` would otherwise accept. A byte-literal
    ``token + b" "`` prefix check previously rejected every real-world record
    with a leading SP/HT (both permitted by Issue #88 Section 11's outer
    grammar) or an HT field separator, silently making the detector
    unreachable for those inputs even though its own parsing logic already
    handled them correctly.
    """
    fields = _openssh_one_record_fields(context.data)
    if fields is None:
        return False
    algorithm_token, _ = fields
    return algorithm_token in _OPENSSH_CERT_ALGORITHM_TOKENS


def _detect_openssh_host_certificate(context: FileContext) -> DetectionResult:
    fields = _openssh_one_record_fields(context.data)
    if fields is None:
        return DetectionResult.no_match()
    algorithm_token, base64_blob = fields
    if algorithm_token not in _OPENSSH_CERT_ALGORITHM_TOKENS:
        return DetectionResult.no_match()
    try:
        identity = serialization.load_ssh_public_identity(algorithm_token + b" " + base64_blob)
    except (ValueError, UnsupportedAlgorithm):
        return DetectionResult.no_match()
    if not isinstance(identity, serialization.SSHCertificate):
        return DetectionResult.no_match()
    if identity.type is not serialization.SSHCertificateType.HOST:
        return DetectionResult.no_match()
    try:
        certified_key = identity.public_key()
    except UnsupportedAlgorithm:
        return DetectionResult.no_match()
    certified_family = _openssh_host_identity_key_family(certified_key)
    if certified_family is None:
        return DetectionResult.no_match()
    try:
        signing_key = identity.signature_key()
    except UnsupportedAlgorithm:
        return DetectionResult.no_match()
    if _openssh_host_identity_key_family(signing_key) is None:
        return DetectionResult.no_match()
    algorithm, key_size = _openssh_host_identity_metadata(certified_key, certified_family)
    return DetectionResult.match(
        [
            CryptoInventoryFinding(
                asset_type="OpenSSH Host Certificate",
                location=context.location,
                algorithm=algorithm,
                key_size=key_size,
                evidence="OpenSSH host certificate structure detected",
                confidence="High",
                rule_id=_OPENSSH_HOST_CERTIFICATE_RULE_ID,
            )
        ],
        terminal=True,
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


def _java_truststore_jks_candidate(context: FileContext) -> bool:
    """The cheap leading-byte gate for the JKS trusted-certificate-only
    detector: the JKS magic at offset 0, which is the one condition the store
    parser requires before it can return True.

    Content only, and deliberately not behind ``_passes_candidate_gate``: that
    gate admits files by extension, and a store named ``cacerts`` -- the single
    most common name for exactly this kind of file -- has none.
    """
    return _looks_like_jks(context.leading_bytes(len(_JKS_MAGIC)))


def _java_truststore_jceks_candidate(context: FileContext) -> bool:
    """The same gate for the JCEKS trusted-certificate-only detector: the JCEKS
    magic at offset 0. Content only, for the same reason."""
    return context.leading_bytes(len(_JCEKS_MAGIC)) == _JCEKS_MAGIC


def _detect_java_truststore_jks(context: FileContext) -> DetectionResult:
    # The full bytes are required, not a prefix: the entry table is validated
    # against the reserved trailer at the end of the file, and "exactly 20 bytes
    # remain" is only meaningful against the whole file. The bytes are already in
    # the shared context, so this is not an extra read.
    if not _looks_like_trusted_certificate_only_store(context.data, _JKS_MAGIC):
        # Not a no-match this detector can narrow: the file falls through to the
        # generic JKS detector, which stays the owner of every malformed,
        # unsupported, key-bearing, and mixed JKS store.
        return DetectionResult.no_match()
    return DetectionResult.match([_java_truststore_finding(context.path, "JKS")])


def _detect_java_truststore_jceks(context: FileContext) -> DetectionResult:
    if not _looks_like_trusted_certificate_only_store(context.data, _JCEKS_MAGIC):
        return DetectionResult.no_match()
    return DetectionResult.match([_java_truststore_finding(context.path, "JCEKS")])


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


# --- HG-044: Kubernetes TLS Secret manifest evidence (Issue #89) ------------
#
# One aggregate finding per supported local `kubernetes.io/tls` Secret
# *document*: this manifest document structurally declares a Kubernetes v1 TLS
# Secret whose effective `tls.crt`/`tls.key` values hold a supported X.509
# certificate chain and a matching unencrypted private key. It establishes
# nothing about cluster existence, workload use, trust, validity, or safety --
# the manifest is read from the bytes the scanner already loaded, and no
# Kubernetes API, kubeconfig, kubectl, Helm, Kustomize, OpenSSL, external
# process, or network is ever touched.

_KUBERNETES_TLS_RULE_ID = "kubernetes_secret:tls"
_KUBERNETES_TLS_ASSET_TYPE = "Kubernetes TLS Secret"
_KUBERNETES_TLS_EVIDENCE = (
    "Kubernetes TLS Secret manifest with matching certificate and private key "
    "detected"
)
_KUBERNETES_TLS_METADATA_KEYS = frozenset({"Algorithm", "Key Size", "Format"})
_KUBERNETES_JSON_FORMAT = "Kubernetes JSON Manifest"
_KUBERNETES_YAML_FORMAT = "Kubernetes YAML Manifest"

# The content gate (Issue #89 "Candidate Gate"): all three literal tokens must
# appear in the file's bounded text view. Extension is never evidence -- a
# manifest saved with no extension, or with a misleading one no earlier
# terminal detector claims, classifies identically.
_KUBERNETES_TLS_GATE_TOKENS = ("kubernetes.io/tls", "tls.crt", "tls.key")

# The two required Secret keys, in the fixed order the effective-value
# resolution walks them.
_KUBERNETES_TLS_CERTIFICATE_KEY = "tls.crt"
_KUBERNETES_TLS_PRIVATE_KEY_KEY = "tls.key"

# Preflight resource bounds (Issue #89 "Preflight bounds"). The text-size bound
# is the scanner's existing MAX_TEXT_BYTES, already applied by `FileContext`.
_KUBERNETES_MAX_YAML_DOCUMENTS = 64
_KUBERNETES_MAX_YAML_DEPTH = 64
_KUBERNETES_MAX_YAML_EVENTS = 100_000

# The ECDSA curves HG-044 accepts. Every other curve -- and DSA, Ed448, and
# every other key class -- is an ordinary no-match, not a supported key with
# unusual metadata.
_KUBERNETES_ACCEPTED_CURVES = frozenset({"secp256r1", "secp384r1", "secp521r1"})

# Serialization dispatch strips only these four bytes from the front (Issue #89
# "Serialization Dispatch"); a BOM is deliberately not among them.
_KUBERNETES_DISPATCH_WHITESPACE = " \t\r\n"

# Permitted outer/inter-block whitespace inside an effective `tls.crt`/`tls.key`
# value: SP, HT, LF, CR, VT, FF -- exactly these six byte values. A BOM is not
# whitespace.
_KUBERNETES_PEM_WHITESPACE = bytes((0x20, 0x09, 0x0A, 0x0D, 0x0B, 0x0C))
_KUBERNETES_PEM_WHITESPACE_SET = frozenset(_KUBERNETES_PEM_WHITESPACE)
_KUBERNETES_CERTIFICATE_LABELS = ("CERTIFICATE",)
# Exactly the three private-key labels Issue #89 accepts. `ENCRYPTED PRIVATE
# KEY` is absent on purpose: an encrypted PKCS#8 value is a no-match here, not
# a password prompt.
_KUBERNETES_PRIVATE_KEY_LABELS = (
    "PRIVATE KEY",
    "RSA PRIVATE KEY",
    "EC PRIVATE KEY",
)
_UTF8_BOM_TEXT = "﻿"


class _KubernetesJsonRejected(Exception):
    """A deterministic HG-044 rejection of JSON manifest text: a repeated exact
    string key at some nested object level, or a non-finite JSON constant.

    Private to this module and raised only from the ``json.loads`` hooks, so
    the JSON no-match boundary can name it explicitly instead of widening to a
    bare ``except Exception``. Carries no manifest content.
    """


class _KubernetesYamlRejected(Exception):
    """A deterministic HG-044 rejection of YAML manifest text raised by this
    module's own preflight or construction rules -- a bound exceeded, an alias,
    anchor, explicit tag, or directive, a non-string or complex mapping key, a
    ``<<`` merge key, or a duplicate mapping key.

    Private to this module, deliberately *not* a ``yaml.YAMLError``, and
    carrying no manifest content.
    """


class _KubernetesDocumentCountMismatch(RuntimeError):
    """The constructed YAML document count disagreed with the preflight
    ``DocumentStartEvent`` count.

    Issue #89 declares this an implementation defect rather than a no-match, so
    it is never suppressed: it reaches the shared detector-error boundary and
    surfaces as a sanitized ``DetectorExecutionError`` naming only the detector
    id, the physical file location, and this exception's type.
    """


def _kubernetes_json_object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """``json.loads``'s ``object_pairs_hook``: reject a repeated exact string key
    *before* constructing the object, at every nesting level.

    Python's decoder is last-wins by default, which would silently pick one of
    two conflicting ``tls.key`` values. HG-044 refuses to guess.
    """
    seen: set[str] = set()
    for key, _value in pairs:
        if key in seen:
            raise _KubernetesJsonRejected("duplicate JSON object key")
        seen.add(key)
    return dict(pairs)


def _kubernetes_json_reject_constant(name: str) -> Any:
    """``json.loads``'s ``parse_constant``: reject ``NaN``, ``Infinity``, and
    ``-Infinity``, which Python's decoder accepts by default and strict JSON
    does not define."""
    raise _KubernetesJsonRejected("non-finite JSON constant")


def _kubernetes_json_documents(text: str) -> list[tuple[int, Any]] | None:
    """The single JSON manifest document in ``text`` as ``[(1, object)]``, or
    None for every expected JSON no-match.

    Standard library only. Exactly one JSON value plus JSON whitespace is
    permitted (``json.loads`` already enforces that), the value must be a
    top-level object, and duplicate keys and non-finite constants reject
    through the two hooks above. A top-level array -- the unsupported
    ``SecretList``/``kind: List`` shape's usual spelling -- is parsed only to be
    rejected here; it never falls back to YAML handling.
    """
    try:
        value = json.loads(
            text,
            object_pairs_hook=_kubernetes_json_object_pairs,
            parse_constant=_kubernetes_json_reject_constant,
        )
    except (
        json.JSONDecodeError,
        RecursionError,
        ValueError,
        _KubernetesJsonRejected,
    ):
        # ValueError covers the standard decoder's own bounded numeric
        # conversion failure; JSONDecodeError is its subclass. Nothing broader
        # is suppressed.
        return None
    if not isinstance(value, dict):
        return None
    return [(1, value)]


class _KubernetesManifestLoader(yaml.BaseLoader):
    """The only loader HG-044 ever points at target input.

    ``yaml.BaseLoader`` -- never ``Loader``, ``FullLoader``, ``UnsafeLoader``,
    ``SafeLoader``, or their C variants -- so no Python object is ever
    constructed and every scalar stays its exact constructed text. The one
    override tightens mapping construction: every key at every level must
    construct as a scalar string, a key exactly equal to ``<<`` is rejected
    however it was quoted, and a duplicate key rejects rather than last-wins.
    """

    def construct_mapping(self, node: Any, deep: bool = False) -> dict[str, Any]:
        mapping: dict[str, Any] = {}
        for key_node, value_node in node.value:
            if not isinstance(key_node, yaml.ScalarNode):
                raise _KubernetesYamlRejected("complex YAML mapping key")
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str):
                raise _KubernetesYamlRejected("non-string YAML mapping key")
            if key == "<<":
                raise _KubernetesYamlRejected("YAML merge key")
            if key in mapping:
                raise _KubernetesYamlRejected("duplicate YAML mapping key")
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping


def _kubernetes_yaml_preflight(text: str) -> int | None:
    """The number of YAML documents in ``text`` once every preflight bound and
    prohibition holds, or None when the *complete file* is rejected.

    Event-level only: nothing is constructed here. Every event is counted;
    aliases, anchors, explicit tags, and YAML/TAG directives are refused
    outright; collection starts and ends are matched on one typed stack; and
    the document, depth, and event bounds are enforced as the stream is read.
    Rejection is always whole-file, before any document is evaluated.
    """
    events = 0
    documents = 0
    depth: list[type] = []
    try:
        for event in yaml.parse(text, Loader=yaml.BaseLoader):
            events += 1
            if events > _KUBERNETES_MAX_YAML_EVENTS:
                return None
            if isinstance(event, yaml.events.AliasEvent):
                return None
            if getattr(event, "anchor", None) is not None:
                return None
            if isinstance(
                event,
                (
                    yaml.events.ScalarEvent,
                    yaml.events.MappingStartEvent,
                    yaml.events.SequenceStartEvent,
                ),
            ) and event.tag is not None:
                return None
            if isinstance(event, yaml.events.DocumentStartEvent):
                if event.version is not None or event.tags is not None:
                    return None
                documents += 1
                if documents > _KUBERNETES_MAX_YAML_DOCUMENTS:
                    return None
            elif isinstance(
                event,
                (yaml.events.MappingStartEvent, yaml.events.SequenceStartEvent),
            ):
                depth.append(type(event))
                if len(depth) > _KUBERNETES_MAX_YAML_DEPTH:
                    return None
            elif isinstance(event, yaml.events.MappingEndEvent):
                if not depth or depth.pop() is not yaml.events.MappingStartEvent:
                    return None
            elif isinstance(event, yaml.events.SequenceEndEvent):
                if not depth or depth.pop() is not yaml.events.SequenceStartEvent:
                    return None
    except yaml.YAMLError:
        return None
    if depth:
        return None
    return documents


def _kubernetes_yaml_documents(text: str) -> list[tuple[int, Any]] | None:
    """Every YAML document in ``text`` as ``[(one-based index, object), ...]``,
    or None when the complete file is rejected.

    Document numbering is the one-based ordinal of each ``DocumentStartEvent``
    in the preflight stream, so empty and non-matching documents still consume
    an index and source order alone decides identity. Construction runs only
    after the whole stream passed preflight; a disagreement between the two
    counts is a defect, not a no-match, and is raised rather than swallowed.
    """
    document_count = _kubernetes_yaml_preflight(text)
    if document_count is None:
        return None
    try:
        documents = list(yaml.load_all(text, Loader=_KubernetesManifestLoader))
    except (yaml.YAMLError, _KubernetesYamlRejected):
        return None
    if len(documents) != document_count:
        raise _KubernetesDocumentCountMismatch(
            "constructed YAML document count disagreed with the preflight count"
        )
    return list(enumerate(documents, start=1))


def _kubernetes_manifest_documents(text: str) -> list[tuple[int, Any, str]] | None:
    """Every manifest document in ``text`` as ``(index, object, Format)``, or
    None when the file is not a supported manifest serialization at all.

    Dispatch is by first non-whitespace byte after removing only SP/HT/CR/LF:
    ``{`` or ``[`` selects JSON-only handling (the second only to confirm and
    reject the unsupported top-level array), and everything else selects
    YAML-only handling. A JSON candidate that fails strict JSON parsing never
    falls back to YAML. A UTF BOM rejects outright.
    """
    if text.startswith(_UTF8_BOM_TEXT):
        return None
    leading = text.lstrip(_KUBERNETES_DISPATCH_WHITESPACE)
    if leading[:1] in ("{", "["):
        documents = _kubernetes_json_documents(text)
        manifest_format = _KUBERNETES_JSON_FORMAT
    else:
        documents = _kubernetes_yaml_documents(text)
        manifest_format = _KUBERNETES_YAML_FORMAT
    if documents is None:
        return None
    return [(index, document, manifest_format) for index, document in documents]


def _kubernetes_strict_base64(value: str) -> bytes | None:
    """The bytes a ``data`` value decodes to under HG-044's strict canonical
    RFC 4648 profile, or None when it does not qualify.

    ASCII only, no whitespace of any kind, standard alphabet and padding,
    non-empty decoded output, and a standard padded re-encoding that reproduces
    the source byte for byte -- which is what rejects the noncanonical final
    quantum an ordinary decoder would accept.
    """
    if not value or not value.isascii():
        return None
    encoded = value.encode("ascii")
    try:
        decoded = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError):
        return None
    if not decoded or base64.b64encode(decoded) != encoded:
        return None
    return decoded


def _kubernetes_pem_blocks(
    data: bytes, labels: tuple[str, ...]
) -> list[tuple[str, bytes]] | None:
    """Every complete PEM block in ``data`` under HG-044's whole-value framing,
    or None when ``data`` is not exactly a sequence of such blocks.

    Deliberately not ``_extract_pem_blocks``: that helper searches for markers
    inside arbitrary surrounding text, which would let a decoded Secret value
    carry a prefix, a suffix, or an unrelated PEM block alongside the material
    HG-044 claims to have validated. Here the complete value, after removing
    only the six permitted whitespace bytes, must be consumed by adjacent
    blocks whose BEGIN/END delimiter lines are exact, share one label, and
    carry no leading or trailing content of their own.
    """
    stripped = data.strip(_KUBERNETES_PEM_WHITESPACE)
    if not stripped:
        return None
    blocks: list[tuple[str, bytes]] = []
    offset = 0
    size = len(stripped)
    while offset < size:
        while offset < size and stripped[offset] in _KUBERNETES_PEM_WHITESPACE_SET:
            offset += 1
        if offset >= size:
            break
        label = None
        for candidate in labels:
            begin = f"-----BEGIN {candidate}-----".encode("ascii")
            if stripped.startswith(begin, offset):
                label = candidate
                break
        if label is None:
            return None
        begin_end = offset + len(f"-----BEGIN {label}-----")
        if stripped[begin_end : begin_end + 1] not in (b"\n", b"\r"):
            return None
        end_marker = f"-----END {label}-----".encode("ascii")
        end_index = stripped.find(end_marker, begin_end)
        if end_index == -1:
            return None
        if stripped[end_index - 1 : end_index] not in (b"\n", b"\r"):
            return None
        block_end = end_index + len(end_marker)
        # The END delimiter line must be exact and carry no trailing content
        # of its own: the byte immediately following the marker must end that
        # line (a bare LF, or the start of a CRLF pair) or the marker must run
        # to the exact end of the value. Anything else -- including further
        # permitted whitespace bytes such as a trailing space or tab -- is
        # content on the same line as "-----END <LABEL>-----" and must reject
        # the whole value, not be silently treated as ordinary inter-block
        # whitespace by the next iteration's whitespace-skip loop.
        if block_end != size and stripped[block_end : block_end + 1] not in (b"\n", b"\r"):
            return None
        blocks.append((label, stripped[offset:block_end]))
        offset = block_end
    if not blocks:
        return None
    return blocks


def _kubernetes_certificates(data: bytes) -> list[x509.Certificate] | None:
    """Every X.509 certificate in an effective ``tls.crt`` value, or None when
    the value is not exactly one or more complete, parsable ``CERTIFICATE``
    blocks. The first certificate is the key-match target; the rest are parsed
    structurally and otherwise unused -- no chain is built, no signature,
    subject, hostname, or date is checked, and no certificate identity is
    reported."""
    blocks = _kubernetes_pem_blocks(data, _KUBERNETES_CERTIFICATE_LABELS)
    if blocks is None:
        return None
    certificates = []
    for _label, block in blocks:
        try:
            certificates.append(x509.load_pem_x509_certificate(block))
        except ValueError:
            return None
    return certificates


def _kubernetes_private_key(data: bytes) -> Any | None:
    """The single unencrypted private key in an effective ``tls.key`` value, or
    None for every expected no-match: not exactly one accepted-label block, an
    encrypted or malformed body, or an unsupported algorithm. Parsed
    password-less; no password is ever prompted for, guessed, read from the
    environment, or accepted."""
    blocks = _kubernetes_pem_blocks(data, _KUBERNETES_PRIVATE_KEY_LABELS)
    if blocks is None or len(blocks) != 1:
        return None
    try:
        return serialization.load_pem_private_key(blocks[0][1], password=None)
    except (ValueError, TypeError, UnsupportedAlgorithm):
        return None


def _kubernetes_key_metadata(key: Any) -> tuple[str, int] | None:
    """The frozen Algorithm/Key Size pair for an accepted HG-044 private key, or
    None when the key's class or (for ECDSA) curve falls outside the accepted
    profile.

    The class and curve boundary is checked here, independently, *before*
    deferring to the repository's shared ``_key_algorithm_and_size`` for the
    values themselves -- so HG-044 cannot silently inherit a future widening of
    that helper (DSA and Ed448, which the helper does describe, are HG-044
    no-matches).
    """
    if isinstance(key, rsa.RSAPrivateKey):
        pass
    elif isinstance(key, ec.EllipticCurvePrivateKey):
        if key.curve.name not in _KUBERNETES_ACCEPTED_CURVES:
            return None
    elif not isinstance(key, ed25519.Ed25519PrivateKey):
        return None
    algorithm, key_size = _key_algorithm_and_size(key)
    if key_size is None:
        return None
    return algorithm, key_size


def _kubernetes_effective_tls_values(document: dict) -> dict[str, bytes] | None:
    """The effective ``tls.crt``/``tls.key`` bytes for one supported Secret
    document, or None when the document does not qualify.

    ``stringData`` wins over ``data`` for the same key, exactly as Kubernetes
    resolves a write-time Secret, and the win is unconditional: an empty or
    otherwise unusable ``stringData`` value overrides and rejects the document
    rather than falling back to ``data``. A selected ``stringData`` scalar is
    encoded as UTF-8 exactly as the parser constructed it, with no further
    Unicode or newline normalization; a selected ``data`` value goes through the
    strict canonical base64 profile. Unrelated Secret values are shape-checked
    and never decoded.
    """
    sections: dict[str, dict] = {}
    for name in ("data", "stringData"):
        if name not in document:
            continue
        section = document[name]
        if not isinstance(section, dict):
            return None
        for key, value in section.items():
            if not isinstance(key, str) or not isinstance(value, str):
                return None
        sections[name] = section
    if not sections:
        return None
    resolved: dict[str, bytes] = {}
    for key in (_KUBERNETES_TLS_CERTIFICATE_KEY, _KUBERNETES_TLS_PRIVATE_KEY_KEY):
        string_data = sections.get("stringData", {})
        data = sections.get("data", {})
        if key in string_data:
            value = string_data[key].encode("utf-8")
        elif key in data:
            value = _kubernetes_strict_base64(data[key])
        else:
            return None
        if not value:
            return None
        resolved[key] = value
    return resolved


def _kubernetes_tls_secret_finding(
    location: str, document: Any
) -> tuple[str, int] | None:
    """The Algorithm/Key Size pair for one qualifying TLS Secret document, or
    None when this document is an ordinary no-match.

    ``location`` is accepted only to keep the caller's shape obvious; nothing
    from the document -- name, namespace, labels, annotations, unrelated Secret
    values, certificate identity, or key material -- is read into it or into
    anything this function returns.
    """
    if not isinstance(document, dict):
        return None
    if document.get("apiVersion") != "v1":
        return None
    if document.get("kind") != "Secret":
        return None
    if document.get("type") != "kubernetes.io/tls":
        return None
    values = _kubernetes_effective_tls_values(document)
    if values is None:
        return None
    certificates = _kubernetes_certificates(values[_KUBERNETES_TLS_CERTIFICATE_KEY])
    if not certificates:
        return None
    key = _kubernetes_private_key(values[_KUBERNETES_TLS_PRIVATE_KEY_KEY])
    if key is None:
        return None
    metadata = _kubernetes_key_metadata(key)
    if metadata is None:
        return None
    try:
        certificate_public_key = certificates[0].public_key()
    except (ValueError, UnsupportedAlgorithm):
        # A certificate public-key algorithm `cryptography` does not support:
        # ValueError before 47.0.0, UnsupportedAlgorithm from 47.0.0 on. Both
        # are ordinary HG-044 no-matches.
        return None
    encoding = serialization.Encoding.DER
    public_format = serialization.PublicFormat.SubjectPublicKeyInfo
    if certificate_public_key.public_bytes(encoding, public_format) != key.public_key(
        ).public_bytes(encoding, public_format):
        return None
    return metadata


def _kubernetes_tls_secret_candidate(context: FileContext) -> bool:
    """HG-044's content gate: a bounded text view that literally contains all
    three required tokens. Extension is never evidence, and the gate only limits
    how often the manifest parsers run -- it is not itself a finding
    condition."""
    text = context.text
    if text is None:
        return False
    return all(token in text for token in _KUBERNETES_TLS_GATE_TOKENS)


def _detect_kubernetes_tls_secret(context: FileContext) -> DetectionResult:
    text = context.text
    if text is None:
        return DetectionResult.no_match()
    documents = _kubernetes_manifest_documents(text)
    if documents is None:
        return DetectionResult.no_match()
    findings: list[CryptoInventoryFinding] = []
    for index, document, manifest_format in documents:
        # The virtual document location identifies one object inside the file.
        # It is never claimed as a real filesystem path, and never carries the
        # Secret's name or namespace.
        location = f"{context.location}#document={index}"
        metadata = _kubernetes_tls_secret_finding(location, document)
        if metadata is None:
            continue
        algorithm, key_size = metadata
        findings.append(
            CryptoInventoryFinding(
                asset_type=_KUBERNETES_TLS_ASSET_TYPE,
                location=location,
                algorithm=algorithm,
                key_size=key_size,
                evidence=_KUBERNETES_TLS_EVIDENCE,
                confidence="High",
                rule_id=_KUBERNETES_TLS_RULE_ID,
                format=manifest_format,
            )
        )
    if not findings:
        return DetectionResult.no_match()
    return DetectionResult.match(findings)


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
            detector_id="java_truststore:jceks",
            priority=36,
            candidate=_java_truststore_jceks_candidate,
            detect=_detect_java_truststore_jceks,
            evidence="JCEKS trusted-certificate-only store structure detected",
            confidence="High",
            terminal=True,
            rule_id="java_truststore:jceks",
            metadata_keys=frozenset({"Format"}),
            verification_rationale=(
                "JCEKS magic at offset 0, a supported version, and the complete "
                "declared entry table read from the file's own bytes -- every "
                "entry a trusted-certificate entry with a canonically encoded "
                "alias, an exact X.509 certificate type where the version "
                "declares one, and a payload that parses as DER X.509 -- ending "
                "exactly at the reserved 20-byte trailer. Structure only: no "
                "password is requested or accepted, the trailer is neither read "
                "nor verified, no private-key body is parsed, no secret-key "
                "object is deserialized, keytool and Java are never invoked, and "
                "no alias or certificate identity is reported. It does not "
                "establish that any application uses the store for trust "
                "decisions."
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
            detector_id="java_truststore:jks",
            priority=39,
            candidate=_java_truststore_jks_candidate,
            detect=_detect_java_truststore_jks,
            evidence="JKS trusted-certificate-only store structure detected",
            confidence="High",
            terminal=True,
            rule_id="java_truststore:jks",
            metadata_keys=frozenset({"Format"}),
            verification_rationale=(
                "JKS magic at offset 0, a supported version, and the complete "
                "declared entry table read from the file's own bytes -- every "
                "entry a trusted-certificate entry with a canonically encoded "
                "alias, an exact X.509 certificate type where the version "
                "declares one, and a payload that parses as DER X.509 -- ending "
                "exactly at the reserved 20-byte trailer. Structure only: no "
                "password is requested or accepted, the trailer is neither read "
                "nor verified, no private-key body is parsed, keytool and Java "
                "are never invoked, and no alias or certificate identity is "
                "reported. It does not establish that any application uses the "
                "store for trust decisions."
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
            detector_id="openssh_host_identity:private_key",
            priority=76,
            candidate=_openssh_host_private_key_candidate,
            detect=_detect_openssh_host_private_key,
            evidence=(
                "Supported private key observed at canonical OpenSSH "
                "host-key filename"
            ),
            confidence="Medium",
            terminal=True,
            rule_id=_OPENSSH_PRIVATE_RULE_ID,
            metadata_keys=_OPENSSH_METADATA_KEYS,
            verification_rationale=(
                "Exact canonical OpenSSH host-private-key basename "
                "(ssh_host_rsa_key/ssh_host_ecdsa_key/ssh_host_ed25519_key) "
                "whose complete file, apart from permitted outer ASCII "
                "whitespace, is exactly one supported unencrypted private-key "
                "PEM/OpenSSH block, password-less parsed, and whose parsed "
                "key class agrees with the basename. Priority 76 places this "
                "after certificate PEM, legacy encrypted PEM, and every "
                "dedicated encrypted/container detector, and before generic "
                "private-key PEM at priority 80, so it never steals an "
                "encrypted or otherwise dedicated file; a no-match here "
                "(wrong algorithm, non-canonical name, encrypted, malformed, "
                "or multi-block) falls straight through to that generic "
                "detector unchanged (Issue #88)."
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
            detector_id="openssh_host_identity:public_key",
            priority=81,
            candidate=_openssh_host_public_key_candidate,
            detect=_detect_openssh_host_public_key,
            evidence=(
                "Supported SSH public key observed at canonical OpenSSH "
                "host-public-key filename"
            ),
            confidence="Medium",
            terminal=True,
            rule_id=_OPENSSH_PUBLIC_RULE_ID,
            metadata_keys=_OPENSSH_METADATA_KEYS,
            verification_rationale=(
                "Exact canonical OpenSSH host-public-key basename "
                "(ssh_host_rsa_key.pub/ssh_host_ecdsa_key.pub/"
                "ssh_host_ed25519_key.pub) whose complete file is exactly one "
                "OpenSSH public-key record under the shared one-record "
                "grammar, with a plain (non-certificate) accepted algorithm "
                "token, parsed successfully, and whose parsed key class "
                "agrees with the basename. Priority 81 places this before "
                "generic SSH public handling at priority 90 (Issue #88)."
            ),
        ),
        FileDetector(
            detector_id="openssh_host_identity:host_certificate",
            priority=82,
            candidate=_openssh_host_certificate_candidate,
            detect=_detect_openssh_host_certificate,
            evidence="OpenSSH host certificate structure detected",
            confidence="High",
            terminal=True,
            rule_id=_OPENSSH_HOST_CERTIFICATE_RULE_ID,
            metadata_keys=_OPENSSH_METADATA_KEYS,
            verification_rationale=(
                "One OpenSSH certificate record under the shared one-record "
                "grammar, with an accepted certificate algorithm token, "
                "structurally parsed via load_ssh_public_identity into an "
                "SSHCertificate whose encoded type is exactly HOST and whose "
                "certified key and signature key are both a supported "
                "RSA/ECDSA/Ed25519 family. No filename requirement; the "
                "certificate signature itself is deliberately never "
                "verified. Priority 82 places this before generic SSH public "
                "handling at priority 90 (Issue #88)."
            ),
        ),
        FileDetector(
            detector_id=_KUBERNETES_TLS_RULE_ID,
            priority=83,
            candidate=_kubernetes_tls_secret_candidate,
            detect=_detect_kubernetes_tls_secret,
            evidence=_KUBERNETES_TLS_EVIDENCE,
            confidence="High",
            terminal=False,
            rule_id=_KUBERNETES_TLS_RULE_ID,
            metadata_keys=_KUBERNETES_TLS_METADATA_KEYS,
            verification_rationale=(
                "One local manifest document that structurally declares a "
                "Kubernetes v1 `kubernetes.io/tls` Secret -- exact "
                "apiVersion/kind/type strings -- whose effective tls.crt and "
                "tls.key values, resolved under Kubernetes stringData-over-data "
                "precedence and (for data) a strict canonical RFC 4648 base64 "
                "profile, hold one or more complete PEM CERTIFICATE blocks and "
                "exactly one supported unencrypted PEM private key, with the "
                "key's public key byte-identical to the first certificate's in "
                "DER SubjectPublicKeyInfo form. Manifest bytes only: no "
                "Kubernetes API, kubeconfig, kubectl, Helm, Kustomize, OpenSSL, "
                "external process, or network is used, no password is "
                "accepted, and no Secret value, metadata, or certificate "
                "identity is reported. It establishes nothing about cluster "
                "existence, workload use, trust, validity, or safety. Priority 83 places "
                "this after every dedicated encrypted/container detector and "
                "after the generic certificate/private-key PEM detectors, so "
                "the independent physical-file findings those produce from the "
                "manifest's own source text coexist with this aggregate "
                "finding rather than being suppressed; decoded Secret values "
                "are validation-only and are never redispatched (Issue #89)."
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
        if not stripped:
            continue
        # OpenSSH certificate records (Issue #88 Sections 11, 26) are never a
        # generic public-key candidate at any confidence, matched or not: a
        # USER certificate and a HOST certificate HG-043 rejects both freeze
        # at zero findings, and this parser was never designed to describe
        # certificate content -- it has no certificate-specific evidence
        # wording, and reusing "OpenSSH Public Key"/"Malformed OpenSSH Public
        # Key" for one would misdescribe the asset and leak a fingerprint
        # this rule never intended to report for certificate input. Checked
        # against the first whitespace-separated token, not a startswith
        # prefix, so this is exact rather than relying on the loose
        # "ecdsa-sha2-" prefix below happening not to also match an ECDSA
        # certificate token.
        first_token = stripped.split(None, 1)[0]
        if first_token in _OPENSSH_CERT_ALGORITHM_TOKENS_TEXT:
            continue
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
