from __future__ import annotations

import argparse
import base64
import fnmatch
import json
import math
import os
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
    # Unset for every asset type except the two Encrypted File findings -- the
    # OpenSSL Salted__ signature (HG-030) and the OpenPGP encrypted-file
    # structure (HG-031): a rule_id is only meaningful for a finding backed by
    # a specific, nameable detection rule rather than a parsed certificate/key,
    # so every other asset type leaves this None rather than inventing one.
    rule_id: str | None = None
    # Encrypted-filesystem container metadata (HG-032 gocryptfs; kept generic
    # rather than gocryptfs-specific field names so a future container format
    # can reuse them). Unset for every other asset type. Deliberately limited
    # to what HG-032's privacy contract allows: a format name, the supported
    # on-disk config version observed, and the supported mode -- never the raw
    # config, key material, salts, or nonces.
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

    for file_path in _iter_candidate_files(
        root_path, patterns, follow_symlinks, traversal_errors
    ):
        files_inspected += 1
        try:
            findings.extend(_scan_file(file_path))
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
#   30 gocryptfs root ahead of the file-format branches and the gate for the
#      same reason -- gocryptfs.conf is plain JSON -- and terminal for its
#      marker file either way, so a rejected marker never falls through into
#      PEM/DER/PKCS#12 parsing (HG-032).
#   40-60 JKS, PKCS#12, and DER: mutually exclusive in practice, but each
#      terminal for the file it claims, which is what keeps a keystore or
#      container from also being read as PEM text.
#   70-90 The text detectors, deliberately non-terminal: one PEM file may
#      legitimately hold a certificate, a private key, and an SSH public key,
#      and all three are reported.
#
# Detectors below 70 are terminal; nothing here relies on a general "first
# detector wins" rule.


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
            detector_id="private_key:pem",
            priority=80,
            candidate=_text_candidate,
            detect=_detect_pem_private_keys,
            evidence="PEM block BEGIN <label>",
            confidence="High",
            metadata_keys=_KEY_METADATA_KEYS,
            verification_rationale=(
                "PEM/OpenSSH private-key block parsed with no passphrase; an "
                "encrypted block is identified by its header and reported "
                "without being decrypted."
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
    file_path: Path, detectors: tuple | None = None
) -> list[CryptoInventoryFinding]:
    """Every finding the detector registry produces for one file the scanner's
    traversal already selected.

    One read per file, shared by every detector through the file context -- the
    same single read this function performed before HG-033. An unreadable file
    (permission denied, vanished or replaced mid-scan) produces no findings and
    no evidence, unchanged.
    """
    context = FileContext(file_path)
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
        if label in {"CERTIFICATE", "OPENSSH PRIVATE KEY", "PUBLIC KEY"}:
            continue
        for block in _extract_pem_blocks(text, label):
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
