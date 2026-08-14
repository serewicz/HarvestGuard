"""HG-042: Java trusted-certificate-only store (JKS/JCEKS) detection.

What this detector claims is deliberately narrow: a structurally supported JKS or
JCEKS store whose *complete* declared entry table holds only supported trusted-
certificate entries. It is not a claim that any application uses the store for
trust decisions, that the certificates in it are trustworthy or current, that the
store is authenticated, or that a password is known. These tests pin that
boundary from both sides -- what must match, and the much longer list of things
that must fall through to the existing generic JKS/JCEKS detectors unchanged.

The positive version-2 coverage is grounded in real `keytool` output committed
under `tests/fixtures/crypto_inventory/`; the version-1 coverage is grounded in
byte-exact fixtures built from OpenJDK's own version-1 load grammar. Adversarial
inputs are composed here from those same real certificate bytes, so a negative
test is a controlled mutation of something real rather than an invented blob.
See the fixture directories' `PROVENANCE.md` for both.
"""

from __future__ import annotations

import hashlib
import json
import struct
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

import harvestguard
import scanner.crypto_inventory as crypto_inventory
from finding_adapters import normalize_crypto_inventory_df
from scanner.crypto_detectors import FileContext
from scanner.crypto_inventory import (
    CRYPTO_DETECTORS,
    scan_crypto_inventory,
    scan_crypto_inventory_findings,
)
from scanner.errors import LocalScanError

JKS_RULE_ID = "java_truststore:jks"
JCEKS_RULE_ID = "java_truststore:jceks"
ASSET_TYPE = "Java Trusted-Certificate-Only Store"
JKS_EVIDENCE = "JKS trusted-certificate-only store structure detected"
JCEKS_EVIDENCE = "JCEKS trusted-certificate-only store structure detected"
CONFIDENCE = "High"

# The existing generic keystore contracts HG-042 must never disturb. The generic
# JKS detector carries no rule id at all (its identity is the detector id
# `java_keystore:jks_magic`); giving it one would be a change to existing
# behavior, which HG-042 is explicitly out of scope for, so the fallback tests
# below assert its output exactly as it already is.
GENERIC_JKS_DETECTOR_ID = "java_keystore:jks_magic"
GENERIC_JKS_RULE_ID = None
GENERIC_JKS_ASSET_TYPE = "Java Keystore"
GENERIC_JKS_EVIDENCE = "JKS magic header detected"
GENERIC_JCEKS_RULE_ID = "java_keystore:jceks"
GENERIC_JCEKS_ASSET_TYPE = "Java Keystore"
GENERIC_JCEKS_EVIDENCE = "JCEKS keystore header detected"

JKS_MAGIC = b"\xfe\xed\xfe\xed"
JCEKS_MAGIC = b"\xce\xce\xce\xce"
TAG_TRUSTED_CERTIFICATE = 2
TAG_PRIVATE_KEY = 1
TAG_SECRET_KEY = 3
TRAILER = bytes(20)

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "crypto_inventory"
TRUSTSTORE_FIXTURES = FIXTURE_DIR / "java_truststore"
JCEKS_FIXTURES = FIXTURE_DIR / "jceks"

# Real `keytool` output (HG-042 fixtures) ...
JKS_V2_POSITIVE = TRUSTSTORE_FIXTURES / "trusted_certificate_store.jks"
JKS_V2_MULTI = TRUSTSTORE_FIXTURES / "multi_trusted_certificate_store.jks"
JKS_V2_NON_ASCII_ALIAS = TRUSTSTORE_FIXTURES / "non_ascii_alias_store.jks"
JKS_V2_PRIVATE_KEY = TRUSTSTORE_FIXTURES / "private_key_store.jks"
JKS_V2_MIXED = TRUSTSTORE_FIXTURES / "mixed_store.jks"
JCEKS_V2_MIXED = TRUSTSTORE_FIXTURES / "mixed_store.jceks"
# ... byte-constructed version-1 fixtures (no keytool writes version 1) ...
JKS_V1_POSITIVE = TRUSTSTORE_FIXTURES / "trusted_certificate_store_v1.jks"
JCEKS_V1_POSITIVE = TRUSTSTORE_FIXTURES / "trusted_certificate_store_v1.jceks"
# ... and the real HG-037 JCEKS stores, reused rather than duplicated.
JCEKS_V2_POSITIVE = JCEKS_FIXTURES / "trusted_certificate_store.jceks"
JCEKS_V2_PRIVATE_KEY = JCEKS_FIXTURES / "private_key_store.jceks"
JCEKS_V2_SECRET_KEY = JCEKS_FIXTURES / "secret_key_store.jceks"
JCEKS_V2_EMPTY = JCEKS_FIXTURES / "empty_store.jceks"

# Committed-fixture identity, so a test that "passes" cannot be passing against
# quietly regenerated or edited bytes.
FIXTURE_DIGESTS = {
    JKS_V2_POSITIVE: (
        808,
        "6731d3b5b6d486f7939ab3610e9f53fa75f00eb0aa07b719f31e827aada645b4",
    ),
    JKS_V2_MULTI: (
        1593,
        "300c4fdadc0ba58a47e51c9a3f545fdf5e5030588256b4f1ca9fa5e84c80ae18",
    ),
    JKS_V2_NON_ASCII_ALIAS: (
        822,
        "101af6556330a726daeab1bd1407e7905f163b5a723006668a057095accc1bb0",
    ),
    JKS_V2_PRIVATE_KEY: (
        2090,
        "2b9213fb94a51e4a277e4fc110b16f8e5c313052637dd5a3873db8ca3b78ca02",
    ),
    JKS_V2_MIXED: (
        2866,
        "d02513b60cee8d2c17c3cb5e5251ea97991e36de3b4c4d4817eea39a736ed729",
    ),
    JCEKS_V2_MIXED: (
        3334,
        "c1f4c11c05d7c3c420d9788bd793d0b03e14e972948537ad01873c5f106e1821",
    ),
    JKS_V1_POSITIVE: (
        801,
        "5f869d5c0004788d049d2a20d68ea5764294d5d4d71d79c035a594254a7bd46f",
    ),
    JCEKS_V1_POSITIVE: (
        801,
        "a437a1efd57c96486d8bf168c097cd2258b54a288f5aedd67eecfde9248d6615",
    ),
}

# Where the real DER certificate inside the version-1 fixtures starts: magic 4 +
# version 4 + entry count 4 + tag 4 + alias length field 2 + alias 8 +
# timestamp 8 + certificate length field 4. Version 1 has no certificate-type
# field, which is exactly what makes this offset 38 rather than 45.
_V1_CERTIFICATE_OFFSET = 38

# Unique, greppable values so the privacy tests can prove that neither an alias
# nor a certificate identity escapes into any output, persistence, or error
# surface.
CANARY_ALIAS = "canary-alias-6b41f9de"
CANARY_SUBJECT = "canary-subject-2d7ae05c"
CANARY_ISSUER = "canary-issuer-8f30cb1a"
CANARIES = (CANARY_ALIAS, CANARY_SUBJECT, CANARY_ISSUER)


# ---------------------------------------------------------------------------
# Byte helpers: real certificate material, composed stores
# ---------------------------------------------------------------------------


def _real_certificate() -> bytes:
    """The genuine `keytool`-generated DER certificate carried by the version-1
    fixture, reused so composed stores are mutations of something real."""
    data = JKS_V1_POSITIVE.read_bytes()
    length = struct.unpack(">i", data[_V1_CERTIFICATE_OFFSET - 4 : _V1_CERTIFICATE_OFFSET])[0]
    return data[_V1_CERTIFICATE_OFFSET : _V1_CERTIFICATE_OFFSET + length]


REAL_CERTIFICATE = _real_certificate()


def _canary_certificate() -> bytes:
    """A throwaway self-signed certificate whose subject and issuer carry
    canaries, used only to prove certificate identity never escapes."""
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, CANARY_SUBJECT)])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, CANARY_ISSUER)])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(0x0CA9A11)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def _utf(raw: bytes) -> bytes:
    """A `DataOutputStream.writeUTF` field around already-encoded bytes."""
    return struct.pack(">H", len(raw)) + raw


def _entry(
    *,
    version: int = 2,
    tag: int = TAG_TRUSTED_CERTIFICATE,
    alias: bytes = b"a1",
    timestamp: bytes = b"\x00\x00\x01\x8f\x1b\x2c\x3d\x4e",
    certificate_type: bytes | None = None,
    certificate: bytes | None = None,
    certificate_length: int | None = None,
) -> bytes:
    """One entry record in OpenJDK's own trusted-certificate framing.

    Every field is overridable so a negative test can mutate exactly one of them:
    ``certificate_type`` is written only for version 2 (version 1 has no such
    field), and ``certificate_length`` may disagree with the payload on purpose.
    """
    certificate = REAL_CERTIFICATE if certificate is None else certificate
    record = struct.pack(">i", tag) + _utf(alias) + timestamp
    if version == 2:
        record += _utf(b"X.509" if certificate_type is None else certificate_type)
    declared = len(certificate) if certificate_length is None else certificate_length
    return record + struct.pack(">i", declared) + certificate


def _store(
    magic: bytes = JKS_MAGIC,
    *,
    version: int = 2,
    entries: bytes | None = None,
    entry_count: int | None = None,
    trailer: bytes = TRAILER,
) -> bytes:
    entries = _entry(version=version) if entries is None else entries
    count = 1 if entry_count is None else entry_count
    return magic + struct.pack(">i", version) + struct.pack(">i", count) + entries + trailer


def _write(tmp_path: Path, data: bytes, name: str = "store.jks") -> Path:
    path = tmp_path / name
    path.write_bytes(data)
    return path


# ---------------------------------------------------------------------------
# Scan helpers
# ---------------------------------------------------------------------------


def _records(path: Path, **kwargs) -> list[dict]:
    df = scan_crypto_inventory(str(path), **kwargs)
    return [] if df.empty else df.to_dict(orient="records")


def _truststore_records(path: Path, **kwargs) -> list[dict]:
    return [
        r
        for r in _records(path, **kwargs)
        if r.get("Rule ID") in {JKS_RULE_ID, JCEKS_RULE_ID}
    ]


def _detector(detector_id: str):
    return next(d for d in CRYPTO_DETECTORS if d.detector_id == detector_id)


def _matches(data: bytes, magic: bytes = JKS_MAGIC) -> bool:
    """The store-level structural predicate, called directly so a negative test
    names the byte it mutated rather than an absent DataFrame row."""
    return crypto_inventory._looks_like_trusted_certificate_only_store(data, magic)


# ---------------------------------------------------------------------------
# Fixtures are the real, unmodified bytes
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("path", list(FIXTURE_DIGESTS))
def test_committed_fixtures_are_unmodified(path):
    size, digest = FIXTURE_DIGESTS[path]
    data = path.read_bytes()
    assert len(data) == size
    assert hashlib.sha256(data).hexdigest() == digest


def test_provenance_is_documented():
    assert (TRUSTSTORE_FIXTURES / "PROVENANCE.md").is_file()


@pytest.mark.parametrize(
    "path,magic,version",
    [
        (JKS_V2_POSITIVE, JKS_MAGIC, 2),
        (JCEKS_V2_POSITIVE, JCEKS_MAGIC, 2),
        (JKS_V1_POSITIVE, JKS_MAGIC, 1),
        (JCEKS_V1_POSITIVE, JCEKS_MAGIC, 1),
    ],
)
def test_fixture_headers_declare_the_expected_format_and_version(path, magic, version):
    data = path.read_bytes()
    assert data[:4] == magic
    assert struct.unpack(">i", data[4:8])[0] == version
    assert struct.unpack(">i", data[8:12])[0] >= 1
    # The trailer HG-042 reserves is present as the exact residual length.
    assert len(data) > 12 + 20


# ---------------------------------------------------------------------------
# Positive detection
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path,rule_id,evidence,store_format",
    [
        (JKS_V2_POSITIVE, JKS_RULE_ID, JKS_EVIDENCE, "JKS"),
        (JCEKS_V2_POSITIVE, JCEKS_RULE_ID, JCEKS_EVIDENCE, "JCEKS"),
        (JKS_V1_POSITIVE, JKS_RULE_ID, JKS_EVIDENCE, "JKS"),
        (JCEKS_V1_POSITIVE, JCEKS_RULE_ID, JCEKS_EVIDENCE, "JCEKS"),
    ],
)
def test_exact_finding_contract(path, rule_id, evidence, store_format):
    records = _records(path)
    assert len(records) == 1
    record = records[0]
    assert record["Rule ID"] == rule_id
    assert record["Asset Type"] == ASSET_TYPE
    assert record["Evidence"] == evidence
    assert record["Confidence"] == CONFIDENCE
    assert record["Format"] == store_format
    assert record["Location"] == str(path)
    assert record["Errors"] == ""


@pytest.mark.parametrize("path", [JKS_V2_POSITIVE, JCEKS_V2_POSITIVE, JKS_V1_POSITIVE])
def test_no_metadata_beyond_format_is_emitted(path):
    record = _records(path)[0]
    for key in (
        "Algorithm",
        "Key Size",
        "Signature Algorithm",
        "Expiration",
        "Issuer",
        "Subject",
        "Fingerprint",
        "Config Version",
        "Mode",
    ):
        assert record[key] is None


def test_asset_type_is_not_the_unqualified_java_truststore():
    """The product terminology boundary: the observed fact is a certificate-only
    store structure, never an established runtime truststore role."""
    record = _records(JKS_V2_POSITIVE)[0]
    assert record["Asset Type"] == "Java Trusted-Certificate-Only Store"
    assert record["Asset Type"] != "Java Truststore"


def test_multiple_trusted_certificate_entries_produce_exactly_one_finding():
    data = JKS_V2_MULTI.read_bytes()
    assert struct.unpack(">i", data[8:12])[0] == 2
    records = _records(JKS_V2_MULTI)
    assert len(records) == 1
    assert records[0]["Rule ID"] == JKS_RULE_ID


def test_many_entries_still_produce_one_finding(tmp_path):
    store = _store(entries=_entry() * 12, entry_count=12)
    records = _records(_write(tmp_path, store, "many.jks"))
    assert len(records) == 1
    assert records[0]["Rule ID"] == JKS_RULE_ID


def test_real_non_ascii_alias_matches_without_leaking_the_alias():
    data = JKS_V2_NON_ASCII_ALIAS.read_bytes()
    alias_length = struct.unpack(">H", data[16:18])[0]
    alias = data[18 : 18 + alias_length]
    # Real `writeUTF` output with canonical two-byte and three-byte sequences.
    assert b"\xc3\xbc" in alias and b"\xe2\x98\x83" in alias
    assert crypto_inventory._is_canonical_java_modified_utf(alias)

    records = _records(JKS_V2_NON_ASCII_ALIAS)
    assert len(records) == 1
    assert records[0]["Rule ID"] == JKS_RULE_ID
    payload = json.dumps(records)
    assert alias.decode("utf-8") not in payload
    assert "trüsted" not in payload


# ---------------------------------------------------------------------------
# Version 1 is accepted specifically through the version-1 grammar
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path,magic", [(JKS_V1_POSITIVE, JKS_MAGIC), (JCEKS_V1_POSITIVE, JCEKS_MAGIC)]
)
def test_version_1_fixture_has_no_certificate_type_field(path, magic):
    """Byte-exact: where version 2 writes a `writeUTF` certificate type, the
    version-1 fixture writes the certificate length immediately."""
    data = path.read_bytes()
    assert data[:4] == magic
    assert struct.unpack(">i", data[4:8])[0] == 1
    assert struct.unpack(">i", data[8:12])[0] == 1
    assert struct.unpack(">i", data[12:16])[0] == TAG_TRUSTED_CERTIFICATE
    alias_length = struct.unpack(">H", data[16:18])[0]
    assert alias_length == 8
    after_timestamp = 18 + alias_length + 8
    assert after_timestamp == _V1_CERTIFICATE_OFFSET - 4
    # No `00 05 X.509` at this position -- the next four bytes are the length.
    assert data[after_timestamp : after_timestamp + 7] != _utf(b"X.509")
    declared = struct.unpack(">i", data[after_timestamp : after_timestamp + 4])[0]
    assert declared == len(data) - _V1_CERTIFICATE_OFFSET - 20
    certificate = data[_V1_CERTIFICATE_OFFSET : _V1_CERTIFICATE_OFFSET + declared]
    assert x509.load_der_x509_certificate(certificate)
    assert data[_V1_CERTIFICATE_OFFSET + declared :] == TRAILER


@pytest.mark.parametrize("magic", [JKS_MAGIC, JCEKS_MAGIC])
def test_version_1_bytes_read_as_version_2_do_not_match(magic):
    """The two grammars are not interchangeable: the same entry bytes relabeled
    version 2 are rejected, because the certificate-type field is absent."""
    data = (JKS_V1_POSITIVE if magic == JKS_MAGIC else JCEKS_V1_POSITIVE).read_bytes()
    assert _matches(data, magic)
    relabeled = data[:4] + struct.pack(">i", 2) + data[8:]
    assert not _matches(relabeled, magic)


def test_version_2_entry_bytes_read_as_version_1_do_not_match(tmp_path):
    """And the reverse: a version-2 store relabeled version 1 leaves the
    certificate-type field unconsumed, so the entry table no longer ends at the
    trailer."""
    data = JKS_V2_POSITIVE.read_bytes()
    assert _matches(data)
    relabeled = data[:4] + struct.pack(">i", 1) + data[8:]
    assert not _matches(relabeled)


# ---------------------------------------------------------------------------
# Content, not filename: `cacerts` is not privileged
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    ["cacerts", "notes.txt", "archive.zip", "bundle.p12", "server.der", "store", "store.bin"],
)
def test_identical_bytes_match_under_any_filename(tmp_path, name):
    path = _write(tmp_path, JKS_V2_POSITIVE.read_bytes(), name)
    records = _records(path)
    assert len(records) == 1
    record = records[0]
    assert record["Rule ID"] == JKS_RULE_ID
    assert record["Evidence"] == JKS_EVIDENCE
    assert record["Location"] == str(path)


def test_cacerts_without_supported_content_does_not_match(tmp_path):
    """The filename earns nothing on its own."""
    path = _write(tmp_path, b"not a keystore at all, just bytes\n", "cacerts")
    assert _truststore_records(path) == []


def test_pkcs12_named_cacerts_is_not_claimed(tmp_path):
    """A PKCS#12 truststore is outside HG-042 even under the canonical name."""
    path = _write(tmp_path, b"\x30\x82\x01\x00" + bytes(200), "cacerts")
    assert _truststore_records(path) == []


# ---------------------------------------------------------------------------
# Detector declarations and registry precedence
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "detector_id,priority,evidence",
    [(JCEKS_RULE_ID, 36, JCEKS_EVIDENCE), (JKS_RULE_ID, 39, JKS_EVIDENCE)],
)
def test_detector_declaration_is_pinned(detector_id, priority, evidence):
    detector = _detector(detector_id)
    assert detector.scope == "file"
    assert detector.rule_id == detector_id
    assert detector.priority == priority
    assert detector.confidence == CONFIDENCE
    assert detector.evidence == evidence
    assert detector.terminal is True
    assert detector.metadata_keys == frozenset({"Format"})
    assert detector.verification_rationale


def test_registry_ordering_matches_the_contract():
    priorities = {d.detector_id: d.priority for d in CRYPTO_DETECTORS}
    assert priorities["java_keystore:bcfks"] == 35
    assert priorities[JCEKS_RULE_ID] == 36
    assert priorities["java_keystore:jceks"] == 37
    assert priorities[JKS_RULE_ID] == 39
    assert priorities[GENERIC_JKS_DETECTOR_ID] == 40
    ordered = [d.detector_id for d in CRYPTO_DETECTORS]
    assert (
        ordered.index("java_keystore:bcfks")
        < ordered.index(JCEKS_RULE_ID)
        < ordered.index("java_keystore:jceks")
        < ordered.index(JKS_RULE_ID)
        < ordered.index(GENERIC_JKS_DETECTOR_ID)
    )


def test_candidate_gates_are_content_only(tmp_path):
    """Both candidates key on magic alone, so an extensionless `cacerts` reaches
    the detector and a misleading extension earns nothing."""
    jks = FileContext(path=_write(tmp_path, JKS_V2_POSITIVE.read_bytes(), "cacerts"))
    assert crypto_inventory._java_truststore_jks_candidate(jks)
    jceks = FileContext(path=_write(tmp_path, JCEKS_V2_POSITIVE.read_bytes(), "truststore"))
    assert crypto_inventory._java_truststore_jceks_candidate(jceks)
    other = FileContext(path=_write(tmp_path, b"", "empty.jks"))
    assert not crypto_inventory._java_truststore_jks_candidate(other)
    assert not crypto_inventory._java_truststore_jceks_candidate(other)


def test_each_detector_ignores_the_other_format(tmp_path):
    jceks = FileContext(path=_write(tmp_path, JCEKS_V2_POSITIVE.read_bytes(), "s.jceks"))
    assert crypto_inventory._detect_java_truststore_jks(jceks).matched is False
    jks = FileContext(path=_write(tmp_path, JKS_V2_POSITIVE.read_bytes(), "s.jks"))
    assert crypto_inventory._detect_java_truststore_jceks(jks).matched is False


# ---------------------------------------------------------------------------
# Container and framing negatives
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "magic",
    [b"\xfe\xed\xfe\xec", b"\xce\xce\xce\xcf", b"\x30\x82\x04\x00", b"PK\x03\x04", bytes(4)],
)
def test_wrong_magic_does_not_match(magic):
    assert not _matches(_store(magic), JKS_MAGIC)
    assert not _matches(_store(magic), JCEKS_MAGIC)


def test_jks_bytes_are_not_matched_as_jceks_and_vice_versa():
    assert not _matches(_store(JKS_MAGIC), JCEKS_MAGIC)
    assert not _matches(_store(JCEKS_MAGIC), JKS_MAGIC)


@pytest.mark.parametrize("version", [-1, 0, 3, 4, 0x7FFFFFFF])
def test_unsupported_version_does_not_match(version):
    data = _store(version=2)
    mutated = data[:4] + struct.pack(">i", version) + data[8:]
    assert not _matches(mutated)


def test_negative_entry_count_does_not_match():
    data = _store()
    assert not _matches(data[:8] + b"\xff\xff\xff\xff" + data[12:])


def test_zero_entries_does_not_match(tmp_path):
    empty = JKS_MAGIC + struct.pack(">i", 2) + struct.pack(">i", 0) + TRAILER
    assert not _matches(empty)
    assert _truststore_records(_write(tmp_path, empty, "empty.jks")) == []


def test_real_empty_jceks_store_does_not_match():
    assert not _matches(JCEKS_V2_EMPTY.read_bytes(), JCEKS_MAGIC)
    assert _truststore_records(JCEKS_V2_EMPTY) == []


def test_header_only_store_does_not_match():
    assert not _matches(JKS_MAGIC + struct.pack(">i", 2) + struct.pack(">i", 1))
    assert not _matches(JKS_MAGIC[:3])
    assert not _matches(b"")


@pytest.mark.parametrize("count", [2, 1000, 0x7FFFFFFF])
def test_infeasible_entry_count_does_not_match(count):
    data = _store()
    assert not _matches(data[:8] + struct.pack(">i", count) + data[12:])


def test_feasibility_rejection_happens_before_any_entry_is_read(monkeypatch):
    """The declared count is checked against the remaining bounded bytes first,
    so a store claiming two billion entries costs one division, not a loop."""
    calls: list[int] = []
    real = crypto_inventory._read_trusted_certificate_entry

    def _counting(data, offset, limit, version):
        calls.append(offset)
        return real(data, offset, limit, version)

    monkeypatch.setattr(crypto_inventory, "_read_trusted_certificate_entry", _counting)
    data = _store()
    assert not _matches(data[:8] + struct.pack(">i", 0x7FFFFFFF) + data[12:])
    assert calls == []
    # The same predicate does iterate for a feasible count, so the assertion
    # above is about the bound and not about the probe never firing.
    assert _matches(data)
    assert calls == [12]


@pytest.mark.parametrize("version,minimum", [(1, 19), (2, 26)])
def test_minimum_entry_size_bound_is_exact(version, minimum):
    assert crypto_inventory._JAVA_KEYSTORE_MIN_TRUSTED_CERTIFICATE_ENTRY_BYTES[version] == minimum
    # A store whose entry table is exactly one byte short of `count * minimum`
    # is rejected by the bound rather than by parsing.
    body = bytes(2 * minimum - 1)
    data = _store(version=version, entries=body, entry_count=2)
    assert not _matches(data)


@pytest.mark.parametrize("truncate_at", [1, 2, 3])
def test_truncated_entry_tag_does_not_match(truncate_at):
    entry = _entry()
    data = _store(entries=entry[:truncate_at])
    assert not _matches(data)


@pytest.mark.parametrize("tag", [0, TAG_PRIVATE_KEY, TAG_SECRET_KEY, 4, 99, -1])
def test_non_trusted_certificate_tag_does_not_match(tag):
    assert not _matches(_store(entries=_entry(tag=tag)))


def test_truncated_alias_length_field_does_not_match():
    entry = _entry()
    assert not _matches(_store(entries=entry[:5]))


def test_truncated_alias_body_does_not_match():
    entry = struct.pack(">i", TAG_TRUSTED_CERTIFICATE) + struct.pack(">H", 40) + b"short"
    assert not _matches(_store(entries=entry))


def test_truncated_timestamp_does_not_match():
    entry = struct.pack(">i", TAG_TRUSTED_CERTIFICATE) + _utf(b"a1") + b"\x00\x00\x00"
    assert not _matches(_store(entries=entry))


def test_negative_certificate_length_does_not_match():
    entry = _entry(certificate_length=-1)
    assert not _matches(_store(entries=entry))
    assert not _matches(_store(entries=_entry(certificate_length=-0x7FFFFFFF)))


def test_zero_certificate_length_does_not_match():
    assert not _matches(_store(entries=_entry(certificate=b"", certificate_length=0)))


def test_truncated_certificate_length_field_does_not_match():
    entry = struct.pack(">i", TAG_TRUSTED_CERTIFICATE) + _utf(b"a1") + bytes(8) + _utf(b"X.509")
    assert not _matches(_store(entries=entry + b"\x00\x00"))


def test_certificate_length_beyond_remaining_bytes_does_not_match():
    assert not _matches(_store(entries=_entry(certificate_length=len(REAL_CERTIFICATE) + 1)))
    assert not _matches(_store(entries=_entry(certificate_length=0x7FFFFFFF)))


def test_certificate_length_reaching_into_the_trailer_does_not_match():
    """The declared payload must fit entirely before the reserved trailer, so a
    length that would consume even one trailer byte is rejected."""
    data = _store()
    grown = data[:-20] + bytes(19)
    assert not _matches(grown)


@pytest.mark.parametrize(
    "payload",
    [
        b"\x00" * 700,
        b"-----BEGIN CERTIFICATE-----\n",
        REAL_CERTIFICATE[:-1],
        REAL_CERTIFICATE[1:],
        bytes([0x30, 0x82, 0x02, 0xE3]) + bytes(739),
    ],
)
def test_invalid_der_certificate_does_not_match(payload):
    assert not _matches(_store(entries=_entry(certificate=payload)))


def test_second_entry_disqualifies_the_whole_store():
    """The complete declared table is examined -- a good first entry does not
    carry a bad second one."""
    entries = _entry() + _entry(tag=TAG_PRIVATE_KEY)
    assert not _matches(_store(entries=entries, entry_count=2))


# ---------------------------------------------------------------------------
# The 20-byte trailer
# ---------------------------------------------------------------------------


def test_missing_trailer_does_not_match():
    assert not _matches(_store(trailer=b""))


@pytest.mark.parametrize("size", [1, 4, 19])
def test_short_trailer_does_not_match(size):
    assert not _matches(_store(trailer=bytes(size)))


@pytest.mark.parametrize("size", [21, 24, 40])
def test_long_trailer_does_not_match(size):
    assert not _matches(_store(trailer=bytes(size)))


def test_bytes_after_the_trailer_do_not_match():
    assert not _matches(_store() + b"appended")
    assert not _matches(JKS_V2_POSITIVE.read_bytes() + b"\x00")


def test_trailer_content_is_never_inspected(tmp_path):
    """The trailer is a length, not a digest HG-042 checks: replacing every byte
    of it changes nothing about the classification."""
    data = JKS_V2_POSITIVE.read_bytes()
    for filler in (bytes(20), b"\xff" * 20, bytes(range(20))):
        assert _matches(data[:-20] + filler)


# ---------------------------------------------------------------------------
# Canonical Java modified UTF (Section 6 normative vectors)
# ---------------------------------------------------------------------------

# Every row is a normative outcome from the contract; the implementation and
# these tests share exactly this table.
MODIFIED_UTF_VECTORS = [
    (b"", True),  # writeUTF of the empty string
    (b"\x00", False),  # raw NUL
    (b"\xc0\x80", True),  # canonical modified-UTF NUL
    (b"\xc0\xaf", False),  # noncanonical two-byte overlong form
    (b"\xc1\xbf", False),  # noncanonical two-byte lead
    (b"\xc2\x80", True),
    (b"\xe0\x80\x80", False),  # overlong three-byte form
    (b"\xe0\xa0\x80", True),
    (b"\xed\xa0\x80", True),  # isolated high-surrogate code unit
    (b"\xed\xb0\x80", True),  # isolated low-surrogate code unit
    (b"\xed\xa0\x80\xed\xb0\x80", True),  # surrogate pair as two code units
    (b"\x80", False),  # standalone continuation byte
    (b"\xf0\x90\x80\x80", False),  # ordinary UTF-8 four-byte form
    (b"\xc2", False),  # truncated two-byte sequence
    (b"\xe1\x80", False),  # truncated three-byte sequence
]


@pytest.mark.parametrize("encoded,valid", MODIFIED_UTF_VECTORS)
def test_canonical_modified_utf_outcomes(encoded, valid):
    assert crypto_inventory._is_canonical_java_modified_utf(encoded) is valid


@pytest.mark.parametrize(
    "encoded,valid",
    [
        (b"\x01", True),
        (b"\x7f", True),
        (b"a-z_0.9", True),
        (b"\xdf\xbf", True),
        (b"\xef\xbf\xbf", True),
        (b"\xc2\x41", False),  # continuation byte out of range
        (b"\xe0\xbf", False),
        (b"\xbf", False),
        (b"\xff", False),
        (b"\xfe\xff", False),
        (b"a\x00b", False),  # a NUL anywhere in the slice
        (b"\xe1\x80\x80\xc2", False),  # valid prefix, truncated tail
    ],
)
def test_additional_canonical_modified_utf_outcomes(encoded, valid):
    assert crypto_inventory._is_canonical_java_modified_utf(encoded) is valid


@pytest.mark.parametrize("encoded,valid", MODIFIED_UTF_VECTORS)
def test_alias_validation_decides_the_store(encoded, valid):
    """The same vectors through a whole store's alias field: a malformed alias is
    a no-match, a canonical one is not."""
    assert _matches(_store(entries=_entry(alias=encoded))) is valid


@pytest.mark.parametrize("encoded,valid", MODIFIED_UTF_VECTORS)
def test_version_1_alias_validation_decides_the_store(encoded, valid):
    store = _store(version=1, entries=_entry(version=1, alias=encoded))
    assert _matches(store) is valid


def test_declared_alias_length_is_encoded_bytes_not_characters():
    """A three-byte code unit declared as one character is a truncation, not a
    one-byte alias followed by entry bytes."""
    entry = (
        struct.pack(">i", TAG_TRUSTED_CERTIFICATE)
        + struct.pack(">H", 1)
        + b"\xe2\x98\x83"
        + bytes(8)
        + _utf(b"X.509")
        + struct.pack(">i", len(REAL_CERTIFICATE))
        + REAL_CERTIFICATE
    )
    assert not _matches(_store(entries=entry))


def test_alias_length_beyond_the_trailer_does_not_match():
    entry = struct.pack(">i", TAG_TRUSTED_CERTIFICATE) + struct.pack(">H", 0xFFFF) + b"a"
    assert not _matches(_store(entries=entry))


def test_validator_is_iterative_over_long_input():
    """Non-recursive by construction: a long field cannot exhaust the stack."""
    assert crypto_inventory._is_canonical_java_modified_utf(b"\xe2\x98\x83" * 20000)
    assert not crypto_inventory._is_canonical_java_modified_utf(b"\xe2\x98\x83" * 20000 + b"\x80")


# ---------------------------------------------------------------------------
# Version-2 certificate type must be exactly X.509
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "certificate_type",
    [
        b"X509",
        b"x.509",
        b"X.509 ",
        b" X.509",
        b"X.5099",
        b"x.5O9",
        b"PkiPath",
        b"PKCS7",
        b"",
        b"\xc0\x80",  # valid modified UTF, wrong value
    ],
)
def test_non_x509_version_2_certificate_type_does_not_match(certificate_type):
    assert not _matches(_store(entries=_entry(certificate_type=certificate_type)))


@pytest.mark.parametrize("certificate_type", [b"\x00", b"\x80", b"\xc1\xbf", b"\xf0\x90\x80\x80"])
def test_malformed_version_2_certificate_type_does_not_match(certificate_type):
    assert not _matches(_store(entries=_entry(certificate_type=certificate_type)))


def test_truncated_certificate_type_field_does_not_match():
    entry = struct.pack(">i", TAG_TRUSTED_CERTIFICATE) + _utf(b"a1") + bytes(8) + b"\x00"
    assert not _matches(_store(entries=entry))


def test_certificate_type_length_beyond_the_trailer_does_not_match():
    entry = (
        struct.pack(">i", TAG_TRUSTED_CERTIFICATE)
        + _utf(b"a1")
        + bytes(8)
        + struct.pack(">H", 0xFFFF)
        + b"X.509"
    )
    assert not _matches(_store(entries=entry))


def test_exact_x509_certificate_type_matches():
    assert _matches(_store(entries=_entry(certificate_type=b"X.509")))
    assert crypto_inventory._JAVA_KEYSTORE_X509_CERTIFICATE_TYPE == b"X.509"


# ---------------------------------------------------------------------------
# Ownership: negatives fall through to the existing generic detectors
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("path", [JKS_V2_PRIVATE_KEY, JKS_V2_MIXED])
def test_jks_key_and_mixed_stores_fall_through_to_the_generic_jks_detector(path):
    records = _records(path)
    assert len(records) == 1
    record = records[0]
    assert record["Rule ID"] == GENERIC_JKS_RULE_ID
    assert record["Asset Type"] == GENERIC_JKS_ASSET_TYPE
    assert record["Evidence"] == GENERIC_JKS_EVIDENCE
    assert record["Confidence"] == "Medium"
    assert ASSET_TYPE not in {r["Asset Type"] for r in records}


@pytest.mark.parametrize("path", [JCEKS_V2_PRIVATE_KEY, JCEKS_V2_SECRET_KEY, JCEKS_V2_MIXED])
def test_jceks_key_secret_and_mixed_stores_fall_through_to_the_generic_detector(path):
    records = _records(path)
    assert len(records) == 1
    record = records[0]
    assert record["Rule ID"] == GENERIC_JCEKS_RULE_ID
    assert record["Asset Type"] == GENERIC_JCEKS_ASSET_TYPE
    assert record["Evidence"] == GENERIC_JCEKS_EVIDENCE
    assert record["Confidence"] == "Medium"
    assert record["Format"] == "JCEKS"


@pytest.mark.parametrize(
    "magic,rule_id,evidence",
    [
        (JKS_MAGIC, GENERIC_JKS_RULE_ID, GENERIC_JKS_EVIDENCE),
        (JCEKS_MAGIC, GENERIC_JCEKS_RULE_ID, GENERIC_JCEKS_EVIDENCE),
    ],
)
def test_composed_key_bearing_stores_fall_through(tmp_path, magic, rule_id, evidence):
    suffix = ".jks" if magic == JKS_MAGIC else ".jceks"
    for label, entries, count in (
        ("key", _entry(tag=TAG_PRIVATE_KEY), 1),
        ("secret", _entry(tag=TAG_SECRET_KEY), 1),
        ("unknown", _entry(tag=77), 1),
        ("mixed", _entry() + _entry(tag=TAG_PRIVATE_KEY), 2),
    ):
        path = _write(tmp_path, _store(magic, entries=entries, entry_count=count), label + suffix)
        records = _records(path)
        assert [r["Rule ID"] for r in records] == [rule_id]
        assert records[0]["Evidence"] == evidence


def test_a_positive_match_is_terminal(tmp_path):
    """The same file does not also emit the generic finding, and is not re-read
    as a DER certificate despite a misleading extension."""
    path = _write(tmp_path, JKS_V2_POSITIVE.read_bytes(), "truststore.der")
    records = _records(path)
    assert len(records) == 1
    assert records[0]["Rule ID"] == JKS_RULE_ID
    assert GENERIC_JKS_EVIDENCE not in {r["Evidence"] for r in records}


def test_bcfks_retains_precedence_over_the_truststore_detectors():
    """HG-042 sits below BCFKS in the registry, and neither of its candidates
    can fire on a BCFKS container anyway."""
    priorities = {d.detector_id: d.priority for d in CRYPTO_DETECTORS}
    assert priorities["java_keystore:bcfks"] < priorities[JCEKS_RULE_ID]


def test_directory_scan_classifies_each_store_independently(tmp_path):
    for source, name in (
        (JKS_V2_POSITIVE, "trust.jks"),
        (JKS_V2_MIXED, "mixed.jks"),
        (JCEKS_V2_POSITIVE, "trust.jceks"),
        (JCEKS_V2_SECRET_KEY, "secret.jceks"),
    ):
        _write(tmp_path, source.read_bytes(), name)
    by_name = {Path(r["Location"]).name: r["Rule ID"] for r in _records(tmp_path)}
    assert by_name == {
        "trust.jks": JKS_RULE_ID,
        "mixed.jks": GENERIC_JKS_RULE_ID,
        "trust.jceks": JCEKS_RULE_ID,
        "secret.jceks": GENERIC_JCEKS_RULE_ID,
    }


# ---------------------------------------------------------------------------
# No password, no key parsing, no deserialization, no subprocess
# ---------------------------------------------------------------------------


def _forbid(monkeypatch, name, target, attribute):
    def _raise(*args, **kwargs):
        raise AssertionError(f"HG-042 must never call {name}")

    monkeypatch.setattr(target, attribute, _raise)


@pytest.mark.parametrize(
    "path",
    [JKS_V2_POSITIVE, JCEKS_V2_POSITIVE, JKS_V1_POSITIVE, JKS_V2_MIXED, JCEKS_V2_SECRET_KEY],
)
def test_no_subprocess_java_or_keytool_is_invoked(monkeypatch, path):
    import os as os_module

    for attribute in ("run", "Popen", "check_output", "check_call", "call"):
        _forbid(monkeypatch, f"subprocess.{attribute}", subprocess, attribute)
    for attribute in ("system", "execv", "execvp", "posix_spawn", "popen"):
        _forbid(monkeypatch, f"os.{attribute}", os_module, attribute)
    assert len(_records(path)) == 1


@pytest.mark.parametrize("path", [JKS_V2_POSITIVE, JCEKS_V2_POSITIVE, JCEKS_V2_SECRET_KEY])
def test_no_key_loading_or_password_api_is_used(monkeypatch, path):
    from cryptography.hazmat.primitives.serialization import pkcs12

    _forbid(monkeypatch, "pkcs12.load_key_and_certificates", pkcs12, "load_key_and_certificates")
    for attribute in ("load_der_private_key", "load_pem_private_key"):
        _forbid(monkeypatch, f"serialization.{attribute}", serialization, attribute)
    assert len(_records(path)) == 1


@pytest.mark.parametrize("path", [JKS_V2_POSITIVE, JCEKS_V2_POSITIVE, JCEKS_V2_SECRET_KEY])
def test_no_deserialization_interface_is_used(monkeypatch, path):
    """The JCEKS secret-key entry is a Java-serialized `SealedObject`. HG-042
    disqualifies the store at the tag and never hands the payload to any
    deserializer."""
    import marshal
    import pickle

    for attribute in ("loads", "load"):
        _forbid(monkeypatch, f"pickle.{attribute}", pickle, attribute)
        _forbid(monkeypatch, f"marshal.{attribute}", marshal, attribute)
    assert len(_records(path)) == 1


@pytest.mark.parametrize(
    "path,magic",
    [
        (JCEKS_V2_SECRET_KEY, JCEKS_MAGIC),
        (JCEKS_V2_PRIVATE_KEY, JCEKS_MAGIC),
        (JKS_V2_PRIVATE_KEY, JKS_MAGIC),
    ],
)
def test_disqualifying_tag_stops_before_any_payload_is_parsed(monkeypatch, path, magic):
    """A tag-1 or tag-3 entry ends classification at the tag: the protected
    private-key body and the sealed secret-key object are never parsed, which is
    observable as zero certificate-parse attempts."""
    parses: list[int] = []
    real = x509.load_der_x509_certificate

    def _counting(payload, *args, **kwargs):
        parses.append(len(payload))
        return real(payload, *args, **kwargs)

    monkeypatch.setattr(crypto_inventory.x509, "load_der_x509_certificate", _counting)
    assert not _matches(path.read_bytes(), magic)
    assert parses == []


def test_no_password_environment_variable_is_read(monkeypatch):
    import os as os_module

    reads: list[str] = []
    real_getenv = os_module.getenv

    def _tracking_getenv(key, *args, **kwargs):
        reads.append(key)
        return real_getenv(key, *args, **kwargs)

    monkeypatch.setattr(os_module, "getenv", _tracking_getenv)
    monkeypatch.setenv("JAVA_HOME", "/canary-java-home")
    monkeypatch.setenv("TRUSTSTORE_PASSWORD", "canary-password-9f1c")
    assert len(_records(JKS_V2_POSITIVE)) == 1
    assert not any(
        token in key.upper()
        for key in reads
        for token in ("PASS", "PIN", "JAVA_HOME", "TRUSTSTORE", "KEYSTORE")
    )


def test_nothing_is_written_beside_the_store(tmp_path):
    _write(tmp_path, JKS_V2_POSITIVE.read_bytes(), "cacerts")
    before = sorted(p.name for p in tmp_path.iterdir())
    assert len(_records(tmp_path)) == 1
    assert sorted(p.name for p in tmp_path.iterdir()) == before


def test_the_store_is_read_once(monkeypatch, tmp_path):
    path = _write(tmp_path, JKS_V2_POSITIVE.read_bytes(), "cacerts")
    reads: list[str] = []
    real_read_bytes = Path.read_bytes

    def _tracking(self):
        reads.append(self.name)
        return real_read_bytes(self)

    monkeypatch.setattr(Path, "read_bytes", _tracking)
    assert len(_records(path)) == 1
    assert reads == ["cacerts"]


# ---------------------------------------------------------------------------
# Normalization, evidence store, privacy canaries
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path,rule_id,evidence,store_format",
    [
        (JKS_V2_POSITIVE, JKS_RULE_ID, JKS_EVIDENCE, "JKS"),
        (JCEKS_V2_POSITIVE, JCEKS_RULE_ID, JCEKS_EVIDENCE, "JCEKS"),
        (JKS_V1_POSITIVE, JKS_RULE_ID, JKS_EVIDENCE, "JKS"),
        (JCEKS_V1_POSITIVE, JCEKS_RULE_ID, JCEKS_EVIDENCE, "JCEKS"),
    ],
)
def test_normalized_finding_contract(path, rule_id, evidence, store_format):
    findings = scan_crypto_inventory_findings(str(path), scan_id="scan-1")
    assert len(findings) == 1
    finding = findings[0]
    assert finding.source_type == "crypto_inventory"
    assert finding.asset_type == ASSET_TYPE
    assert finding.rule_id == rule_id
    assert finding.confidence == CONFIDENCE
    assert finding.evidence == evidence
    assert finding.technical_metadata.get("Format") == store_format
    assert finding.location == str(path)
    assert finding.scan_id == "scan-1"
    assert finding.finding_id


def test_normalized_identity_is_deterministic_and_location_bound(tmp_path):
    first = _write(tmp_path, JKS_V2_POSITIVE.read_bytes(), "a.jks")
    second = _write(tmp_path, JKS_V2_POSITIVE.read_bytes(), "b.jks")
    ids = {
        f.location: f.finding_id
        for f in scan_crypto_inventory_findings(str(tmp_path), scan_id="scan-1")
    }
    repeat = {
        f.location: f.finding_id
        for f in scan_crypto_inventory_findings(str(tmp_path), scan_id="scan-1")
    }
    assert ids == repeat
    assert ids[str(first)] != ids[str(second)]


def _canary_store(tmp_path: Path, magic: bytes = JKS_MAGIC, name: str = "cacerts") -> Path:
    entry = _entry(alias=CANARY_ALIAS.encode("ascii"), certificate=_canary_certificate())
    return _write(tmp_path, _store(magic, entries=entry), name)


def test_canary_store_actually_matches(tmp_path):
    path = _canary_store(tmp_path)
    assert [r["Rule ID"] for r in _records(path)] == [JKS_RULE_ID]
    # The canaries really are in the bytes being scanned.
    data = path.read_bytes()
    assert CANARY_ALIAS.encode("ascii") in data
    assert CANARY_SUBJECT.encode("ascii") in data
    assert CANARY_ISSUER.encode("ascii") in data


def test_canaries_do_not_reach_findings_or_dataframe(tmp_path):
    _canary_store(tmp_path)
    df = scan_crypto_inventory(str(tmp_path))
    payload = df.to_json()
    for canary in CANARIES:
        assert canary not in payload
    normalized = normalize_crypto_inventory_df(df)
    assert normalized
    serialized = json.dumps([f.to_dict() for f in normalized])
    for canary in CANARIES:
        assert canary not in serialized


def test_canaries_do_not_reach_cli_json_or_markdown(tmp_path, capsys):
    target = tmp_path / "target"
    target.mkdir()
    _canary_store(target)
    # A store that HG-042 rejects, whose alias and certificate carry the same
    # canaries: a no-match must not leak them either.
    rejected = _store(entries=_entry(tag=TAG_PRIVATE_KEY, alias=CANARY_ALIAS.encode("ascii")))
    _write(target, rejected, "rejected.jks")

    assert harvestguard.main(["scan", str(target), "--type", "crypto", "--json", "--quiet"]) == 0
    payload = capsys.readouterr().out
    assert JKS_RULE_ID in payload
    for canary in CANARIES:
        assert canary not in payload

    assert harvestguard.main(["scan", str(target), "--type", "crypto", "--quiet"]) == 0
    markdown = capsys.readouterr().out
    for canary in CANARIES:
        assert canary not in markdown


def test_evidence_store_round_trip_preserves_the_finding(tmp_path, capsys):
    target = tmp_path / "target"
    target.mkdir()
    path = _canary_store(target)
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
    records = [r for r in json.loads(live) if r["rule_id"] == JKS_RULE_ID]
    assert len(records) == 1
    record = records[0]
    scan_id = record["scan_id"]
    assert scan_id
    assert record["source_type"] == "crypto_inventory"
    assert record["asset_type"] == ASSET_TYPE
    assert record["confidence"] == CONFIDENCE
    assert record["evidence"] == JKS_EVIDENCE
    assert record["technical_metadata"]["Format"] == "JKS"
    assert record["location"] == str(path)

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
    stored_record = [r for r in json.loads(stored) if r["rule_id"] == JKS_RULE_ID][0]
    assert stored_record["evidence"] == JKS_EVIDENCE
    metadata = stored_record["technical_metadata"]
    assert {k: v for k, v in metadata.items() if v is not None} == {"Format": "JKS"}

    assert (
        harvestguard.main(
            ["evidence", "export", scan_id, "--evidence-db", str(db), "--markdown", "--quiet"]
        )
        == 0
    )
    markdown = capsys.readouterr().out
    assert ASSET_TYPE in markdown
    assert JKS_EVIDENCE in markdown

    for payload in (live, stored, markdown):
        for canary in CANARIES:
            assert canary not in payload


def test_detector_failure_is_sanitized(tmp_path, monkeypatch):
    """An unexpected detector defect surfaces the detector id, the exception
    type, and the location -- never alias bytes, certificate content, or the
    parser's own message."""
    path = _canary_store(tmp_path)

    def _boom(data, magic):
        raise ValueError(f"parser choked on {CANARY_ALIAS} / {CANARY_SUBJECT}")

    monkeypatch.setattr(
        crypto_inventory, "_looks_like_trusted_certificate_only_store", _boom
    )
    with pytest.raises(LocalScanError) as excinfo:
        scan_crypto_inventory_findings(str(path))
    message = str(excinfo.value)
    assert "ValueError" in message
    assert str(path) in message
    for canary in CANARIES:
        assert canary not in message


def test_x509_parser_failure_is_not_swallowed_as_a_no_match(tmp_path, monkeypatch):
    """Principal review (PR #107 -> HG-042 correction): only the documented,
    expected ``ValueError`` that ``load_der_x509_certificate`` raises for
    malformed input may become an HG-042 no-match. Anything else -- a
    ``RuntimeError`` here standing in for any unexpected defect -- must
    propagate into the existing sanitized ``DetectorExecutionError`` /
    ``LocalScanError`` path instead of being silently absorbed into a clean
    non-match, exactly like every other unexpected detector failure.

    A real, valid HG-042 candidate (``_canary_store``, whose certificate is a
    genuine signed DER X.509 certificate) is required so execution actually
    reaches the X.509 loader rather than being rejected earlier by some other
    structural check.
    """
    real_iter = crypto_inventory._iter_candidate_files
    monkeypatch.setattr(
        crypto_inventory,
        "_iter_candidate_files",
        lambda *args, **kwargs: iter(sorted(real_iter(*args, **kwargs))),
    )
    # Sorts before "cacerts" (the default _canary_store filename), so its
    # finding is already collected when the later file's parser explodes --
    # proving partial findings survive the failure, not just that the error
    # itself is sanitized.
    (tmp_path / "aaa_cert.pem").write_bytes((FIXTURE_DIR / "rsa_cert.pem").read_bytes())
    path = _canary_store(tmp_path)

    def _boom(*args, **kwargs):
        raise RuntimeError("canary-secret")

    monkeypatch.setattr(crypto_inventory.x509, "load_der_x509_certificate", _boom)

    with pytest.raises(LocalScanError) as excinfo:
        scan_crypto_inventory_findings(str(tmp_path))

    message = str(excinfo.value)
    assert JKS_RULE_ID in message
    assert str(path) in message
    assert "RuntimeError" in message
    assert "canary-secret" not in message
    for canary in CANARIES:
        assert canary not in message
    # The evidence collected before the failure is preserved, not discarded.
    assert [f.asset_type for f in excinfo.value.partial_findings] == ["PEM Certificate"]


def test_malformed_der_certificate_still_falls_through_ownership_unchanged(tmp_path):
    """The correction narrows the caught exception type; it must not turn
    ordinary malformed certificate content into a scanner defect. A store
    whose only flaw is an invalid DER certificate payload still produces an
    HG-042 no-match and falls through to the generic JKS detector, exactly as
    the live Issue #87 ownership contract requires.

    Asserts the complete existing generic JKS output contract -- not just
    "Rule ID is None, java_truststore:jks is absent", which another rule-less
    detector's finding could also satisfy -- so this proves specifically the
    generic JKS finding, not merely the specialized one's absence.
    """
    path = _write(
        tmp_path, _store(entries=_entry(certificate=b"\x00" * 700)), "invalid-cert.jks"
    )

    records = _records(path)

    assert len(records) == 1
    record = records[0]
    assert record["Rule ID"] == GENERIC_JKS_RULE_ID
    assert record["Asset Type"] == GENERIC_JKS_ASSET_TYPE
    assert record["Evidence"] == GENERIC_JKS_EVIDENCE
    assert record["Confidence"] == "Medium"
    assert JKS_RULE_ID not in {r["Rule ID"] for r in records}


def test_generic_jks_fallback_ownership_is_the_jks_magic_detector():
    """Registry ownership, established separately from the output-contract
    test above so the two are not conflated: the fallback that
    ``test_malformed_der_certificate_still_falls_through_ownership_unchanged``
    observes is produced by exactly one registered detector,
    ``java_keystore:jks_magic``, and that detector's own declaration -- not
    just the finding it emits -- is what deliberately leaves ``rule_id``
    unset. This is a structural claim about the registry entry; the finding's
    ``Rule ID`` being ``None`` in scan output is the separate, already-covered
    behavioral claim.
    """
    generic = _detector(GENERIC_JKS_DETECTOR_ID)
    truststore = _detector(JKS_RULE_ID)

    assert generic.detector_id == GENERIC_JKS_DETECTOR_ID
    assert generic.scope == "file"
    assert generic.rule_id is None
    assert generic.terminal is True
    assert generic.evidence == GENERIC_JKS_EVIDENCE
    assert generic.confidence == "Medium"
    # Position relative to the HG-042 JKS truststore detector: the generic
    # detector sits after it, so a validated trusted-certificate-only store
    # is claimed by java_truststore:jks first and never reaches this one.
    assert generic.priority > truststore.priority
    assert generic.priority == 40
    assert truststore.priority == 39
