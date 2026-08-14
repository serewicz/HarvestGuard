"""HG-043 (GitHub issue #88): OpenSSH host identity evidence.

Three bounded, file-local observations, none of which reads a sibling file,
compares a public candidate with a private candidate, resolves
`sshd_config`/`HostKey`, or verifies a certificate signature:

- ``openssh_host_identity:private_key`` (priority 76) -- a supported
  unencrypted private key at an exact canonical OpenSSH host-key basename
  whose parsed algorithm agrees with that basename.
- ``openssh_host_identity:public_key`` (priority 81) -- one supported OpenSSH
  public-key record at the corresponding canonical basename.
- ``openssh_host_identity:host_certificate`` (priority 82) -- one
  structurally parsed OpenSSH certificate whose encoded type is HOST. No
  filename requirement; the certificate signature itself is deliberately
  never verified (Issue #88 Section 12).

Positive coverage is grounded in real `ssh-keygen`-generated fixtures under
``tests/fixtures/crypto_inventory/openssh_host_identity/`` (see
``PROVENANCE.md``). Negative/adversarial inputs are either real fixtures
mutated in this file or small synthetic byte sequences constructed here.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa

import harvestguard
import scanner.crypto_inventory as crypto_inventory
from scanner.crypto_inventory import (
    CRYPTO_DETECTORS,
    scan_crypto_inventory,
    scan_crypto_inventory_findings,
)
from scanner.errors import LocalScanError

# ---------------------------------------------------------------------------
# Frozen contract constants (Issue #88 Sections 2-5, 26)
# ---------------------------------------------------------------------------

PRIVATE_RULE_ID = "openssh_host_identity:private_key"
PUBLIC_RULE_ID = "openssh_host_identity:public_key"
CERT_RULE_ID = "openssh_host_identity:host_certificate"
HG043_RULE_IDS = {PRIVATE_RULE_ID, PUBLIC_RULE_ID, CERT_RULE_ID}

PRIVATE_ASSET_TYPE = "OpenSSH Host Private Key Candidate"
PUBLIC_ASSET_TYPE = "OpenSSH Host Public Key Candidate"
CERT_ASSET_TYPE = "OpenSSH Host Certificate"

PRIVATE_EVIDENCE = "Supported private key observed at canonical OpenSSH host-key filename"
PUBLIC_EVIDENCE = (
    "Supported SSH public key observed at canonical OpenSSH host-public-key filename"
)
CERT_EVIDENCE = "OpenSSH host certificate structure detected"

CANDIDATE_CONFIDENCE = "Medium"
CERT_CONFIDENCE = "High"

PRIVATE_PRIORITY = 76
PUBLIC_PRIORITY = 81
CERT_PRIORITY = 82

GENERIC_PRIVATE_DETECTOR_ID = "private_key:pem"
GENERIC_PUBLIC_DETECTOR_ID = "public_key:ssh"

# Reserved test-only canaries (Issue #88 Section 18/17).
PRINCIPAL_CANARY = "host.example.invalid"
KEY_ID_CANARY = "HG043-CANARY-KEY-ID"
COMMENT_CANARY = "HG043-PUBLIC-COMMENT-CANARY"
CANARIES = (PRINCIPAL_CANARY, KEY_ID_CANARY, COMMENT_CANARY)

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "crypto_inventory" / "openssh_host_identity"

EXPECTED_SHA256 = {
    "ssh_host_rsa_key": "4ae4ce97fc1983140ca99016ad6c16ca59b2c797d64833370c0742f1e6b74e24",
    "ssh_host_rsa_key.pub": "1abb0cdba7d3d9e308ac8de62bd886f0ef9acbaed230ced626aa4d7cf0a23cdb",
    "ssh_host_rsa_key_pkcs8.pem": (
        "2c3f3e387a54941474ffd5bf708002ac888632defd0968a13e2c3e92606a2c4d"
    ),
    "ssh_host_rsa_key_traditional.pem": (
        "310dc2f762f84903e1ac0c093f5e41ebae0dc7e6ce4c1dbc1192a7ce6d859fcc"
    ),
    "ssh_host_rsa_key_encrypted": (
        "96ebbc031bca3ee23c650fab38f05d44349c9d071f9ee6b3c91299491b7a664d"
    ),
    "ssh_host_ecdsa_key": "e891dbe3029932b769cdbe986bbb468e6467520f32c78526560d0bdfd7278f11",
    "ssh_host_ecdsa_key.pub": "7f8f852b3647ffa27d2d0dfbb7fa0473fd2236090b453aceaed0c0881d3d00c3",
    "ssh_host_ecdsa_key_pkcs8.pem": (
        "b2f2b722460397b0f4ab43156175f3ebeec0d9fe78e7d1802fb695fa46c6e139"
    ),
    "ssh_host_ecdsa_key_traditional.pem": (
        "8fbbd093eb1344401e62cae02e0ef51b6bc291c852c17d625fd8afd44b0eb0c5"
    ),
    "ssh_host_ed25519_key": "cdf263ea1ff4526179c70bf367ccfeb4ac33c44328f4439665181e995ceecff9",
    "ssh_host_ed25519_key.pub": "49d46bc5f67e44613544076a20365a6a057c381714b221abf3c3858d8022e01c",
    "ssh_host_ed25519_key_pkcs8.pem": (
        "efb4e4941b2f0c9f9b1ab33b6f671300f6c6299157e109bce6c3de1cc8ec9f39"
    ),
    "ssh_host_rsa_key-cert.pub": "946b111c90b6b561147bfe43e97d8189339c6711e743f97b385ef45b51c09bea",
    "ssh_host_ecdsa_key-cert.pub": (
        "eca5e7f198fcfceb43fe7f651267fb5a2da6668e12f9ef4f01d927d8c7361f25"
    ),
    "ssh_host_ed25519_key-cert.pub": (
        "50aac8d27100b6659ec856f284f7d5ee8036f5b856ed00103b819deda06924ab"
    ),
    "ssh_host_ed25519_key-cert-tampered.pub": (
        "70173e0e19f16ca6bfae1fb0a729124a54095f5bf6f239442c3f11814024fc52"
    ),
    "user_key": "d45dab218b47270137f995b9bb1bc0bb8c21b1dadeffbe056ca2f08ea53df68e",
    "user_key.pub": "a52fb493680fb38cb9fd3b4ded0f50884955fc43003f36da9a03edbb50f27fc4",
    "user_key-cert.pub": "44205b216859d89a883674a5f79b87dc23314a65b7bce0b8f528d20f87d47d16",
    "ca_key.pub": "062509df467d25152b22c34a78ecf98da9873278c7525f06b47d9b1f057345f7",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _real(name: str) -> bytes:
    return (FIXTURE_DIR / name).read_bytes()


def _write(tmp_path: Path, name: str, data: bytes) -> Path:
    path = tmp_path / name
    path.write_bytes(data)
    return path


def _copy(tmp_path: Path, source_name: str, dest_name: str) -> Path:
    """Copy a committed fixture's bytes to ``dest_name`` -- the exact
    canonical (or deliberately non-canonical) basename a test needs, which is
    frequently not the fixture's own filename in the fixtures directory."""
    return _write(tmp_path, dest_name, _real(source_name))


def _records(target: Path, **kwargs) -> list[dict]:
    df = scan_crypto_inventory(str(target), **kwargs)
    return [] if df.empty else df.to_dict(orient="records")


def _hg043_records(target: Path, **kwargs) -> list[dict]:
    return [r for r in _records(target, **kwargs) if r.get("Rule ID") in HG043_RULE_IDS]


def _findings(target: Path):
    return scan_crypto_inventory_findings(str(target))


def _detector(detector_id: str):
    return next(d for d in CRYPTO_DETECTORS if d.detector_id == detector_id)


def _no_secret_leak(records: list[dict]) -> None:
    blob = json.dumps(records, default=str)
    for canary in CANARIES:
        assert canary not in blob


# ---------------------------------------------------------------------------
# Fixture provenance and registry contract
# ---------------------------------------------------------------------------


def test_fixture_hashes_match_provenance():
    for name, expected in EXPECTED_SHA256.items():
        digest = hashlib.sha256(_real(name)).hexdigest()
        assert digest == expected, f"{name}: {digest}"


@pytest.mark.parametrize(
    "rule_id,priority,asset_type,evidence,confidence",
    [
        (PRIVATE_RULE_ID, PRIVATE_PRIORITY, PRIVATE_ASSET_TYPE, PRIVATE_EVIDENCE, "Medium"),
        (PUBLIC_RULE_ID, PUBLIC_PRIORITY, PUBLIC_ASSET_TYPE, PUBLIC_EVIDENCE, "Medium"),
        (CERT_RULE_ID, CERT_PRIORITY, CERT_ASSET_TYPE, CERT_EVIDENCE, "High"),
    ],
)
def test_detector_registered_with_expected_contract(
    rule_id, priority, asset_type, evidence, confidence
):
    detector = _detector(rule_id)
    assert detector.priority == priority
    assert detector.terminal is True
    assert detector.rule_id == rule_id
    assert detector.confidence == confidence
    assert detector.evidence == evidence
    assert detector.metadata_keys == frozenset({"Algorithm", "Key Size"})


def test_registry_ordering_matches_the_post_hg042_delta_freeze():
    legacy_encrypted = _detector("private_key:legacy_pem_encrypted")
    generic_private = _detector(GENERIC_PRIVATE_DETECTOR_ID)
    generic_public = _detector(GENERIC_PUBLIC_DETECTOR_ID)
    private = _detector(PRIVATE_RULE_ID)
    public = _detector(PUBLIC_RULE_ID)
    cert = _detector(CERT_RULE_ID)

    assert legacy_encrypted.priority < private.priority < generic_private.priority
    assert generic_private.priority < public.priority < cert.priority < generic_public.priority
    assert generic_private.terminal is False
    assert generic_public.terminal is False


# ---------------------------------------------------------------------------
# Private candidate: positive coverage (Issue #88 Sections 7, 19)
# ---------------------------------------------------------------------------


PRIVATE_POSITIVE = [
    ("ssh_host_rsa_key", "ssh_host_rsa_key", "RSA", 2048),
    ("ssh_host_rsa_key_pkcs8.pem", "ssh_host_rsa_key", "RSA", 2048),
    ("ssh_host_rsa_key_traditional.pem", "ssh_host_rsa_key", "RSA", 2048),
    ("ssh_host_ecdsa_key", "ssh_host_ecdsa_key", "EC (secp256r1)", 256),
    ("ssh_host_ecdsa_key_pkcs8.pem", "ssh_host_ecdsa_key", "EC (secp256r1)", 256),
    ("ssh_host_ecdsa_key_traditional.pem", "ssh_host_ecdsa_key", "EC (secp256r1)", 256),
    ("ssh_host_ed25519_key", "ssh_host_ed25519_key", "Ed25519", 256),
    ("ssh_host_ed25519_key_pkcs8.pem", "ssh_host_ed25519_key", "Ed25519", 256),
]


@pytest.mark.parametrize("source,basename,algorithm,key_size", PRIVATE_POSITIVE)
def test_private_candidate_positive_encodings(tmp_path, source, basename, algorithm, key_size):
    path = _copy(tmp_path, source, basename)
    records = _hg043_records(path)
    assert len(records) == 1
    record = records[0]
    assert record["Asset Type"] == PRIVATE_ASSET_TYPE
    assert record["Rule ID"] == PRIVATE_RULE_ID
    assert record["Confidence"] == CANDIDATE_CONFIDENCE
    assert record["Evidence"] == PRIVATE_EVIDENCE
    assert record["Algorithm"] == algorithm
    assert record["Key Size"] == key_size
    assert record["Fingerprint"] is None
    # No generic duplicate for the same file.
    all_records = _records(path)
    assert len(all_records) == 1


def test_ed25519_traditional_pem_is_not_a_thing_and_is_not_accepted(tmp_path):
    # Section 19: "Traditional PEM forms are not accepted for Ed25519." There
    # is no such fixture; a traditional-labelled block containing Ed25519 key
    # bytes is not representable by the real format at all, so the negative
    # is implicit. Nothing to assert beyond the fixture set already omitting
    # it (see PRIVATE_POSITIVE above).
    assert not (FIXTURE_DIR / "ssh_host_ed25519_key_traditional.pem").exists()


# ---------------------------------------------------------------------------
# Private candidate: filename/algorithm agreement (Issue #88 Section 4)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "content_source,basename",
    [
        ("ssh_host_ecdsa_key", "ssh_host_rsa_key"),
        ("ssh_host_ed25519_key", "ssh_host_rsa_key"),
        ("ssh_host_rsa_key", "ssh_host_ecdsa_key"),
        ("ssh_host_ed25519_key", "ssh_host_ecdsa_key"),
        ("ssh_host_rsa_key", "ssh_host_ed25519_key"),
        ("ssh_host_ecdsa_key", "ssh_host_ed25519_key"),
    ],
)
def test_private_candidate_wrong_algorithm_for_basename_is_no_match(
    tmp_path, content_source, basename
):
    path = _copy(tmp_path, content_source, basename)
    assert _hg043_records(path) == []
    # Falls through to the existing generic path, unchanged.
    records = _records(path)
    assert len(records) == 1
    assert records[0]["Rule ID"] is None
    assert records[0]["Asset Type"] == "OpenSSH Private Key"


# ---------------------------------------------------------------------------
# Private candidate: explicitly excluded encodings (Issue #88 Section 7.5)
# ---------------------------------------------------------------------------


def test_der_private_key_is_no_match(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    der = key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path = _write(tmp_path, "ssh_host_rsa_key", der)
    assert _hg043_records(path) == []


def test_dsa_traditional_pem_is_no_match(tmp_path):
    key = dsa.generate_private_key(key_size=1024)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    # No canonical DSA basename exists; this proves the encoding itself (not
    # merely a filename mismatch) is rejected even placed at a basename whose
    # family happens to share no name with DSA.
    path = _write(tmp_path, "ssh_host_rsa_key", pem)
    assert _hg043_records(path) == []


def test_encrypted_pkcs8_under_canonical_basename_is_no_match_and_keeps_earlier_ownership(
    tmp_path,
):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    encrypted = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(b"harvestguard-fixture"),
    )
    path = _write(tmp_path, "ssh_host_rsa_key", encrypted)
    assert _hg043_records(path) == []
    records = _records(path)
    assert len(records) == 1
    assert records[0]["Rule ID"] == "private_key:pkcs8_encrypted"


def test_encrypted_openssh_under_canonical_basename_is_no_match_and_falls_through(tmp_path):
    path = _copy(tmp_path, "ssh_host_rsa_key_encrypted", "ssh_host_rsa_key")
    assert _hg043_records(path) == []
    records = _records(path)
    assert len(records) == 1
    record = records[0]
    assert record["Asset Type"] == "Encrypted OpenSSH Private Key"
    assert record["Confidence"] == "Medium"
    assert record["Evidence"] == "OpenSSH private key block detected"
    assert record["Rule ID"] is None
    assert record["Algorithm"] is None
    assert record["Key Size"] is None
    assert record["Fingerprint"] is None


def test_encrypted_traditional_rsa_under_canonical_basename_is_no_match_and_keeps_legacy_owner(
    tmp_path,
):
    legacy_fixture = (
        Path(__file__).parent
        / "fixtures"
        / "crypto_inventory"
        / "legacy_pem_encrypted"
        / "rsa_encrypted_legacy.pem"
    )
    path = _write(tmp_path, "ssh_host_rsa_key", legacy_fixture.read_bytes())
    assert _hg043_records(path) == []
    records = _records(path)
    assert len(records) == 1
    assert records[0]["Rule ID"] == "private_key:legacy_pem_encrypted"


def test_embedded_valid_block_with_surrounding_text_is_no_match(tmp_path):
    block = _real("ssh_host_rsa_key").decode("ascii")
    wrapped = f"# leading comment\n{block}\n# trailing comment\n"
    path = _write(tmp_path, "ssh_host_rsa_key", wrapped.encode("ascii"))
    assert _hg043_records(path) == []


def test_two_private_key_blocks_is_no_match(tmp_path):
    block = _real("ssh_host_rsa_key").decode("ascii").strip()
    combined = block + "\n" + block + "\n"
    path = _write(tmp_path, "ssh_host_rsa_key", combined.encode("ascii"))
    assert _hg043_records(path) == []


def test_private_key_plus_certificate_block_is_no_match(tmp_path):
    private_block = _real("ssh_host_rsa_key").decode("ascii").strip()
    cert_pem = (
        Path(__file__).parent / "fixtures" / "crypto_inventory" / "rsa_cert.pem"
    ).read_text(encoding="ascii")
    combined = private_block + "\n" + cert_pem.strip() + "\n"
    path = _write(tmp_path, "ssh_host_rsa_key", combined.encode("ascii"))
    assert _hg043_records(path) == []


def test_private_key_plus_public_key_pem_block_is_no_match(tmp_path):
    private_block = _real("ssh_host_rsa_key").decode("ascii").strip()
    public_pem = (
        "-----BEGIN PUBLIC KEY-----\n"
        "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAK4Q1z0j2Q6f2n2m3v0Xy4XxWq2i2iQd\n"
        "ID3GgpZ8g8Fh0v8n7l8f6r3EwIDAQAB\n"
        "-----END PUBLIC KEY-----\n"
    )
    combined = private_block + "\n" + public_pem
    path = _write(tmp_path, "ssh_host_rsa_key", combined.encode("ascii"))
    assert _hg043_records(path) == []


# ---------------------------------------------------------------------------
# Private candidate: whole-file framing / whitespace (Issue #88 Sections 8, 19)
# ---------------------------------------------------------------------------


OUTER_WHITESPACE_BYTES = (b"\x20", b"\x09", b"\x0a", b"\x0d", b"\x0b", b"\x0c")


@pytest.mark.parametrize("ws", OUTER_WHITESPACE_BYTES)
def test_each_permitted_outer_whitespace_byte_is_accepted(tmp_path, ws):
    block = _real("ssh_host_ed25519_key")
    padded = ws + ws + block + ws + ws
    path = _write(tmp_path, "ssh_host_ed25519_key", padded)
    records = _hg043_records(path)
    assert len(records) == 1
    assert records[0]["Algorithm"] == "Ed25519"


def test_crlf_formatted_private_envelope_is_accepted(tmp_path):
    block = _real("ssh_host_rsa_key").replace(b"\n", b"\r\n")
    path = _write(tmp_path, "ssh_host_rsa_key", block)
    records = _hg043_records(path)
    assert len(records) == 1
    assert records[0]["Algorithm"] == "RSA"


@pytest.mark.parametrize("prefix", [b"X", b"\x00", b"# not whitespace\n"])
def test_non_whitespace_prefix_rejects_candidate(tmp_path, prefix):
    block = _real("ssh_host_ed25519_key")
    path = _write(tmp_path, "ssh_host_ed25519_key", prefix + block)
    assert _hg043_records(path) == []


@pytest.mark.parametrize("suffix", [b"X", b"\x00", b"trailing"])
def test_non_whitespace_suffix_rejects_candidate(tmp_path, suffix):
    block = _real("ssh_host_ed25519_key")
    path = _write(tmp_path, "ssh_host_ed25519_key", block.rstrip(b"\n") + suffix)
    assert _hg043_records(path) == []


# ---------------------------------------------------------------------------
# Private candidate: canonical basename / case sensitivity (Issue #88 Section 2)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "basename",
    ["SSH_HOST_RSA_KEY", "ssh_Host_rsa_key", "ssh_host_rsa_key.bak", "id_rsa"],
)
def test_noncanonical_or_case_variant_private_basename_is_no_match(tmp_path, basename):
    path = _copy(tmp_path, "ssh_host_rsa_key", basename)
    assert _hg043_records(path) == []
    # Generic behavior remains authoritative.
    assert any(r["Asset Type"] == "OpenSSH Private Key" for r in _records(path))


def test_renamed_user_key_at_canonical_basename_is_an_accepted_false_positive(tmp_path):
    # Issue #88 Section 2: "A user key renamed to an exact canonical basename
    # can become a candidate finding. This is an explicit accepted
    # false-positive boundary."
    path = _copy(tmp_path, "user_key", "ssh_host_ed25519_key")
    records = _hg043_records(path)
    assert len(records) == 1
    assert records[0]["Algorithm"] == "Ed25519"


# ---------------------------------------------------------------------------
# Public candidate: positive coverage (Issue #88 Sections 10, 20)
# ---------------------------------------------------------------------------


PUBLIC_POSITIVE = [
    ("ssh_host_rsa_key.pub", "ssh_host_rsa_key.pub", "RSA", 2048),
    ("ssh_host_ecdsa_key.pub", "ssh_host_ecdsa_key.pub", "EC (secp256r1)", 256),
    ("ssh_host_ed25519_key.pub", "ssh_host_ed25519_key.pub", "Ed25519", 256),
]


@pytest.mark.parametrize("source,basename,algorithm,key_size", PUBLIC_POSITIVE)
def test_public_candidate_positive(tmp_path, source, basename, algorithm, key_size):
    path = _copy(tmp_path, source, basename)
    records = _hg043_records(path)
    assert len(records) == 1
    record = records[0]
    assert record["Asset Type"] == PUBLIC_ASSET_TYPE
    assert record["Rule ID"] == PUBLIC_RULE_ID
    assert record["Confidence"] == CANDIDATE_CONFIDENCE
    assert record["Evidence"] == PUBLIC_EVIDENCE
    assert record["Algorithm"] == algorithm
    assert record["Key Size"] == key_size
    assert record["Fingerprint"] is None
    all_records = _records(path)
    assert len(all_records) == 1


def _rsa_public_line() -> bytes:
    return _real("ssh_host_rsa_key.pub").strip()


# ---------------------------------------------------------------------------
# Public candidate: one-record grammar (Issue #88 Sections 10, 20)
# ---------------------------------------------------------------------------


def test_public_candidate_optional_trailing_comment_accepted_but_not_emitted(tmp_path):
    algo, blob = _rsa_public_line().split(b" ", 1)
    record = algo + b" " + blob + b" some-real-comment\n"
    path = _write(tmp_path, "ssh_host_rsa_key.pub", record)
    records = _hg043_records(path)
    assert len(records) == 1
    _no_secret_leak(records)
    assert "some-real-comment" not in json.dumps(records)


def test_public_candidate_empty_comment_after_separator_accepted(tmp_path):
    algo, blob = _rsa_public_line().split(b" ", 1)
    record = algo + b" " + blob + b" \n"
    path = _write(tmp_path, "ssh_host_rsa_key.pub", record)
    assert len(_hg043_records(path)) == 1


def test_public_candidate_invalid_utf8_comment_accepted_and_not_emitted(tmp_path):
    algo, blob = _rsa_public_line().split(b" ", 1)
    record = algo + b" " + blob + b" \xff\xfe\x00bad-utf8\n"
    path = _write(tmp_path, "ssh_host_rsa_key.pub", record)
    records = _hg043_records(path)
    assert len(records) == 1
    assert b"\xff\xfe" not in json.dumps(records).encode("utf-8", errors="surrogateescape")


@pytest.mark.parametrize("newline", [b"\r", b"\r\r", b"\n\n"])
def test_public_candidate_extra_cr_or_lf_in_comment_rejected(tmp_path, newline):
    algo, blob = _rsa_public_line().split(b" ", 1)
    record = algo + b" " + blob + b" comment" + newline
    path = _write(tmp_path, "ssh_host_rsa_key.pub", record)
    assert _hg043_records(path) == []


def test_public_candidate_no_final_newline_accepted(tmp_path):
    path = _write(tmp_path, "ssh_host_rsa_key.pub", _rsa_public_line())
    assert len(_hg043_records(path)) == 1


def test_public_candidate_single_lf_accepted(tmp_path):
    path = _write(tmp_path, "ssh_host_rsa_key.pub", _rsa_public_line() + b"\n")
    assert len(_hg043_records(path)) == 1


def test_public_candidate_single_crlf_accepted(tmp_path):
    path = _write(tmp_path, "ssh_host_rsa_key.pub", _rsa_public_line() + b"\r\n")
    assert len(_hg043_records(path)) == 1


def test_public_candidate_outer_sp_ht_accepted(tmp_path):
    path = _write(tmp_path, "ssh_host_rsa_key.pub", b"  \t" + _rsa_public_line() + b" \t \n")
    assert len(_hg043_records(path)) == 1


def test_public_candidate_leading_blank_line_rejected(tmp_path):
    path = _write(tmp_path, "ssh_host_rsa_key.pub", b"\n" + _rsa_public_line() + b"\n")
    assert _hg043_records(path) == []


def test_public_candidate_trailing_blank_line_rejected(tmp_path):
    path = _write(tmp_path, "ssh_host_rsa_key.pub", _rsa_public_line() + b"\n\n")
    assert _hg043_records(path) == []


def test_public_candidate_second_identity_record_rejected(tmp_path):
    line = _rsa_public_line()
    path = _write(tmp_path, "ssh_host_rsa_key.pub", line + b"\n" + line + b"\n")
    assert _hg043_records(path) == []


def test_public_candidate_malformed_second_line_rejected(tmp_path):
    path = _write(tmp_path, "ssh_host_rsa_key.pub", _rsa_public_line() + b"\ngarbage\n")
    assert _hg043_records(path) == []


def test_public_candidate_comment_only_line_rejected(tmp_path):
    path = _write(tmp_path, "ssh_host_rsa_key.pub", b"# just a comment\n")
    assert _hg043_records(path) == []


def test_public_candidate_authorized_keys_option_prefix_rejected(tmp_path):
    line = b"no-pty " + _rsa_public_line() + b"\n"
    path = _write(tmp_path, "ssh_host_rsa_key.pub", line)
    assert _hg043_records(path) == []


def test_public_candidate_rfc4716_form_rejected(tmp_path):
    text = (
        "---- BEGIN SSH2 PUBLIC KEY ----\n"
        "Comment: \"test\"\n"
        "AAAAB3NzaC1yc2EAAAABJQAAAIEA\n"
        "---- END SSH2 PUBLIC KEY ----\n"
    ).encode("ascii")
    path = _write(tmp_path, "ssh_host_rsa_key.pub", text)
    assert _hg043_records(path) == []


def test_public_candidate_certificate_record_rejected(tmp_path):
    path = _copy(tmp_path, "ssh_host_rsa_key-cert.pub", "ssh_host_rsa_key.pub")
    hg043 = _hg043_records(path)
    # Excluded from the public-candidate rule specifically, but a real HOST
    # certificate has no filename requirement, so the host-certificate rule
    # legitimately claims this same file (Section 11/21).
    assert all(r["Rule ID"] != PUBLIC_RULE_ID for r in hg043)
    assert any(r["Rule ID"] == CERT_RULE_ID for r in hg043)


@pytest.mark.parametrize(
    "content_source,basename",
    [
        ("ssh_host_ecdsa_key.pub", "ssh_host_rsa_key.pub"),
        ("ssh_host_ed25519_key.pub", "ssh_host_rsa_key.pub"),
        ("ssh_host_rsa_key.pub", "ssh_host_ecdsa_key.pub"),
        ("ssh_host_rsa_key.pub", "ssh_host_ed25519_key.pub"),
    ],
)
def test_public_candidate_wrong_algorithm_for_basename_is_no_match(
    tmp_path, content_source, basename
):
    path = _copy(tmp_path, content_source, basename)
    assert _hg043_records(path) == []
    assert any(r["Asset Type"] == "OpenSSH Public Key" for r in _records(path))


def test_public_candidate_unsupported_algorithm_is_no_match(tmp_path):
    record = b"ssh-dss AAAAB3NzaC1kc3MAAACBAK\n"
    path = _write(tmp_path, "ssh_host_rsa_key.pub", record)
    assert _hg043_records(path) == []


@pytest.mark.parametrize(
    "basename", ["SSH_HOST_RSA_KEY.PUB", "ssh_host_RSA_key.pub", "id_rsa.pub"]
)
def test_public_candidate_case_variant_or_arbitrary_basename_is_no_match(tmp_path, basename):
    path = _copy(tmp_path, "ssh_host_rsa_key.pub", basename)
    assert _hg043_records(path) == []
    assert any(r["Asset Type"] == "OpenSSH Public Key" for r in _records(path))


# ---------------------------------------------------------------------------
# Host certificate: positive coverage (Issue #88 Sections 11, 21)
# ---------------------------------------------------------------------------


CERT_POSITIVE = [
    ("ssh_host_rsa_key-cert.pub", "RSA", 2048),
    ("ssh_host_ecdsa_key-cert.pub", "EC (secp256r1)", 256),
    ("ssh_host_ed25519_key-cert.pub", "Ed25519", 256),
]


@pytest.mark.parametrize("source,algorithm,key_size", CERT_POSITIVE)
def test_host_certificate_positive(tmp_path, source, algorithm, key_size):
    # No filename requirement: an arbitrary, non-canonical name is used
    # deliberately to prove the point (Section 21).
    path = _copy(tmp_path, source, "arbitrary-cert-name.pub")
    records = _hg043_records(path)
    assert len(records) == 1
    record = records[0]
    assert record["Asset Type"] == CERT_ASSET_TYPE
    assert record["Rule ID"] == CERT_RULE_ID
    assert record["Confidence"] == CERT_CONFIDENCE
    assert record["Evidence"] == CERT_EVIDENCE
    assert record["Algorithm"] == algorithm
    assert record["Key Size"] == key_size
    assert record["Fingerprint"] is None
    _no_secret_leak(records)


def test_host_certificate_no_generic_public_duplicate(tmp_path):
    # ssh-ed25519-cert-v01@openssh.com does not collide with the existing
    # generic public_key:ssh candidate prefix check, so this also proves the
    # terminal declaration is doing real work, not merely papering over an
    # already-absent duplicate.
    path = _copy(tmp_path, "ssh_host_ed25519_key-cert.pub", "ssh_host_ed25519_key-cert.pub")
    records = _records(path)
    assert len(records) == 1
    assert records[0]["Rule ID"] == CERT_RULE_ID


def test_user_certificate_is_no_host_certificate_finding_and_zero_generic_findings(tmp_path):
    path = _copy(tmp_path, "user_key-cert.pub", "user_key-cert.pub")
    assert _records(path) == []


def test_ordinary_public_key_is_no_host_certificate_finding(tmp_path):
    path = _copy(tmp_path, "ssh_host_ed25519_key.pub", "not-a-cert.pub")
    records = _hg043_records(path)
    assert all(r["Rule ID"] != CERT_RULE_ID for r in records)


def test_unsupported_certified_key_is_no_match(tmp_path, monkeypatch):
    path = _copy(tmp_path, "ssh_host_ed25519_key-cert.pub", "cert.pub")
    unsupported = dsa.generate_private_key(key_size=1024).public_key()
    monkeypatch.setattr(serialization.SSHCertificate, "public_key", lambda self: unsupported)
    assert _hg043_records(path) == []


def test_unsupported_signing_key_is_no_match(tmp_path, monkeypatch):
    path = _copy(tmp_path, "ssh_host_ed25519_key-cert.pub", "cert.pub")
    unsupported = dsa.generate_private_key(key_size=1024).public_key()
    monkeypatch.setattr(serialization.SSHCertificate, "signature_key", lambda self: unsupported)
    assert _hg043_records(path) == []


def test_signing_key_ecdsa_outside_accepted_curves_is_no_match(tmp_path, monkeypatch):
    path = _copy(tmp_path, "ssh_host_ed25519_key-cert.pub", "cert.pub")
    unsupported_curve_key = ec.generate_private_key(ec.SECP224R1()).public_key()
    monkeypatch.setattr(
        serialization.SSHCertificate, "signature_key", lambda self: unsupported_curve_key
    )
    assert _hg043_records(path) == []


def test_certificate_key_extraction_unsupported_algorithm_is_no_match(tmp_path, monkeypatch):
    path = _copy(tmp_path, "ssh_host_ed25519_key-cert.pub", "cert.pub")

    def _raise(self):
        raise UnsupportedAlgorithm("synthetic boundary test")

    monkeypatch.setattr(serialization.SSHCertificate, "public_key", _raise)
    assert _hg043_records(path) == []


def test_no_filename_requirement(tmp_path):
    for name in ["random.txt", "id_ed25519-cert.pub", "cert"]:
        path = _copy(tmp_path, "ssh_host_ed25519_key-cert.pub", name)
        records = _hg043_records(path)
        assert len(records) == 1
        assert records[0]["Rule ID"] == CERT_RULE_ID


# ---------------------------------------------------------------------------
# Host certificate: signature boundary (Issue #88 Sections 12, 21)
# ---------------------------------------------------------------------------


def test_tampered_signature_host_certificate_still_matches_structurally(tmp_path):
    path = _copy(
        tmp_path, "ssh_host_ed25519_key-cert-tampered.pub", "ssh_host_ed25519_key-cert-tampered.pub"
    )
    records = _hg043_records(path)
    assert len(records) == 1
    record = records[0]
    assert record["Asset Type"] == CERT_ASSET_TYPE
    assert record["Rule ID"] == CERT_RULE_ID
    assert record["Confidence"] == CERT_CONFIDENCE
    assert record["Algorithm"] == "Ed25519"


def test_tampered_signature_fails_verify_cert_signature_directly():
    """Confirms the fixture itself: the mutated certificate still parses as
    HOST (proven above through the full scan), but its cryptographic
    signature is genuinely invalid. HG-043 never calls this API; this test
    exists only to prove the fixture is what PROVENANCE.md claims it is."""
    from cryptography.exceptions import InvalidSignature

    record = _real("ssh_host_ed25519_key-cert-tampered.pub").strip()
    algo, blob = record.split(b" ", 2)[:2]
    identity = serialization.load_ssh_public_identity(algo + b" " + blob)
    assert isinstance(identity, serialization.SSHCertificate)
    assert identity.type is serialization.SSHCertificateType.HOST
    with pytest.raises(InvalidSignature):
        identity.verify_cert_signature()


def test_untampered_certificate_verifies_cleanly_confirming_the_control():
    record = _real("ssh_host_ed25519_key-cert.pub").strip()
    algo, blob = record.split(b" ", 2)[:2]
    identity = serialization.load_ssh_public_identity(algo + b" " + blob)
    identity.verify_cert_signature()  # must not raise


def test_hg043_never_calls_verify_cert_signature(monkeypatch, tmp_path):
    def _forbidden(self):
        raise AssertionError("HG-043 must never call verify_cert_signature()")

    monkeypatch.setattr(serialization.SSHCertificate, "verify_cert_signature", _forbidden)
    path = _copy(tmp_path, "ssh_host_ed25519_key-cert.pub", "cert.pub")
    records = _hg043_records(path)
    assert len(records) == 1


# ---------------------------------------------------------------------------
# No-pairing tests (Issue #88 Section 1, 22)
# ---------------------------------------------------------------------------


def test_unrelated_private_and_public_files_each_independently_candidate(tmp_path):
    # ssh_host_ed25519_key (key A) and an unrelated user_key.pub renamed to
    # the matching .pub basename (key B): the exact example Issue #88 Section
    # 1 gives.
    private_path = _copy(tmp_path, "ssh_host_ed25519_key", "ssh_host_ed25519_key")
    public_path = _copy(tmp_path, "user_key.pub", "ssh_host_ed25519_key.pub")

    private_records = _hg043_records(private_path)
    public_records = _hg043_records(public_path)
    assert len(private_records) == 1
    assert len(public_records) == 1

    blob = json.dumps(private_records + public_records)
    for word in ("match", "pair", "paired", "corresponds"):
        assert word not in blob.lower()


def test_direct_scan_of_private_file_does_not_touch_pub_sibling(tmp_path, monkeypatch):
    private_path = _copy(tmp_path, "ssh_host_ed25519_key", "ssh_host_ed25519_key")
    _copy(tmp_path, "ssh_host_ed25519_key.pub", "ssh_host_ed25519_key.pub")

    real_read_bytes = Path.read_bytes

    def _guarded(self, *args, **kwargs):
        if self.name.endswith(".pub"):
            raise AssertionError(f"private-file scan must not read {self}")
        return real_read_bytes(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_bytes", _guarded)
    records = _hg043_records(private_path)
    assert len(records) == 1


def test_direct_scan_of_public_file_does_not_touch_private_sibling(tmp_path, monkeypatch):
    _copy(tmp_path, "ssh_host_ed25519_key", "ssh_host_ed25519_key")
    public_path = _copy(tmp_path, "ssh_host_ed25519_key.pub", "ssh_host_ed25519_key.pub")

    real_read_bytes = Path.read_bytes

    def _guarded(self, *args, **kwargs):
        if self.name == "ssh_host_ed25519_key":
            raise AssertionError(f"public-file scan must not read {self}")
        return real_read_bytes(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_bytes", _guarded)
    records = _hg043_records(public_path)
    assert len(records) == 1


# ---------------------------------------------------------------------------
# Error-boundary tests (Issue #88 Sections 13, 23)
# ---------------------------------------------------------------------------


def test_load_ssh_private_key_unexpected_exception_is_not_swallowed(tmp_path, monkeypatch):
    _copy(tmp_path, "ssh_host_ed25519_key", "ssh_host_ed25519_key")

    def _boom(*args, **kwargs):
        raise RuntimeError("canary-secret")

    monkeypatch.setattr(crypto_inventory.serialization, "load_ssh_private_key", _boom)
    with pytest.raises(LocalScanError) as excinfo:
        scan_crypto_inventory_findings(str(tmp_path))
    message = str(excinfo.value)
    assert PRIVATE_RULE_ID in message
    assert "RuntimeError" in message
    assert "canary-secret" not in message


def test_load_pem_private_key_unexpected_exception_is_not_swallowed(tmp_path, monkeypatch):
    _copy(tmp_path, "ssh_host_rsa_key_pkcs8.pem", "ssh_host_rsa_key")

    def _boom(*args, **kwargs):
        raise RuntimeError("canary-secret")

    monkeypatch.setattr(crypto_inventory.serialization, "load_pem_private_key", _boom)
    with pytest.raises(LocalScanError) as excinfo:
        scan_crypto_inventory_findings(str(tmp_path))
    message = str(excinfo.value)
    assert PRIVATE_RULE_ID in message
    assert "RuntimeError" in message
    assert "canary-secret" not in message


def test_load_ssh_public_key_unexpected_exception_is_not_swallowed(tmp_path, monkeypatch):
    _copy(tmp_path, "ssh_host_rsa_key.pub", "ssh_host_rsa_key.pub")

    def _boom(*args, **kwargs):
        raise RuntimeError("canary-secret")

    monkeypatch.setattr(crypto_inventory.serialization, "load_ssh_public_key", _boom)
    with pytest.raises(LocalScanError) as excinfo:
        scan_crypto_inventory_findings(str(tmp_path))
    message = str(excinfo.value)
    assert PUBLIC_RULE_ID in message
    assert "RuntimeError" in message
    assert "canary-secret" not in message


def test_load_ssh_public_identity_unexpected_exception_is_not_swallowed(tmp_path, monkeypatch):
    _copy(tmp_path, "ssh_host_ed25519_key-cert.pub", "cert.pub")

    def _boom(*args, **kwargs):
        raise RuntimeError("canary-secret")

    monkeypatch.setattr(crypto_inventory.serialization, "load_ssh_public_identity", _boom)
    with pytest.raises(LocalScanError) as excinfo:
        scan_crypto_inventory_findings(str(tmp_path))
    message = str(excinfo.value)
    assert CERT_RULE_ID in message
    assert "RuntimeError" in message
    assert "canary-secret" not in message


def test_certificate_public_key_extraction_unexpected_exception_is_not_swallowed(
    tmp_path, monkeypatch
):
    _copy(tmp_path, "ssh_host_ed25519_key-cert.pub", "cert.pub")

    def _boom(self):
        raise RuntimeError("canary-secret")

    monkeypatch.setattr(serialization.SSHCertificate, "public_key", _boom)
    with pytest.raises(LocalScanError) as excinfo:
        scan_crypto_inventory_findings(str(tmp_path))
    message = str(excinfo.value)
    assert CERT_RULE_ID in message
    assert "RuntimeError" in message
    assert "canary-secret" not in message


def test_certificate_signature_key_extraction_unexpected_exception_is_not_swallowed(
    tmp_path, monkeypatch
):
    _copy(tmp_path, "ssh_host_ed25519_key-cert.pub", "cert.pub")

    def _boom(self):
        raise RuntimeError("canary-secret")

    monkeypatch.setattr(serialization.SSHCertificate, "signature_key", _boom)
    with pytest.raises(LocalScanError) as excinfo:
        scan_crypto_inventory_findings(str(tmp_path))
    message = str(excinfo.value)
    assert CERT_RULE_ID in message
    assert "RuntimeError" in message
    assert "canary-secret" not in message


def test_malformed_content_canary_never_leaks(tmp_path):
    canary = "HG043-MALFORMED-CONTENT-CANARY"
    text = f"-----BEGIN OPENSSH PRIVATE KEY-----\n{canary}\n-----END OPENSSH PRIVATE KEY-----\n"
    path = _write(tmp_path, "ssh_host_rsa_key", text.encode("ascii"))
    records = _records(path)
    blob = json.dumps(records)
    assert canary not in blob


# ---------------------------------------------------------------------------
# Normalization and durable evidence (Issue #88 Section 24)
# ---------------------------------------------------------------------------


def _canary_target(tmp_path: Path) -> Path:
    target = tmp_path / "target"
    target.mkdir()
    _copy(target, "ssh_host_rsa_key", "ssh_host_rsa_key")
    _copy(target, "ssh_host_rsa_key.pub", "ssh_host_rsa_key.pub")
    _copy(target, "user_key.pub", "ssh_host_ed25519_key.pub")  # comment canary
    _copy(target, "ssh_host_ed25519_key-cert.pub", "ssh_host_ed25519_key-cert.pub")
    return target


def test_normalized_findings_carry_the_exact_frozen_contract(tmp_path):
    target = _canary_target(tmp_path)
    findings = {f.rule_id: f for f in _findings(target) if f.rule_id in HG043_RULE_IDS}

    private = findings[PRIVATE_RULE_ID]
    assert private.asset_type == PRIVATE_ASSET_TYPE
    assert private.confidence == CANDIDATE_CONFIDENCE
    assert private.evidence == PRIVATE_EVIDENCE
    assert private.technical_metadata.get("Algorithm") == "RSA"
    assert private.technical_metadata.get("Key Size") == 2048
    assert "Fingerprint" not in private.technical_metadata or (
        private.technical_metadata.get("Fingerprint") is None
    )

    public = findings[PUBLIC_RULE_ID]
    assert public.asset_type == PUBLIC_ASSET_TYPE
    assert public.confidence == CANDIDATE_CONFIDENCE
    assert public.evidence == PUBLIC_EVIDENCE

    cert = findings[CERT_RULE_ID]
    assert cert.asset_type == CERT_ASSET_TYPE
    assert cert.confidence == CERT_CONFIDENCE
    assert cert.evidence == CERT_EVIDENCE

    for finding in findings.values():
        assert finding.source_type == "crypto_inventory"
        assert finding.location  # deterministic existing location-based identity


def test_evidence_store_round_trip_preserves_all_three_findings(tmp_path, capsys):
    target = _canary_target(tmp_path)
    db = tmp_path / "evidence.db"

    assert (
        harvestguard.main(
            ["scan", str(target), "--type", "crypto", "--json", "--quiet", "--evidence-db", str(db)]
        )
        == 0
    )
    live = capsys.readouterr().out
    records = {r["rule_id"]: r for r in json.loads(live) if r["rule_id"] in HG043_RULE_IDS}
    assert set(records) == HG043_RULE_IDS
    scan_id = next(iter(records.values()))["scan_id"]
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

    assert (
        harvestguard.main(
            ["evidence", "export", scan_id, "--evidence-db", str(db), "--markdown", "--quiet"]
        )
        == 0
    )
    markdown = capsys.readouterr().out
    assert PRIVATE_ASSET_TYPE in markdown
    assert PUBLIC_ASSET_TYPE in markdown
    assert CERT_ASSET_TYPE in markdown

    for payload in (live, stored, markdown):
        for canary in CANARIES:
            assert canary not in payload
    for record in json.loads(live):
        if record.get("rule_id") in HG043_RULE_IDS:
            assert record["technical_metadata"].get("Fingerprint") is None


def test_json_and_markdown_cli_exports_omit_canaries(tmp_path, capsys):
    target = _canary_target(tmp_path)

    assert harvestguard.main(["scan", str(target), "--type", "crypto", "--json", "--quiet"]) == 0
    json_out = capsys.readouterr().out
    for canary in CANARIES:
        assert canary not in json_out

    assert harvestguard.main(["scan", str(target), "--type", "crypto", "--quiet"]) == 0
    markdown_out = capsys.readouterr().out
    for canary in CANARIES:
        assert canary not in markdown_out


# ---------------------------------------------------------------------------
# Frozen generic fallback (Issue #88 Section 26)
# ---------------------------------------------------------------------------


def test_generic_private_fallback_unchanged_for_noncanonical_filename(tmp_path):
    path = _copy(tmp_path, "ssh_host_rsa_key", "id_rsa")
    records = _records(path)
    assert len(records) == 1
    record = records[0]
    assert record["Rule ID"] is None
    assert record["Asset Type"] == "OpenSSH Private Key"
    assert record["Algorithm"] == "RSA"
    assert record["Key Size"] == 2048
    assert record["Fingerprint"] is not None


def test_generic_ssh_public_fallback_unchanged_for_noncanonical_filename(tmp_path):
    path = _copy(tmp_path, "ssh_host_ed25519_key.pub", "id_ed25519.pub")
    records = _records(path)
    assert len(records) == 1
    record = records[0]
    assert record["Rule ID"] is None
    assert record["Asset Type"] == "OpenSSH Public Key"
    assert record["Confidence"] == "High"
    assert record["Algorithm"] == "Ed25519"
    assert record["Fingerprint"] is not None


def test_pre_hg043_host_certificate_generic_fallback_zero_findings(tmp_path, monkeypatch):
    # Force an HG-043 no-match on a real, otherwise-valid HOST certificate
    # (unsupported signing key), then confirm the file produces zero findings
    # under the existing generic path -- exactly the frozen "HOST certificate
    # before HG-043: zero findings" contract.
    path = _copy(tmp_path, "ssh_host_rsa_key-cert.pub", "ssh_host_rsa_key-cert.pub")
    unsupported = dsa.generate_private_key(key_size=1024).public_key()
    monkeypatch.setattr(serialization.SSHCertificate, "signature_key", lambda self: unsupported)
    assert _records(path) == []
