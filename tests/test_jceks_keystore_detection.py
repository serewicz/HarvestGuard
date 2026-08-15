"""Regression coverage for HG-037 (GitHub issue #82): JCEKS keystore-container
detection in the crypto-inventory scanner, the exact evidence-only finding
contract, and the deliberately narrow boundary of that claim (the top-level
header and a plausible container length, never an authenticated or fully parsed
store).

Complements tests/test_bcfks_keystore_detection.py (HG-036), which has the same
shape of coverage for the other Java keystore container, and
tests/test_crypto_detector_framework.py, which pins the registry composition
this adds one detector to.

Positive coverage uses **real JCEKS keystores written by OpenJDK's own
`keytool -storetype JCEKS`** (`tests/fixtures/crypto_inventory/jceks/`,
generated as recorded in that directory's PROVENANCE.md), never bytes this test
invented: four stores with different contents, passwords, and protected
material, all of which must produce the identical public finding contract.

Negative controls are constructed narrowly here rather than committed --
empty, truncated, unsupported-version, near-match, and misleading-name inputs,
plus the neighbouring real formats (JKS, BCFKS, PKCS#12, DER) that must keep
their own classification.
"""

from __future__ import annotations

import hashlib
import json
import os
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
from scanner.filesystem import scan_filesystem_findings

REPO_ROOT = Path(__file__).parent.parent
FIXTURE_DIR = Path(__file__).parent / "fixtures" / "crypto_inventory"
JCEKS_DIR = FIXTURE_DIR / "jceks"
BCFKS_DIR = FIXTURE_DIR / "bcfks"

# The real stores this generic-detector suite exercises, and what each one was
# at generation time. The generated contents are recorded here only to show
# that the *same* public contract comes out of a keystore, a secret-key store,
# and an empty store: HarvestGuard cannot tell them apart and never claims to.
#
# trusted_certificate_store.jceks is deliberately not included here: HG-042
# reuses it as its own documented JCEKS v2 trusted-certificate-only positive
# fixture (see tests/fixtures/crypto_inventory/java_truststore/PROVENANCE.md),
# and the terminal java_truststore:jceks detector now claims it before this
# generic rule ever sees it. Its generic-fallback behavior is no longer
# applicable to that file; tests/test_java_truststore_detection.py covers its
# new classification and privacy contract instead.
REAL_FIXTURES = {
    "private_key_store.jceks": "private-key store (RSA 2048 + self-signed cert)",
    "secret_key_store.jceks": "secret-key store (AES 256, a serialized SealedObject)",
    "empty_store.jceks": "empty store (minimum valid form, 32 bytes)",
}

ASSET_TYPE = "Java Keystore"
RULE_ID = "java_keystore:jceks"
EVIDENCE = "JCEKS keystore header detected"
CONFIDENCE = "Medium"
FORMAT = "JCEKS"

MAGIC = b"\xce\xce\xce\xce"
JKS_MAGIC = b"\xfe\xed\xfe\xed"

# Everything the fixtures' PROVENANCE.md records about what is *inside* the
# stores, none of which may ever appear in HarvestGuard's own output.
GENERATION_SECRETS = (
    "password123",
    "trustpass456",
    "aDifferentPassphrase!42",
    "HarvestGuard JCEKS Test",
    "trusted1",
    "sk1",
)


def _real_store(name: str = "private_key_store.jceks") -> bytes:
    return (JCEKS_DIR / name).read_bytes()


def _write(directory: Path, name: str, data: bytes) -> Path:
    path = directory / name
    path.write_bytes(data)
    return path


def _header(version: int = 2, entry_count: int = 1) -> bytes:
    """A JCEKS top-level header built independently of the implementation, for
    the negative controls that vary exactly one header field."""
    return (
        MAGIC
        + version.to_bytes(4, "big", signed=True)
        + entry_count.to_bytes(4, "big", signed=True)
    )


def _only_finding(target: Path):
    findings = scan_crypto_inventory_findings(str(target))
    assert len(findings) == 1, [f.rule_id for f in findings]
    return findings[0]


# --- 1-10. The positive contract, from real keytool output ------------------


@pytest.mark.parametrize("name", sorted(REAL_FIXTURES))
def test_real_keytool_store_produces_the_exact_finding_contract(tmp_path, name):
    _write(tmp_path, name, _real_store(name))

    finding = _only_finding(tmp_path)

    assert finding.asset_type == ASSET_TYPE
    assert finding.rule_id == RULE_ID
    assert finding.confidence == CONFIDENCE
    assert finding.evidence == EVIDENCE
    assert finding.technical_metadata["Format"] == FORMAT


def test_every_real_store_produces_the_same_public_contract(tmp_path):
    # A private-key store, a secret-key store, and an empty store: three
    # different sets of protected contents, one identical public claim, which is
    # the point -- the detector reads the container header and nothing else.
    for name in REAL_FIXTURES:
        _write(tmp_path, name, _real_store(name))

    findings = scan_crypto_inventory_findings(str(tmp_path))

    assert len(findings) == len(REAL_FIXTURES)
    contracts = {
        (f.asset_type, f.rule_id, f.confidence, f.evidence, f.technical_metadata["Format"])
        for f in findings
    }
    assert contracts == {(ASSET_TYPE, RULE_ID, CONFIDENCE, EVIDENCE, FORMAT)}


def test_the_minimum_size_store_is_the_header_plus_the_trailing_digest():
    # The empty store keytool writes is exactly 12 header bytes + 20 digest
    # bytes, which is where the detector's minimum-size rule comes from.
    assert len(_real_store("empty_store.jceks")) == 32


def test_version_one_is_accepted(tmp_path):
    # OpenJDK's JceKeyStore supports format versions 1 and 2; the JDK available
    # here writes version 2 only, so version 1 is exercised by changing exactly
    # the four version bytes of a real store rather than by inventing a file.
    store = _real_store()
    _write(tmp_path, "v1.jceks", store[:4] + (1).to_bytes(4, "big") + store[8:])

    assert _only_finding(tmp_path).rule_id == RULE_ID


def test_one_valid_store_emits_exactly_one_jceks_finding(tmp_path):
    _write(tmp_path, "store.jceks", _real_store())

    df = scan_crypto_inventory(str(tmp_path))

    assert list(df["Rule ID"]) == [RULE_ID]
    assert len(df) == 1


def test_crypto_scan_emits_the_finding_and_filesystem_scan_does_not(tmp_path):
    _write(tmp_path, "store.jceks", _real_store())

    crypto_findings = scan_crypto_inventory_findings(str(tmp_path))
    filesystem_findings = scan_filesystem_findings(str(tmp_path))

    assert [f.rule_id for f in crypto_findings] == [RULE_ID]
    assert [f for f in filesystem_findings if f.rule_id == RULE_ID] == []
    assert [f for f in filesystem_findings if f.asset_type == ASSET_TYPE] == []


def test_the_store_is_read_once_through_the_shared_context(tmp_path, monkeypatch):
    target = _write(tmp_path, "store.jceks", _real_store())
    reads: list[str] = []
    real_read_bytes = Path.read_bytes

    def counting_read_bytes(self):
        reads.append(str(self))
        return real_read_bytes(self)

    monkeypatch.setattr(Path, "read_bytes", counting_read_bytes)
    findings = scan_crypto_inventory_findings(str(tmp_path))

    assert [f.rule_id for f in findings] == [RULE_ID]
    assert reads == [str(target)]


def test_one_jceks_file_counts_once_in_crypto_files_inspected(tmp_path, capsys):
    _write(tmp_path, "store.jceks", _real_store())
    for index in range(3):
        (tmp_path / f"ordinary_{index}.txt").write_text("harvestguard fixture text")

    stats: dict[str, int] = {}
    scan_crypto_inventory(str(tmp_path), stats=stats)
    assert stats["files_inspected"] == 4

    assert (
        harvestguard.main(["scan", str(tmp_path), "--type", "crypto", "--summary", "--quiet"])
        == 0
    )
    output = capsys.readouterr().out
    assert "Crypto files inspected: 4" in output
    assert "Files scanned: 0" in output
    for jceks_specific in ("jceks files", "keystores inspected", RULE_ID):
        assert jceks_specific not in output.lower()


# --- 11-20. Content beats extension -----------------------------------------


MISLEADING_NAMES = (
    "store",
    "store.bin",
    "store.jks",
    "store.p12",
    "store.pfx",
    "store.der",
    "store.cer",
    "store.crt",
    "store.jceks",
    "STORE.JCEKS",
)


@pytest.mark.parametrize("name", MISLEADING_NAMES)
def test_jceks_content_beats_a_misleading_extension(tmp_path, name):
    # In particular `.p12`/`.pfx`/`.der` must not fall through into a malformed
    # PKCS#12 or DER finding, and `store`/`store.bin` must not be missed by the
    # extension-based candidate gate.
    _write(tmp_path, name, _real_store())

    finding = _only_finding(tmp_path)

    assert finding.rule_id == RULE_ID
    assert finding.asset_type == ASSET_TYPE
    assert "malformed" not in finding.asset_type.lower()


def test_every_misleading_extension_in_one_scan(tmp_path):
    for index, name in enumerate(MISLEADING_NAMES):
        subdir = tmp_path / f"d{index}"
        subdir.mkdir()
        _write(subdir, name, _real_store())

    findings = scan_crypto_inventory_findings(str(tmp_path))

    assert len(findings) == len(MISLEADING_NAMES)
    assert {f.rule_id for f in findings} == {RULE_ID}


def test_a_jceks_extension_alone_never_produces_a_finding(tmp_path):
    # The filename is never evidence: these are the same names as above with
    # content that is not a JCEKS store.
    for name in ("empty.jceks", "text.jceks", "JKS.JCEKS"):
        subdir = tmp_path / name.replace(".", "_")
        subdir.mkdir()
        _write(subdir, name, b"" if name.startswith("empty") else b"not a keystore at all\n")

    assert [
        f for f in scan_crypto_inventory_findings(str(tmp_path)) if f.rule_id == RULE_ID
    ] == []


def test_a_jceks_match_is_terminal_for_that_file(tmp_path):
    # Terminal means no later detector also reports the same asset: valid JCEKS
    # bytes named store.p12 produce one finding, not a JCEKS finding plus a
    # malformed-PKCS#12 one.
    _write(tmp_path, "store.p12", _real_store())

    findings = scan_crypto_inventory_findings(str(tmp_path))

    assert [f.rule_id for f in findings] == [RULE_ID]
    assert [f.asset_type for f in findings] == [ASSET_TYPE]


# --- 21-40. Negative controls -----------------------------------------------


NEGATIVE_CONTROLS = {
    "empty file": b"",
    "truncated magic": MAGIC[:3],
    "correct magic only": MAGIC,
    "magic + truncated version": MAGIC + b"\x00\x00",
    "magic + unsupported version 0": _header(version=0) + b"\x00" * 20,
    "magic + unsupported version 3": _header(version=3) + b"\x00" * 20,
    "magic + unsupported version 255": _header(version=255) + b"\x00" * 20,
    "magic + negative version": _header(version=-1) + b"\x00" * 20,
    "magic + version + missing entry count": MAGIC + (2).to_bytes(4, "big"),
    "magic + version + truncated entry count": MAGIC + (2).to_bytes(4, "big") + b"\x00\x00",
    "negative entry count": _header(entry_count=-1) + b"\x00" * 20,
    "most negative entry count": _header(entry_count=-(2**31)) + b"\x00" * 20,
    "truncated container (header only)": _real_store()[:12],
    "truncated container (one byte short)": _real_store("empty_store.jceks")[:31],
    "near-match magic cececf": b"\xce\xce\xce\xcf" + b"\x00" * 60,
    "near-match magic cdcecece": b"\xcd\xce\xce\xce" + b"\x00" * 60,
    "jceks magic at a nonzero offset": b"\x00" + _real_store(),
    "jceks magic after a JKS header": JKS_MAGIC + _real_store(),
}


@pytest.mark.parametrize("case", sorted(NEGATIVE_CONTROLS))
def test_near_matches_produce_no_jceks_finding(tmp_path, case):
    _write(tmp_path, "candidate.jceks", NEGATIVE_CONTROLS[case])

    assert [
        f for f in scan_crypto_inventory_findings(str(tmp_path)) if f.rule_id == RULE_ID
    ] == []


def test_no_negative_control_becomes_a_scanner_error_or_a_partial_finding(tmp_path):
    for index, (case, data) in enumerate(sorted(NEGATIVE_CONTROLS.items())):
        _write(tmp_path, f"case_{index}.jceks", data)

    traversal_errors: list[str] = []
    detector_errors: list[str] = []
    df = scan_crypto_inventory(
        str(tmp_path),
        traversal_errors=traversal_errors,
        detector_errors=detector_errors,
    )

    assert traversal_errors == []
    assert detector_errors == []
    assert RULE_ID not in set(df["Rule ID"].dropna())


def test_the_neighbouring_real_formats_keep_their_own_classification(tmp_path):
    cases = {
        "sample.jks": (FIXTURE_DIR / "sample.jks").read_bytes(),
        "store.bcfks": (BCFKS_DIR / "private_key_store.bcfks").read_bytes(),
        "bundle.p12": (FIXTURE_DIR / "bundle.p12").read_bytes(),
        "rsa_cert.der": (FIXTURE_DIR / "rsa_cert.der").read_bytes(),
        "random.bin": (FIXTURE_DIR / "random.bin").read_bytes(),
    }
    for name, data in cases.items():
        subdir = tmp_path / name.replace(".", "_")
        subdir.mkdir()
        _write(subdir, name, data)

    findings = scan_crypto_inventory_findings(str(tmp_path))

    assert [f for f in findings if f.rule_id == RULE_ID] == []
    by_name = {Path(f.location).name: f for f in findings}
    # JKS keeps its own detector identity and its existing Medium/magic-header
    # contract, unchanged by HG-037.
    assert by_name["sample.jks"].asset_type == ASSET_TYPE
    assert by_name["sample.jks"].evidence == "JKS magic header detected"
    assert by_name["sample.jks"].rule_id is None
    # BCFKS keeps its own rule id and High confidence.
    assert by_name["store.bcfks"].rule_id == "java_keystore:bcfks"
    assert by_name["store.bcfks"].confidence == "High"
    assert by_name["store.bcfks"].technical_metadata["Format"] == "BCFKS"


def test_jks_and_jceks_remain_distinct_detectors():
    jks = [d for d in CRYPTO_DETECTORS if d.detector_id == "java_keystore:jks_magic"]
    jceks = [d for d in CRYPTO_DETECTORS if d.detector_id == RULE_ID]

    assert len(jks) == 1 and len(jceks) == 1
    assert jks[0].detect is not jceks[0].detect
    assert jks[0].evidence == "JKS magic header detected"
    assert jks[0].rule_id is None


def test_committed_non_jceks_fixtures_are_unaffected(tmp_path):
    # A whole-directory scan of the existing fixture corpus gains no
    # *unexpected* JCEKS finding and loses none of its own. HG-042 legitimately
    # changes this count by one in each direction:
    # tests/fixtures/crypto_inventory/jceks/trusted_certificate_store.jceks is
    # now claimed by the terminal java_truststore:jceks detector instead (see
    # REAL_FIXTURES above), while
    # tests/fixtures/crypto_inventory/java_truststore/mixed_store.jceks -- a
    # JCEKS store HG-042 deliberately declines because it mixes a
    # trusted-certificate entry with a private-key and a secret-key entry --
    # falls through to this generic rule exactly as HG-042's own contract
    # requires.
    findings = scan_crypto_inventory_findings(str(FIXTURE_DIR))
    jceks = [f for f in findings if f.rule_id == RULE_ID]

    assert {Path(f.location).parent.name for f in jceks} == {"jceks", "java_truststore"}
    assert len(jceks) == len(REAL_FIXTURES) + 1


# --- 41-50. Detector registry -----------------------------------------------


def test_registry_includes_the_jceks_detector_exactly_once_with_a_unique_id():
    ids = [d.detector_id for d in CRYPTO_DETECTORS]

    assert ids.count(RULE_ID) == 1
    assert len(ids) == len(set(ids))


def test_jceks_detector_declares_the_required_contract():
    detector = next(d for d in CRYPTO_DETECTORS if d.detector_id == RULE_ID)

    assert detector.priority == 37
    assert detector.terminal is True
    assert detector.rule_id == RULE_ID
    assert detector.confidence == CONFIDENCE
    assert detector.evidence == EVIDENCE
    assert detector.metadata_keys == frozenset({"Format"})
    assert detector.scope == "file"
    assert detector.verification_rationale


def test_registry_order_is_explicit_and_places_jceks_between_bcfks_and_jks():
    assert [d.detector_id for d in CRYPTO_DETECTORS] == [
        "encrypted_file:openssl",
        "encrypted_file:openpgp",
        "encrypted_file:age",
        "encrypted_filesystem:gocryptfs",
        "nss:sql_database_set",
        "java_keystore:bcfks",
        "java_truststore:jceks",
        "java_keystore:jceks",
        "java_truststore:jks",
        "java_keystore:jks_magic",
        "private_key:pkcs8_encrypted",
        "cms:enveloped_data",
        "cms:encrypted_data",
        "pkcs12:container",
        "certificate:der",
        "certificate:pem",
        "private_key:legacy_pem_encrypted",
        "openssh_host_identity:private_key",
        "private_key:pem",
        "openssh_host_identity:public_key",
        "openssh_host_identity:host_certificate",
        "kubernetes_secret:tls",
        "public_key:ssh",
    ]
    priorities = [d.priority for d in CRYPTO_DETECTORS]
    assert priorities == sorted(priorities)
    assert len(priorities) == len(set(priorities))
    by_id = {d.detector_id: d.priority for d in CRYPTO_DETECTORS}
    assert by_id["java_keystore:bcfks"] < by_id[RULE_ID] < by_id["java_keystore:jks_magic"]
    assert by_id[RULE_ID] < by_id["pkcs12:container"] < by_id["certificate:der"]


# --- 51-60. Normalization, evidence store, and output shape -----------------


def test_normalized_finding_preserves_the_whole_contract(tmp_path):
    _write(tmp_path, "store.jceks", _real_store())

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


def test_dataframe_columns_are_unchanged(tmp_path):
    _write(tmp_path, "store.jceks", _real_store())
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
    _write(tmp_path, "store.jceks", _real_store())

    first = scan_crypto_inventory_findings(str(tmp_path))
    second = scan_crypto_inventory_findings(str(tmp_path))

    assert [f.finding_id for f in first] == [f.finding_id for f in second]


def test_cli_json_carries_the_finding_and_markdown_stays_evidence_only(tmp_path, capsys):
    _write(tmp_path, "store.jceks", _real_store())

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
    _write(target, "store.jceks", _real_store())
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

    assert (
        harvestguard.main(
            ["evidence", "verify", scan_id, "--evidence-db", str(db)]
        )
        == 0
    )
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
    assert record["rule_id"] == RULE_ID
    assert record["asset_type"] == ASSET_TYPE
    assert record["confidence"] == CONFIDENCE
    assert record["evidence"] == EVIDENCE
    assert record["technical_metadata"]["Format"] == FORMAT


def test_safe_metadata_carries_only_the_format_key(tmp_path):
    _write(tmp_path, "store.jceks", _real_store())

    finding = _only_finding(tmp_path)
    populated = {k: v for k, v in finding.technical_metadata.items() if v is not None}

    assert populated == {"Format": FORMAT}


# --- 61-70. Privacy: nothing inside the store reaches output ----------------


@pytest.mark.parametrize("name", sorted(REAL_FIXTURES))
def test_no_store_content_reaches_json_or_markdown(tmp_path, capsys, name):
    store = _real_store(name)
    _write(tmp_path, name, store)

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
        # Passwords, aliases, and the certificate subject used at generation
        # time: recorded in PROVENANCE.md, never in a finding.
        for secret in GENERATION_SECRETS:
            assert secret.lower() not in lowered
        # The trailing keyed digest, in hex and base64-ish raw form.
        assert store[-20:].hex() not in lowered
        # No byte excerpt of the store: every 8-byte window past the header,
        # hex-encoded, must be absent.
        for offset in range(12, min(len(store), 160) - 8):
            assert store[offset : offset + 8].hex() not in lowered
        # No Java serialization stream marker leaks through either.
        assert "aced0005" not in lowered
        assert "sealedobject" not in lowered


def test_the_finding_makes_no_entry_or_authentication_claim(tmp_path, capsys):
    for name in REAL_FIXTURES:
        _write(tmp_path, name, _real_store(name))

    assert (
        harvestguard.main(["scan", str(tmp_path), "--type", "crypto", "--json", "--quiet"]) == 0
    )
    payload = json.loads(capsys.readouterr().out)

    assert len(payload) == len(REAL_FIXTURES)
    for record in payload:
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
            "secret key",
            "certificate",
            "digest",
            "verified",
            "authenticated",
            "serial",
        ):
            assert forbidden not in claims


def test_detection_requires_no_password_and_deserializes_nothing(tmp_path, monkeypatch):
    import pickle

    def _forbidden(*args, **kwargs):  # pragma: no cover - must never run
        raise AssertionError("the JCEKS detector must not deserialize or prompt")

    monkeypatch.setattr(pickle, "loads", _forbidden)
    monkeypatch.setattr("builtins.input", _forbidden)
    _write(tmp_path, "store.jceks", _real_store("secret_key_store.jceks"))

    assert [f.rule_id for f in scan_crypto_inventory_findings(str(tmp_path))] == [RULE_ID]

    source = (REPO_ROOT / "scanner" / "crypto_inventory.py").read_text(encoding="utf-8")
    for forbidden_api in ("getpass", "javaobj", "pyjks", "pickle", "marshal"):
        assert forbidden_api not in source.lower()


def test_detection_invokes_no_external_process(tmp_path, monkeypatch):
    source = (REPO_ROOT / "scanner" / "crypto_inventory.py").read_text(encoding="utf-8")
    assert "subprocess" not in source

    def _forbidden(*args, **kwargs):  # pragma: no cover - must never run
        raise AssertionError("the JCEKS detector must not invoke an external process")

    for name in ("run", "Popen", "check_output", "call"):
        monkeypatch.setattr(subprocess, name, _forbidden)
    monkeypatch.setattr(os, "system", _forbidden)
    _write(tmp_path, "store.jceks", _real_store())

    assert [f.rule_id for f in scan_crypto_inventory_findings(str(tmp_path))] == [RULE_ID]


def test_jceks_introduces_no_new_asset_type(tmp_path):
    _write(tmp_path, "store.jceks", _real_store())
    (tmp_path / "sample.jks").write_bytes((FIXTURE_DIR / "sample.jks").read_bytes())

    findings = scan_crypto_inventory_findings(str(tmp_path))

    assert {f.asset_type for f in findings} == {ASSET_TYPE}
    # HG-042 legitimately added a second "jceks" rule ID,
    # java_truststore:jceks, for a structurally different, narrower claim
    # (trusted-certificate-only store structure) with its own asset type. It
    # does not introduce a new *generic* JCEKS asset type, which is what this
    # test otherwise guards.
    jceks_rule_ids = {
        d.rule_id for d in CRYPTO_DETECTORS if d.rule_id and "jceks" in d.rule_id
    }
    assert jceks_rule_ids == {RULE_ID, "java_truststore:jceks"}


def test_no_new_dependency_is_declared_for_jceks():
    for manifest in ("requirements.txt", "requirements-dev.txt", "pyproject.toml"):
        text = (REPO_ROOT / manifest).read_text(encoding="utf-8").lower()
        for library in ("pyjks", "javaobj", "jks", "twisted"):
            assert library not in text


def test_the_committed_fixtures_are_the_recorded_real_artifacts():
    # Provenance is part of the contract: positive coverage must keep resting on
    # the recorded keytool output rather than on regenerated or hand-edited
    # bytes.
    provenance = (JCEKS_DIR / "PROVENANCE.md").read_text(encoding="utf-8")

    for name in REAL_FIXTURES:
        data = (JCEKS_DIR / name).read_bytes()
        assert hashlib.sha256(data).hexdigest() in provenance
        assert str(len(data)) in provenance
        assert name in provenance
        assert data[:4] == MAGIC
    assert "-storetype JCEKS" in provenance
    assert "OpenJDK 17.0.19" in provenance


def test_characterization_documents_the_jceks_boundary():
    doc = (REPO_ROOT / "docs" / "DETECTION_CHARACTERIZATION.md").read_text(encoding="utf-8")

    assert "JCEKS" in doc
    assert RULE_ID in doc
    assert EVIDENCE in doc
