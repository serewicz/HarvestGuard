"""Regression coverage for the shared crypto-detector framework (HG-033).

HG-033 is an implementation refactor that adds no detection capability, so the
detector families themselves are still pinned by the tests that were written
with them: tests/test_crypto_inventory.py (PEM/DER/PKCS#12/JKS/SSH and
malformed assets), tests/test_openssl_encrypted_file_detection.py,
tests/test_openpgp_encrypted_file_detection.py,
tests/test_gocryptfs_encrypted_filesystem_detection.py,
tests/test_detection_characterization.py, tests/test_cli.py, and
tests/test_reports.py -- all of which pass unmodified against the framework.

What this file adds is coverage of the framework's own contracts, which those
tests cannot see: registry composition and determinism, that intentional
precedence is declared rather than incidental, that accounting counts files
rather than detector invocations, that one file is read once no matter how many
detectors inspect it, that detectors cannot traverse, that undeclared metadata
cannot reach a normalized finding, and that an unexpected detector exception
becomes a scanner error with partial findings preserved instead of a clean
non-match.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

import harvestguard
import scanner.crypto_inventory as crypto_inventory
from finding_adapters import normalize_crypto_inventory_df
from scanner.crypto_detectors import (
    SAFE_METADATA_KEYS,
    SCOPE_FILE,
    SCOPE_ROOT,
    DetectionResult,
    DetectorExecutionError,
    FileContext,
    FileDetector,
    RootContext,
    RootDetector,
    build_registry,
    enforce_metadata_allowlist,
    run_detectors,
)
from scanner.crypto_inventory import (
    CRYPTO_DETECTORS,
    CryptoInventoryFinding,
    scan_crypto_inventory,
    scan_crypto_inventory_findings,
)
from scanner.errors import LocalScanError

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "crypto_inventory"

# Every detector family the crypto-inventory scanner supports, exactly once
# each. A new entry here means a new detection capability, which is what makes
# one reviewable: HG-033 (the framework itself) added none, HG-035 added exactly
# one (the native age v1 encrypted-file detector), HG-036 added exactly one
# (the BCFKS keystore-container detector), and HG-037 added exactly one (the
# JCEKS keystore-container detector, a separate format and identity from the
# existing JKS detector below it). HG-039 added exactly two, the CMS/PKCS#7
# EnvelopedData and EncryptedData encrypted-object detectors, which are two
# separate content types with two separate rule identities rather than one
# detector that reports which it saw. HG-041 added exactly one, the aggregate
# NSS SQL database-set root detector -- one root detector for the whole
# canonical set, not one detector per component file. HG-042 added exactly two,
# the JKS and JCEKS trusted-certificate-only store detectors: two formats, two
# identities, each sitting immediately ahead of its own generic keystore
# detector rather than replacing it.
EXPECTED_DETECTOR_IDS = [
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

# The only rule IDs any crypto-inventory detector may carry. Every other asset
# type leaves rule_id unset (parsed certificates and keys have no named
# detection rule); HG-033 introduced none, HG-035 introduced exactly one,
# HG-036 introduced exactly one, HG-037 introduced exactly one, HG-038
# introduced exactly one, HG-039 introduced exactly two, and HG-041 introduced
# exactly one (`nss:sql_database_set`, the aggregate NSS set; there is
# deliberately no file-level `nss:*` rule for pkcs11.txt, cert9.db, or key4.db),
# and HG-042 introduced exactly two (`java_truststore:jks` and
# `java_truststore:jceks`, the trusted-certificate-only store structures),
# HG-043 introduced exactly three (`openssh_host_identity:private_key`,
# `openssh_host_identity:public_key`, `openssh_host_identity:host_certificate`),
# and HG-044 introduced exactly one (`kubernetes_secret:tls`, the aggregate
# Kubernetes TLS Secret manifest-document claim).
# The generic JKS detector deliberately remains without one, unchanged by
# HG-037, HG-038, HG-039, HG-041, HG-042, HG-043, and HG-044; the same is true
# of the generic private_key:pem and public_key:ssh detectors HG-043 and
# HG-044 sit beside.
EXPECTED_RULE_IDS = {
    "encrypted_file:openssl",
    "encrypted_file:openpgp",
    "encrypted_file:age",
    "encrypted_filesystem:gocryptfs",
    "nss:sql_database_set",
    "java_keystore:bcfks",
    "java_keystore:jceks",
    "java_truststore:jks",
    "java_truststore:jceks",
    "private_key:pkcs8_encrypted",
    "cms:enveloped_data",
    "cms:encrypted_data",
    "private_key:legacy_pem_encrypted",
    "openssh_host_identity:private_key",
    "openssh_host_identity:public_key",
    "openssh_host_identity:host_certificate",
    "kubernetes_secret:tls",
}


def _detector(detector_id: str):
    return next(d for d in CRYPTO_DETECTORS if d.detector_id == detector_id)


def _priority(detector_id: str) -> int:
    return _detector(detector_id).priority


def _records(findings: list[CryptoInventoryFinding]) -> list[dict]:
    # Observed At is scan time, not an asset property, so it is excluded when
    # two runs are compared field for field.
    return [
        {k: v for k, v in finding.to_record().items() if k != "Observed At"}
        for finding in findings
    ]


def _multi_asset_pem(tmp_path: Path) -> Path:
    """One file three separate, non-terminal detectors legitimately report on:
    a PEM certificate, a PEM private key, and an OpenSSH public key."""
    target = tmp_path / "bundle.pem"
    target.write_bytes(
        (FIXTURE_DIR / "rsa_cert.pem").read_bytes()
        + (FIXTURE_DIR / "valid_key.pem").read_bytes()
        + (FIXTURE_DIR / "ssh_key.pub").read_bytes()
    )
    return target


def _gocryptfs_root(tmp_path: Path) -> Path:
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
    return root


# --- 1-3. Registry composition, uniqueness, deterministic order -------------


def test_registry_contains_every_migrated_detector_exactly_once():
    assert [d.detector_id for d in CRYPTO_DETECTORS] == EXPECTED_DETECTOR_IDS


def test_detector_ids_are_unique():
    ids = [d.detector_id for d in CRYPTO_DETECTORS]
    assert len(ids) == len(set(ids))


def test_build_registry_rejects_duplicate_detector_ids():
    duplicate = _detector("certificate:pem")
    with pytest.raises(ValueError, match="duplicate crypto detector id"):
        build_registry([duplicate, duplicate])


def test_build_registry_rejects_empty_detector_id():
    with pytest.raises(ValueError, match="non-empty"):
        build_registry(
            [
                FileDetector(
                    detector_id="",
                    priority=1,
                    candidate=lambda context: False,
                    detect=lambda context: DetectionResult.no_match(),
                    evidence="",
                    confidence="Low",
                )
            ]
        )


def test_registry_order_is_declared_priority_not_input_order():
    # Perturbing the input cannot change the registry: order comes from the
    # declared priorities alone, never from import order, filesystem order, or
    # an environment variable.
    perturbed = list(reversed(CRYPTO_DETECTORS))
    assert build_registry(perturbed) == CRYPTO_DETECTORS

    rotated = list(CRYPTO_DETECTORS[4:]) + list(CRYPTO_DETECTORS[:4])
    assert build_registry(rotated) == CRYPTO_DETECTORS


def test_registry_priorities_are_strictly_increasing_and_unique():
    priorities = [d.priority for d in CRYPTO_DETECTORS]
    assert priorities == sorted(priorities)
    assert len(priorities) == len(set(priorities))


def test_build_registry_rejects_duplicate_priorities():
    # A shared priority would leave the relative order of the two detectors
    # decided by the caller's listing order -- the input-order dependence a
    # static registry exists to rule out -- so it is rejected at build time
    # rather than tie-broken silently.
    def _stub(detector_id: str):
        return FileDetector(
            detector_id=detector_id,
            priority=7,
            candidate=lambda context: False,
            detect=lambda context: DetectionResult.no_match(),
            evidence="",
            confidence="Low",
        )

    with pytest.raises(ValueError, match="duplicate crypto detector priority 7"):
        build_registry([_stub("test:a"), _stub("test:b")])


def test_every_detector_declares_a_supported_scope():
    for detector in CRYPTO_DETECTORS:
        assert detector.scope in {SCOPE_FILE, SCOPE_ROOT}
    assert _detector("encrypted_filesystem:gocryptfs").scope == SCOPE_ROOT
    assert _detector("certificate:pem").scope == SCOPE_FILE


# --- 4. Intentional precedence is explicit ---------------------------------


def test_intentional_precedence_is_declared_in_the_registry():
    # OpenSSL and OpenPGP structural detection ahead of every extension-based
    # branch, so a Salted__/OpenPGP file with a misleading .p12/.der extension
    # is not reported as a malformed container (HG-030, HG-031).
    for structural in ("encrypted_file:openssl", "encrypted_file:openpgp"):
        for extension_based in ("pkcs12:container", "certificate:der", "java_keystore:jks_magic"):
            assert _priority(structural) < _priority(extension_based)

    # gocryptfs root classification ahead of the file-format branches, so its
    # marker file is never read as PEM/DER/PKCS#12 content (HG-032).
    assert _priority("encrypted_filesystem:gocryptfs") < _priority("pkcs12:container")
    assert _priority("encrypted_filesystem:gocryptfs") < _priority("certificate:pem")

    # Both Java keystore container detectors ahead of the extension-based
    # branches, so a valid store with a misleading .p12/.der/.jks name (or no
    # extension at all) is classified from its content rather than as a
    # malformed container (HG-036, HG-037). JCEKS sits between BCFKS and JKS:
    # three distinct formats, three distinct detector identities.
    for keystore in ("java_keystore:bcfks", "java_keystore:jceks"):
        for extension_based in ("pkcs12:container", "certificate:der", "certificate:pem"):
            assert _priority(keystore) < _priority(extension_based)
    assert (
        _priority("java_keystore:bcfks")
        < _priority("java_keystore:jceks")
        < _priority("java_keystore:jks_magic")
    )

    # Encrypted PKCS#8 ahead of the extension-based container and certificate
    # branches, so a valid encrypted key with no extension or a misleading
    # .der/.crt/.cer/.p12/.pfx name is classified from its structure rather than
    # missed by the extension gate or reported as malformed certificate or
    # PKCS#12 evidence, and ahead of the generic PEM private-key branch whose
    # exception-driven recognition it replaced (HG-038).
    for extension_based in ("pkcs12:container", "certificate:der", "private_key:pem"):
        assert _priority("private_key:pkcs8_encrypted") < _priority(extension_based)
    # ...but still after every terminal container detector that owns a whole
    # file of its own, so it cannot take one from them.
    for container in (
        "java_keystore:bcfks",
        "java_keystore:jceks",
        "java_keystore:jks_magic",
        "encrypted_filesystem:gocryptfs",
    ):
        assert _priority(container) < _priority("private_key:pkcs8_encrypted")

    # Both CMS/PKCS#7 encrypted-object rules ahead of the extension-based
    # container and certificate branches, so a valid object with no extension or
    # a misleading .der/.cer/.crt/.p12/.pfx name is classified from its
    # structure rather than missed by the extension gate or reported as
    # malformed certificate or PKCS#12 evidence, and after every keystore and
    # encrypted-PKCS#8 detector, whose formats a CMS ContentInfo cannot satisfy
    # (HG-039).
    for extension_based in ("pkcs12:container", "certificate:der", "private_key:pem"):
        assert _priority("cms:enveloped_data") < _priority(extension_based)
        assert _priority("cms:encrypted_data") < _priority(extension_based)
    for earlier in (
        "java_keystore:bcfks",
        "java_keystore:jceks",
        "java_keystore:jks_magic",
        "private_key:pkcs8_encrypted",
    ):
        assert _priority(earlier) < _priority("cms:enveloped_data")
        assert _priority(earlier) < _priority("cms:encrypted_data")
    assert _priority("cms:enveloped_data") < _priority("cms:encrypted_data")

    # Certificate/key precedence within the text detectors.
    assert _priority("certificate:der") < _priority("certificate:pem")
    assert _priority("certificate:pem") < _priority("private_key:legacy_pem_encrypted")
    assert _priority("private_key:legacy_pem_encrypted") < _priority("private_key:pem")
    assert _priority("private_key:pem") < _priority("public_key:ssh")
    # Legacy PEM does not reorder PKCS#12, CMS, or encrypted PKCS#8.
    assert _priority("private_key:pkcs8_encrypted") < _priority("pkcs12:container")
    assert _priority("cms:encrypted_data") < _priority("pkcs12:container")
    assert _priority("pkcs12:container") < _priority("private_key:legacy_pem_encrypted")


def test_terminal_declarations_match_current_dispatch_behavior():
    # Everything that claims a whole file is terminal...
    for terminal_id in (
        "encrypted_file:openssl",
        "encrypted_file:openpgp",
        "java_keystore:bcfks",
        "java_keystore:jceks",
        "java_keystore:jks_magic",
        "private_key:pkcs8_encrypted",
        "cms:enveloped_data",
        "cms:encrypted_data",
        "pkcs12:container",
        "certificate:der",
    ):
        assert _detector(terminal_id).terminal is True
    # ...and the text detectors (including non-terminal legacy encrypted PEM)
    # are not, because one PEM file may legitimately hold a certificate, a
    # private key, and an SSH public key at once. There is no general "first
    # detector wins" rule.
    for coexisting_id in (
        "private_key:legacy_pem_encrypted",
        "certificate:pem",
        "private_key:pem",
        "public_key:ssh",
    ):
        assert _detector(coexisting_id).terminal is False
    assert _detector("encrypted_filesystem:gocryptfs").owns_marker is True


def test_registry_order_perturbation_does_not_change_scan_results():
    reversed_registry = build_registry(list(reversed(CRYPTO_DETECTORS)))
    for file_path in sorted(FIXTURE_DIR.iterdir()):
        if not file_path.is_file():
            continue
        assert _records(crypto_inventory._scan_file(file_path)) == _records(
            crypto_inventory._scan_file(file_path, reversed_registry)
        )


# --- 36. No new asset type or rule ID -------------------------------------


def test_registry_introduces_no_new_rule_id():
    declared = {d.rule_id for d in CRYPTO_DETECTORS if d.rule_id is not None}
    assert declared == EXPECTED_RULE_IDS


def test_declared_rule_ids_match_emitted_rule_ids():
    findings = scan_crypto_inventory_findings(str(FIXTURE_DIR))
    emitted = {
        f.rule_id
        for f in findings
        if isinstance(f.rule_id, str) and f.rule_id
    }
    assert emitted <= EXPECTED_RULE_IDS


# --- 17-19. Accounting counts files, not detectors ------------------------


def test_one_file_evaluated_by_multiple_detectors_counts_once(tmp_path):
    _multi_asset_pem(tmp_path)
    stats: dict[str, int] = {}
    df = scan_crypto_inventory(str(tmp_path), stats=stats)

    # Three detectors each produced evidence for the one file...
    assert set(df["Asset Type"]) == {
        "PEM Certificate",
        "PEM Private Key",
        "OpenSSH Public Key",
    }
    # ...and the inspected-file count is still exactly one.
    assert stats["files_inspected"] == 1


def test_malformed_findings_do_not_inflate_the_inspected_file_count(tmp_path):
    (tmp_path / "malformed_cert.pem").write_bytes(
        (FIXTURE_DIR / "malformed_cert.pem").read_bytes()
    )
    stats: dict[str, int] = {}
    df = scan_crypto_inventory(str(tmp_path), stats=stats)

    assert list(df["Asset Type"]) == ["Malformed PEM Certificate"]
    assert stats["files_inspected"] == 1


def test_root_detector_does_not_count_directories_as_crypto_files(tmp_path):
    root = _gocryptfs_root(tmp_path)
    (root / "ciphertext").write_bytes(os.urandom(32))
    stats: dict[str, int] = {}
    df = scan_crypto_inventory(str(tmp_path), stats=stats)

    # One finding for the validated root, not one per contained file...
    assert list(df["Asset Type"]) == ["Encrypted Filesystem"]
    assert list(df["Location"]) == [str(root)]
    # ...and the count is the three regular files, with no unit for the
    # directory the root detector classified.
    assert stats["files_inspected"] == 3


def test_one_file_is_read_once_no_matter_how_many_detectors_inspect_it(
    tmp_path, monkeypatch
):
    target = _multi_asset_pem(tmp_path)
    reads: list[str] = []
    real_read_bytes = Path.read_bytes

    def counting_read_bytes(self):
        reads.append(str(self))
        return real_read_bytes(self)

    monkeypatch.setattr(Path, "read_bytes", counting_read_bytes)
    df = scan_crypto_inventory(str(tmp_path))

    assert len(df) == 3
    # Not detectors x full-file-read: the shared context is read once and every
    # detector's view (leading bytes, full bytes, text) comes from that read.
    assert reads == [str(target)]


def test_no_detector_performs_independent_traversal(tmp_path, monkeypatch):
    _multi_asset_pem(tmp_path)
    root = _gocryptfs_root(tmp_path)
    (root / "ciphertext").write_bytes(os.urandom(32))

    walk_calls = []
    real_walk = os.walk

    def counting_walk(path, *args, **kwargs):
        walk_calls.append(str(path))
        return real_walk(path, *args, **kwargs)

    monkeypatch.setattr(crypto_inventory.os, "walk", counting_walk)
    scan_crypto_inventory(str(tmp_path))

    # Exactly the scanner's own walk of the requested target. A detector that
    # recursed on its own -- including the root detector, which sees a candidate
    # root rather than a directory to list -- would show up as a second call.
    assert walk_calls == [str(tmp_path)]


def test_root_context_sibling_access_cannot_become_a_traversal_primitive(tmp_path):
    root = _gocryptfs_root(tmp_path)
    context = RootContext(root_path=root, marker=FileContext(root / "gocryptfs.conf"))

    assert context.has_regular_sibling("gocryptfs.diriv") is True
    assert context.has_regular_sibling("absent.diriv") is False
    for rejected in ("../gocryptfs.diriv", "sub/gocryptfs.diriv", "", ".", ".."):
        with pytest.raises(ValueError):
            context.has_regular_sibling(rejected)


# --- 20-22. Error isolation ------------------------------------------------


_LEAKY_MESSAGE = "SECRET-PAYLOAD-0xdeadbeef"


def _boom_registry():
    def boom(context):
        raise RuntimeError(_LEAKY_MESSAGE)

    return build_registry(
        [
            FileDetector(
                detector_id="test:boom",
                priority=5,
                candidate=lambda context: context.name == "boom.bin",
                detect=boom,
                evidence="",
                confidence="Low",
            ),
            *CRYPTO_DETECTORS,
        ]
    )


def _tree_with_boom_after_a_finding(tmp_path: Path) -> Path:
    # os.walk yields the top directory's files before descending, so the
    # certificate is inspected before the failing file -- deterministically,
    # without depending on within-directory ordering.
    (tmp_path / "rsa_cert.pem").write_bytes((FIXTURE_DIR / "rsa_cert.pem").read_bytes())
    later = tmp_path / "later"
    later.mkdir()
    (later / "boom.bin").write_bytes(b"boom")
    return tmp_path


def test_detector_exception_becomes_a_scanner_error_with_partial_findings(
    tmp_path, monkeypatch
):
    _tree_with_boom_after_a_finding(tmp_path)
    monkeypatch.setattr(crypto_inventory, "CRYPTO_DETECTORS", _boom_registry())

    with pytest.raises(LocalScanError) as exc_info:
        scan_crypto_inventory_findings(str(tmp_path))

    message = str(exc_info.value)
    # Attributed to the detector and the asset...
    assert "test:boom" in message
    assert str(tmp_path / "later" / "boom.bin") in message
    assert "RuntimeError" in message
    # ...without the exception's own message, which could carry parser payloads
    # or file content.
    assert _LEAKY_MESSAGE not in message

    # Evidence collected before the failure is preserved, exactly as it is for a
    # traversal failure.
    partial = list(exc_info.value.partial_findings)
    assert [f.asset_type for f in partial] == ["PEM Certificate"]


def test_detector_exception_is_not_silently_a_clean_non_match(tmp_path, monkeypatch):
    _tree_with_boom_after_a_finding(tmp_path)
    monkeypatch.setattr(crypto_inventory, "CRYPTO_DETECTORS", _boom_registry())

    # A caller with nowhere to surface the failure gets the exception rather
    # than a truncated result that looks clean.
    with pytest.raises(DetectorExecutionError):
        scan_crypto_inventory(str(tmp_path))

    # With the error channel supplied, the scan stops, reports, and keeps what
    # it already had.
    detector_errors: list[str] = []
    stats: dict[str, int] = {}
    df = scan_crypto_inventory(
        str(tmp_path), stats=stats, detector_errors=detector_errors
    )
    assert len(detector_errors) == 1
    assert list(df["Asset Type"]) == ["PEM Certificate"]
    # The failing file was inspected; nothing past it is claimed as inspected.
    assert stats["files_inspected"] == 2


def _boom_after_earlier_detectors_registry():
    """The registry plus a detector that fails *after* the non-terminal text
    detectors have already produced evidence for the same file."""

    def boom(context):
        raise RuntimeError(_LEAKY_MESSAGE)

    return build_registry(
        [
            *CRYPTO_DETECTORS,
            FileDetector(
                detector_id="test:boom_late",
                priority=100,
                candidate=lambda context: context.suffix == ".pem",
                detect=boom,
                evidence="",
                confidence="Low",
            ),
        ]
    )


def test_detector_exception_preserves_findings_from_the_same_asset(
    tmp_path, monkeypatch
):
    # One file three non-terminal detectors report on, then a fourth detector on
    # that same file raises: the three findings must survive. They only exist in
    # the abandoned per-file dispatch, so losing them would let one detector's
    # defect discard another detector's valid evidence.
    _multi_asset_pem(tmp_path)
    monkeypatch.setattr(
        crypto_inventory, "CRYPTO_DETECTORS", _boom_after_earlier_detectors_registry()
    )

    with pytest.raises(LocalScanError) as exc_info:
        scan_crypto_inventory_findings(str(tmp_path))

    message = str(exc_info.value)
    assert "test:boom_late" in message
    assert _LEAKY_MESSAGE not in message

    partial = list(exc_info.value.partial_findings)
    assert [f.asset_type for f in partial] == [
        "PEM Certificate",
        "PEM Private Key",
        "OpenSSH Public Key",
    ]


def test_same_asset_partial_findings_reach_the_dataframe(tmp_path, monkeypatch):
    _multi_asset_pem(tmp_path)
    monkeypatch.setattr(
        crypto_inventory, "CRYPTO_DETECTORS", _boom_after_earlier_detectors_registry()
    )

    detector_errors: list[str] = []
    stats: dict[str, int] = {}
    df = scan_crypto_inventory(
        str(tmp_path), stats=stats, detector_errors=detector_errors
    )

    assert len(detector_errors) == 1
    assert list(df["Asset Type"]) == [
        "PEM Certificate",
        "PEM Private Key",
        "OpenSSH Public Key",
    ]
    # The failing file was still inspected exactly once.
    assert stats["files_inspected"] == 1


def test_detector_error_carries_the_same_asset_findings_it_interrupted(tmp_path):
    target = _multi_asset_pem(tmp_path)
    registry = _boom_after_earlier_detectors_registry()
    context = FileContext(target)
    assert context.readable() is True

    with pytest.raises(DetectorExecutionError) as exc_info:
        run_detectors(context, registry)

    assert [f.asset_type for f in exc_info.value.partial_findings] == [
        "PEM Certificate",
        "PEM Private Key",
        "OpenSSH Public Key",
    ]


def test_detector_returning_a_non_result_is_a_detector_error(tmp_path):
    (tmp_path / "anything.txt").write_text("x")
    broken = build_registry(
        [
            FileDetector(
                detector_id="test:wrong_type",
                priority=1,
                candidate=lambda context: True,
                detect=lambda context: [CryptoInventoryFinding("X", "y")],
                evidence="",
                confidence="Low",
            )
        ]
    )
    with pytest.raises(DetectorExecutionError, match="test:wrong_type"):
        crypto_inventory._scan_file(tmp_path / "anything.txt", broken)


def test_unreadable_file_produces_no_finding_and_no_evidence(tmp_path, monkeypatch):
    (tmp_path / "rsa_cert.pem").write_bytes((FIXTURE_DIR / "rsa_cert.pem").read_bytes())
    (tmp_path / "unreadable.pem").write_bytes(
        (FIXTURE_DIR / "ecc_cert.pem").read_bytes()
    )
    real_read_bytes = Path.read_bytes

    def failing_read_bytes(self):
        if self.name == "unreadable.pem":
            raise PermissionError(13, "Permission denied", str(self))
        return real_read_bytes(self)

    monkeypatch.setattr(Path, "read_bytes", failing_read_bytes)
    stats: dict[str, int] = {}
    df = scan_crypto_inventory(str(tmp_path), stats=stats)

    names = {Path(location).name for location in df["Location"]}
    assert names == {"rsa_cert.pem"}
    # Visited and opened, so it counts -- an unreadable file is a coverage fact,
    # not a reason to under-report the inspected count.
    assert stats["files_inspected"] == 2


def test_scan_survives_a_file_that_vanishes_mid_scan(tmp_path, monkeypatch):
    (tmp_path / "rsa_cert.pem").write_bytes((FIXTURE_DIR / "rsa_cert.pem").read_bytes())
    (tmp_path / "vanishing.pem").write_bytes(
        (FIXTURE_DIR / "ecc_cert.pem").read_bytes()
    )
    real_read_bytes = Path.read_bytes

    def vanishing_read_bytes(self):
        if self.name == "vanishing.pem":
            raise FileNotFoundError(2, "No such file or directory", str(self))
        return real_read_bytes(self)

    monkeypatch.setattr(Path, "read_bytes", vanishing_read_bytes)
    df = scan_crypto_inventory(str(tmp_path))

    assert {Path(location).name for location in df["Location"]} == {"rsa_cert.pem"}


# --- 23-24. Safe metadata allowlisting ------------------------------------


def test_every_declared_metadata_key_is_in_the_safe_allowlist():
    for detector in CRYPTO_DETECTORS:
        assert set(detector.metadata_keys) <= SAFE_METADATA_KEYS


def test_build_registry_rejects_metadata_outside_the_safe_allowlist():
    with pytest.raises(ValueError, match="outside the safe"):
        build_registry(
            [
                FileDetector(
                    detector_id="test:unsafe",
                    priority=1,
                    candidate=lambda context: False,
                    detect=lambda context: DetectionResult.no_match(),
                    evidence="",
                    confidence="Low",
                    metadata_keys=frozenset({"Passphrase"}),
                )
            ]
        )


def test_enforce_metadata_allowlist_omits_undeclared_fields():
    finding = CryptoInventoryFinding(
        asset_type="Encrypted File",
        location="/tmp/example",
        algorithm="AES-256",
        issuer="CN=should-not-be-here",
        format="should-not-be-here",
        config_version=2,
    )
    enforce_metadata_allowlist(finding, frozenset({"Algorithm"}))

    record = finding.to_record()
    assert record["Algorithm"] == "AES-256"
    assert record["Issuer"] is None
    assert record["Format"] is None
    assert record["Config Version"] is None


def test_undeclared_metadata_never_reaches_normalized_findings_or_reports(tmp_path):
    (tmp_path / "leaky.bin").write_bytes(b"anything")

    def leaky(context):
        # A detector that populates metadata it never declared -- the shape a
        # future parser regression would take.
        return DetectionResult.match(
            [
                CryptoInventoryFinding(
                    asset_type="Encrypted File",
                    location=context.location,
                    algorithm="AES-256",
                    issuer="CN=ZZ-NOT-ALLOWLISTED",
                    subject="CN=ZZ-NOT-ALLOWLISTED",
                    fingerprint="deadbeef",
                    format="ZZ-NOT-ALLOWLISTED",
                    config_version=99,
                    mode="ZZ-NOT-ALLOWLISTED",
                    evidence="Observed test evidence.",
                    confidence="High",
                )
            ],
            terminal=True,
        )

    registry = build_registry(
        [
            FileDetector(
                detector_id="test:leaky",
                priority=1,
                candidate=lambda context: context.name == "leaky.bin",
                detect=leaky,
                evidence="Observed test evidence.",
                confidence="High",
                metadata_keys=frozenset({"Algorithm"}),
            )
        ]
    )
    findings = crypto_inventory._scan_file(tmp_path / "leaky.bin", registry)
    normalized = normalize_crypto_inventory_df(
        crypto_inventory.pd.DataFrame([f.to_record() for f in findings])
    )

    assert len(normalized) == 1
    metadata = normalized[0].technical_metadata
    assert metadata["Algorithm"] == "AES-256"
    for undeclared in ("Issuer", "Subject", "Fingerprint", "Format", "Config Version", "Mode"):
        assert metadata[undeclared] is None
    # identity_key is derived from Fingerprint, which was never declared.
    assert normalized[0].identity_key is None
    assert "ZZ-NOT-ALLOWLISTED" not in json.dumps(
        [f.to_dict() for f in normalized], default=str
    )


def test_metadata_allowlist_preserves_currently_approved_metadata(tmp_path):
    root = _gocryptfs_root(tmp_path)
    (tmp_path / "rsa_cert.pem").write_bytes((FIXTURE_DIR / "rsa_cert.pem").read_bytes())
    findings = scan_crypto_inventory_findings(str(tmp_path))
    by_type = {f.asset_type: f for f in findings}

    filesystem = by_type["Encrypted Filesystem"].technical_metadata
    assert filesystem["Format"] == "gocryptfs"
    assert filesystem["Config Version"] == 2
    assert filesystem["Mode"] == "forward"
    assert by_type["Encrypted Filesystem"].location == str(root)

    certificate = by_type["PEM Certificate"].technical_metadata
    assert certificate["Algorithm"] == "RSA"
    assert certificate["Key Size"] == 2048
    assert certificate["Signature Algorithm"] == "sha256"
    assert certificate["Issuer"]
    assert certificate["Subject"]
    assert certificate["Expiration"]
    assert certificate["Fingerprint"]


# --- Framework primitives ------------------------------------------------


def test_detection_result_models_the_four_outcomes():
    no_match = DetectionResult.no_match()
    assert (no_match.matched, no_match.terminal, no_match.findings) == (False, False, ())

    coexisting = DetectionResult.match(["a"])
    assert (coexisting.matched, coexisting.terminal) == (True, False)

    owning = DetectionResult.match(["a"], terminal=True)
    assert (owning.matched, owning.terminal) == (True, True)

    claim = DetectionResult.claim()
    assert (claim.matched, claim.terminal, claim.findings) == (True, True, ())


def test_file_context_views_come_from_one_read(tmp_path):
    target = tmp_path / "sample.pem"
    target.write_bytes(b"-----BEGIN CERTIFICATE-----\nabc\n")
    context = FileContext(target)

    assert context.readable() is True
    assert context.leading_bytes(11) == b"-----BEGIN "
    assert context.leading_bytes(10_000) == target.read_bytes()
    assert context.text is not None
    assert context.suffix == ".pem"
    assert context.name == "sample.pem"
    assert context.location == str(target)


def test_file_context_text_view_is_none_for_binary_content(tmp_path):
    target = tmp_path / "binary.bin"
    target.write_bytes(b"\x00\x01\x02\x03")
    context = FileContext(target)

    assert context.readable() is True
    assert context.text is None
    # Cached, including the None: a binary file is not decoded again per
    # detector.
    assert context.text is None


def _dispatch_probe_registry(first_terminal: bool, first_matches: bool):
    """Two file detectors: one declared terminal or not, and a later one that
    records whether it got to run."""
    ran: list[str] = []

    def first_detect(context):
        if not first_matches:
            return DetectionResult.no_match()
        return DetectionResult.match(
            [CryptoInventoryFinding("First Asset", context.location)]
        )

    def second_detect(context):
        ran.append(context.location)
        return DetectionResult.match(
            [CryptoInventoryFinding("Second Asset", context.location)]
        )

    registry = build_registry(
        [
            FileDetector(
                detector_id="test:first",
                priority=1,
                candidate=lambda context: True,
                detect=first_detect,
                evidence="",
                confidence="Low",
                terminal=first_terminal,
            ),
            FileDetector(
                detector_id="test:second",
                priority=2,
                candidate=lambda context: True,
                detect=second_detect,
                evidence="",
                confidence="Low",
            ),
        ]
    )
    return registry, ran


def _run_probe(tmp_path: Path, registry) -> list[str]:
    target = tmp_path / "probe.bin"
    target.write_bytes(b"probe")
    context = FileContext(target)
    assert context.readable() is True
    return [f.asset_type for f in run_detectors(context, registry)]


def test_declared_terminal_detector_stops_dispatch_on_match(tmp_path):
    registry, ran = _dispatch_probe_registry(first_terminal=True, first_matches=True)
    assert _run_probe(tmp_path, registry) == ["First Asset"]
    assert ran == []


def test_declared_non_terminal_detector_lets_later_detectors_run(tmp_path):
    registry, ran = _dispatch_probe_registry(first_terminal=False, first_matches=True)
    assert _run_probe(tmp_path, registry) == ["First Asset", "Second Asset"]
    assert len(ran) == 1


def test_declared_terminal_detector_that_did_not_match_does_not_stop_dispatch(tmp_path):
    registry, ran = _dispatch_probe_registry(first_terminal=True, first_matches=False)
    assert _run_probe(tmp_path, registry) == ["Second Asset"]
    assert len(ran) == 1


def test_owning_root_detector_stops_dispatch_even_on_no_match(tmp_path):
    target = tmp_path / "marker.conf"
    target.write_bytes(b"not a valid root")
    calls: list[str] = []

    def later_detect(context):
        calls.append(context.location)
        return DetectionResult.match(
            [CryptoInventoryFinding("Should Not Appear", context.location)]
        )

    registry = build_registry(
        [
            RootDetector(
                detector_id="test:root",
                priority=1,
                marker_filename="marker.conf",
                detect=lambda context: DetectionResult.no_match(),
                evidence="",
                confidence="High",
                owns_marker=True,
            ),
            FileDetector(
                detector_id="test:later",
                priority=2,
                candidate=lambda context: True,
                detect=later_detect,
                evidence="",
                confidence="Low",
            ),
        ]
    )
    context = FileContext(target)
    assert context.readable() is True
    assert run_detectors(context, registry) == []
    assert calls == []


def test_non_marker_file_skips_root_detectors(tmp_path):
    target = tmp_path / "other.conf"
    target.write_bytes(b"{}")
    registry = build_registry(
        [
            RootDetector(
                detector_id="test:root",
                priority=1,
                marker_filename="marker.conf",
                detect=lambda context: pytest.fail("root detector must not run"),
                evidence="",
                confidence="High",
            ),
            FileDetector(
                detector_id="test:file",
                priority=2,
                candidate=lambda context: True,
                detect=lambda context: DetectionResult.match(
                    [CryptoInventoryFinding("Test Asset", context.location)]
                ),
                evidence="",
                confidence="Low",
            ),
        ]
    )
    context = FileContext(target)
    assert context.readable() is True
    findings = run_detectors(context, registry)
    assert [f.asset_type for f in findings] == ["Test Asset"]


# --- 30-34. End-to-end behavior preservation ------------------------------


def test_cli_crypto_scan_is_unchanged_end_to_end(tmp_path, capsys):
    _multi_asset_pem(tmp_path)
    _gocryptfs_root(tmp_path)

    exit_code = harvestguard.main(
        ["scan", str(tmp_path), "--type", "crypto", "--json", "--quiet"]
    )
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    # A bare array of normalized findings, no envelope.
    assert isinstance(payload, list)
    assert {record["asset_type"] for record in payload} == {
        "PEM Certificate",
        "PEM Private Key",
        "OpenSSH Public Key",
        "Encrypted Filesystem",
    }
    assert {record["source_type"] for record in payload} == {"crypto_inventory"}


def test_dataframe_columns_used_by_existing_callers_are_preserved(tmp_path):
    _multi_asset_pem(tmp_path)
    df = scan_crypto_inventory(str(tmp_path))

    assert list(df.columns) == [
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


def test_finding_ids_remain_stable_for_representative_fixtures():
    # finding_id is derived from the finding's stable identity fields, so it is
    # a compact regression signal that the refactor changed no asset type,
    # location, scanner identity, rule id, or identity key.
    findings = scan_crypto_inventory_findings(str(FIXTURE_DIR), scan_id="fixed-scan-id")
    ids = {f.asset_type: f.finding_id for f in findings}
    repeat = scan_crypto_inventory_findings(str(FIXTURE_DIR), scan_id="fixed-scan-id")

    assert ids == {f.asset_type: f.finding_id for f in repeat}
    assert all(finding_id for finding_id in ids.values())
