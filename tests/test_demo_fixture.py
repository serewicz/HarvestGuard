"""Tests for demo/sample_target/ (HG-006, GitHub issues #18 and #115).

These exist specifically because earlier versions of
demo/sample_target/sensitive/leaked_config.env contained, in turn, a
syntactically valid-looking Slack token and then a valid-looking AWS access
key, and GitHub push protection correctly rejected the push both times. The
fix was to make every fixture value unmistakably fake rather than to weaken
push protection, HarvestGuard's classifiers, or any other security control
-- these tests guard against that regressing.

Issue #115 added two synthetic cryptographic fixtures under
demo/sample_target/crypto/ and a manifest (demo/sample_target/README.md).
The tests at the bottom of this file guard the properties that make that
corpus safe to publish: every file is documented, every fixture is labeled
synthetic, no private key material in it is usable, and none of it reaches
JSON or Markdown output.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from classifier.patterns import AWS_ACCESS_KEY_RE, GITHUB_TOKEN_RE, SLACK_TOKEN_RE
from classifier.scanner import (
    classify_text,
    scan_filesystem_for_sensitive_data,
    scan_filesystem_for_sensitive_data_findings,
)
from reports import findings_json, format_markdown_report, make_report_context

DEMO_TARGET = Path(__file__).parent.parent / "demo" / "sample_target"
LEAKED_CONFIG = DEMO_TARGET / "sensitive" / "leaked_config.env"
DEMO_MANIFEST = DEMO_TARGET / "README.md"
DEMO_CERTIFICATE = DEMO_TARGET / "crypto" / "demo_tls_certificate.pem"
DEMO_ENCRYPTED_KEY = DEMO_TARGET / "crypto" / "demo_encrypted_private_key.pem"

# The passphrase for DEMO_ENCRYPTED_KEY, published in the manifest on purpose
# (the key protects nothing). It must still never appear in scan output --
# HarvestGuard reports that a key is encrypted, never how to open it.
DEMO_KEY_PASSPHRASE = "harvestguard-demo"

# The exact fake values written into the fixture. Used below to prove they
# never appear in classifier/report output, which must report categories
# and counts only -- never the matched values themselves.
FIXTURE_SECRET_VALUES = ("FAKE-DEMO-PASSWORD-VALUE-0000000000",)


def test_demo_target_exists_and_is_reachable():
    assert DEMO_TARGET.is_dir()
    assert LEAKED_CONFIG.is_file()
    assert DEMO_MANIFEST.is_file()
    assert DEMO_CERTIFICATE.is_file()
    assert DEMO_ENCRYPTED_KEY.is_file()


def test_demo_target_produces_expected_sensitive_data_categories():
    df = scan_filesystem_for_sensitive_data(str(DEMO_TARGET))

    assert len(df) == 1
    row = df.iloc[0]
    assert row["Location"].endswith("leaked_config.env")

    categories = {c.strip() for c in row["Categories"].split(",")}
    assert categories == {"Email", "Private Key", "Generic Secret"}
    # Deliberately absent -- see the fixture's header comment. Each of these
    # three is a real, service-specific credential shape that a value
    # matching it would also trip GitHub push protection on, same as the
    # Slack token and AWS access key incidents this fixture's design
    # addresses.
    assert "Slack Token" not in categories
    assert "GitHub Token" not in categories
    assert "AWS Access Key" not in categories


def test_demo_fixture_values_do_not_match_service_specific_credential_shapes():
    text = LEAKED_CONFIG.read_text()

    assert SLACK_TOKEN_RE.search(text) is None
    assert GITHUB_TOKEN_RE.search(text) is None
    assert AWS_ACCESS_KEY_RE.search(text) is None

    # classify_text() must agree with the raw regex checks above.
    counts = classify_text(text)
    assert "Slack Token" not in counts
    assert "GitHub Token" not in counts
    assert "AWS Access Key" not in counts


def test_demo_fixture_is_clearly_marked_as_fake():
    text = LEAKED_CONFIG.read_text()
    lowered = text.lower()

    assert "fake" in lowered
    assert "do not" in lowered  # "do not use" / "do not copy" guidance present
    # The specific incident this fixture's design addresses should be
    # documented in the file itself, not just in a commit message.
    assert "push protection" in lowered


def test_demo_findings_do_not_expose_raw_secret_values():
    findings = scan_filesystem_for_sensitive_data_findings(str(DEMO_TARGET))
    assert len(findings) == 1

    payload = findings[0].to_dict()
    serialized = str(payload)

    for secret_value in FIXTURE_SECRET_VALUES:
        assert secret_value not in serialized
    # Categories/counts are fine to expose; the underlying matched text
    # (e.g. the literal PEM body marker) must not appear.
    assert "NOT-A-REAL-KEY-THIS-IS-FAKE-DEMO-CONTENT-ONLY-DO-NOT-USE" not in serialized


def test_demo_json_report_does_not_expose_raw_secret_values():
    findings = scan_filesystem_for_sensitive_data_findings(str(DEMO_TARGET))

    report = findings_json(findings)

    for secret_value in FIXTURE_SECRET_VALUES:
        assert secret_value not in report


def test_demo_markdown_report_does_not_expose_raw_secret_values():
    findings = scan_filesystem_for_sensitive_data_findings(str(DEMO_TARGET))
    context = make_report_context(target_path=str(DEMO_TARGET))

    report = format_markdown_report(findings, context)

    for secret_value in FIXTURE_SECRET_VALUES:
        assert secret_value not in report
    assert "Email" in report
    assert "Generic Secret" in report


# --- Filesystem/encryption evidence, crypto evidence, confidence, and report
# behavior beyond sensitive-data categories (HG-006 closure requirement) ---
#
# Encryption status for this fixture falls back to volume-level status,
# which is detected differently per platform (FileVault on macOS,
# lsblk/similar on Linux) and is therefore not deterministic across
# environments -- see scanner/filesystem.py's `_detect_volume_encryption`
# and docs/CLI.md's demo walkthrough "What varies by host" section. These
# tests assert structure and confidence-field presence, never the exact
# encryption value or confidence level, so they hold on every supported
# platform.


def test_demo_target_produces_filesystem_encryption_evidence_with_confidence():
    from scanner.filesystem import scan_filesystem_findings

    findings = scan_filesystem_findings(str(DEMO_TARGET))

    # Every file in the corpus is an ordinary file (no file-level
    # encrypted-format signature, no file-specific failure) -- an encrypted
    # PKCS#8 key is a cryptographic asset, not an encrypted container -- so
    # all four are represented by their mount's aggregate context record
    # rather than per-file records. See tests/test_filesystem_aggregate_context.py.
    assert len(findings) == 1
    finding = findings[0]
    assert finding.asset_type == "volume"
    assert finding.source_type == "local_filesystem"
    assert finding.evidence.startswith("Volume-level encryption status")
    assert finding.technical_metadata["Files Represented By This Context"] == len(
        _corpus_files()
    )

    # Confidence is a real evidence-quality field, not a platform-specific
    # value -- it must always be present and be one of the three defined
    # levels, with a non-empty rationale explaining why.
    assert finding.confidence in {"High", "Medium", "Low"}
    assert finding.confidence_rationale
    assert isinstance(finding.confidence_rationale, str)

    # Rule ID always identifies which volume-status value was determined
    # (or Unknown), even though the value itself is platform-dependent.
    assert finding.rule_id.startswith("volume_status:")
    assert isinstance(finding.repeatable, bool)


def test_demo_target_produces_deterministic_crypto_inventory_evidence():
    from scanner.crypto_inventory import scan_crypto_inventory_findings

    findings = scan_crypto_inventory_findings(str(DEMO_TARGET))

    by_asset_type = {finding.asset_type: finding for finding in findings}
    assert set(by_asset_type) == {
        "Malformed PEM Private Key",
        "PEM Certificate",
        "Encrypted PKCS#8 Private Key",
    }
    assert len(findings) == 3

    # The .env fixture's PEM header is real enough to be detected as a PEM
    # block; its body is deliberately fake, so parsing correctly fails.
    # This outcome depends only on the fixture's fixed content, not on
    # host platform, so it is safe to pin exactly.
    malformed = by_asset_type["Malformed PEM Private Key"]
    assert malformed.location.endswith("leaked_config.env")
    assert malformed.confidence == "Low"
    assert malformed.errors  # a parse-failure reason is recorded
    # technical_metadata stays unset -- parsing never succeeded, so no
    # algorithm/key-size/fingerprint data was ever extracted.
    assert malformed.technical_metadata.get("Fingerprint") is None


def test_demo_corpus_demonstrates_two_distinct_crypto_inventory_categories():
    # Issue #115: the corpus must show at least two distinct, currently
    # supported cryptographic-inventory categories, both from real parsed
    # structure rather than a filename-only claim.
    from scanner.crypto_inventory import scan_crypto_inventory_findings

    findings = scan_crypto_inventory_findings(str(DEMO_TARGET))
    by_asset_type = {finding.asset_type: finding for finding in findings}

    certificate = by_asset_type["PEM Certificate"]
    assert certificate.location.endswith("demo_tls_certificate.pem")
    assert certificate.confidence == "High"
    assert not certificate.errors
    # Parsed structure, not the file name: algorithm, key size and subject
    # come out of the certificate itself.
    assert certificate.technical_metadata["Algorithm"] == "RSA"
    assert certificate.technical_metadata["Key Size"] == 2048
    assert "demo.harvestguard.invalid" in certificate.technical_metadata["Subject"]

    encrypted_key = by_asset_type["Encrypted PKCS#8 Private Key"]
    assert encrypted_key.location.endswith("demo_encrypted_private_key.pem")
    assert encrypted_key.confidence == "High"
    assert not encrypted_key.errors
    assert encrypted_key.rule_id == "private_key:pkcs8_encrypted"
    assert encrypted_key.technical_metadata["Format"] == "PKCS#8"


def test_demo_findings_json_output_contains_expected_normalized_evidence():
    from finding_adapters import normalize_crypto_inventory_df
    from reports import findings_json
    from scanner.crypto_inventory import scan_crypto_inventory
    from scanner.filesystem import scan_filesystem_findings

    fs_findings = scan_filesystem_findings(str(DEMO_TARGET))
    crypto_findings = normalize_crypto_inventory_df(scan_crypto_inventory(str(DEMO_TARGET)))
    all_findings = fs_findings + crypto_findings

    report = findings_json(all_findings)
    payload = json.loads(report)

    assert len(payload) == 4
    source_types = {record["source_type"] for record in payload}
    assert source_types == {"local_filesystem", "crypto_inventory"}

    fs_record = next(r for r in payload if r["source_type"] == "local_filesystem")
    assert fs_record["confidence"] in {"High", "Medium", "Low"}
    # leaked_config.env is an ordinary file, represented by the mount's
    # aggregate context record rather than a per-file record.
    assert fs_record["asset_type"] == "volume"
    assert fs_record["evidence"].startswith("Volume-level encryption status")

    crypto_records = {
        r["asset_type"]: r for r in payload if r["source_type"] == "crypto_inventory"
    }
    assert set(crypto_records) == {
        "Malformed PEM Private Key",
        "PEM Certificate",
        "Encrypted PKCS#8 Private Key",
    }
    malformed_record = crypto_records["Malformed PEM Private Key"]
    assert malformed_record["confidence"] == "Low"
    assert malformed_record["errors"]
    assert crypto_records["PEM Certificate"]["confidence"] == "High"
    assert crypto_records["Encrypted PKCS#8 Private Key"]["confidence"] == "High"

    # JSON output must remain valid and never leak the fixture's fake
    # secret text, mirroring the sensitive-data report tests above.
    for secret_value in FIXTURE_SECRET_VALUES:
        assert secret_value not in report
    assert "NOT-A-REAL-KEY-THIS-IS-FAKE-DEMO-CONTENT-ONLY-DO-NOT-USE" not in report


def test_demo_target_sensitive_data_category_string_is_stable():
    # The exact category set and join order, not just membership -- pins
    # the documented CLI.md walkthrough output verbatim.
    df = scan_filesystem_for_sensitive_data(str(DEMO_TARGET))
    assert df.iloc[0]["Categories"] == "Email, Generic Secret, Private Key"


# --- Corpus safety and provenance (GitHub issue #115) ---------------------
#
# The corpus is published material: anyone who clones the repository gets it,
# and a fixture that escapes this directory must still be harmless. These
# tests prove the properties that make that true -- documented provenance for
# every file, self-identifying synthetic labels, no usable private key, and
# nothing bulky or unbounded creeping in.


def test_every_corpus_file_is_documented_in_the_manifest():
    manifest = DEMO_MANIFEST.read_text()

    for path in _corpus_files():
        relative = path.relative_to(DEMO_TARGET).as_posix()
        assert relative in manifest, f"{relative} is not documented in the manifest"


def test_manifest_records_provenance_and_expected_findings():
    manifest = DEMO_MANIFEST.read_text()

    assert "Synthetic provenance" in manifest
    assert "Expected high-level finding" in manifest
    # Generation is attributed to the tool that produced the fixtures, not
    # left as "obtained somewhere".
    assert "openssl req -x509" in manifest
    assert "openssl genpkey" in manifest
    # Claims boundary: the corpus is a sample, not coverage or a conclusion.
    # Compared on collapsed whitespace so prose can be rewrapped freely.
    prose = " ".join(manifest.lower().split())
    assert "not proof of absence" in prose
    assert "not complete cryptographic coverage" in prose


def test_manifest_hashes_match_the_committed_fixture_bytes():
    # Pinned SHA-256 values are the manifest's provenance claim. If a fixture
    # is ever regenerated or edited, the manifest has to be updated with it.
    manifest = DEMO_MANIFEST.read_text()

    for path in (DEMO_CERTIFICATE, DEMO_ENCRYPTED_KEY):
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        assert digest in manifest, f"manifest does not record {path.name}'s SHA-256"


def test_crypto_fixtures_label_themselves_as_synthetic_demo_material():
    for path in (DEMO_CERTIFICATE, DEMO_ENCRYPTED_KEY):
        header = path.read_text()
        assert "SYNTHETIC, NON-OPERATIONAL DEMO MATERIAL" in header
        assert "Do not" in header or "do not" in header


def test_corpus_contains_no_usable_private_key_material():
    # Every private-key-shaped block in the corpus must fail a passwordless
    # load: the .env fixture's body is fake text, and the PKCS#8 fixture is
    # passphrase-encrypted. Nothing here can be picked up and used.
    from cryptography.hazmat.primitives import serialization

    checked = 0
    for path in _corpus_files():
        text = path.read_text(errors="ignore")
        for block in _pem_blocks(text):
            if "PRIVATE KEY" not in block.splitlines()[0]:
                continue
            checked += 1
            with pytest.raises((ValueError, TypeError)):
                serialization.load_pem_private_key(block.encode(), password=None)

    assert checked == 2  # the fake .env block and the encrypted PKCS#8 key


def test_demo_certificate_is_self_signed_and_non_operational():
    from cryptography import x509

    block = _pem_blocks(DEMO_CERTIFICATE.read_text())[0]
    certificate = x509.load_pem_x509_certificate(block.encode())

    # Self-signed and bound to the reserved-for-testing .invalid TLD, so it
    # is not trusted by anything and names no real host.
    assert certificate.issuer == certificate.subject
    common_name = certificate.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[
        0
    ].value
    assert common_name.endswith(".invalid")
    # Still valid, so the demo keeps showing a parsed certificate rather than
    # an expired one -- but the assertion is about the fixture's own dates,
    # not about any host state.
    assert certificate.not_valid_after_utc > datetime.now(timezone.utc)


def test_demo_reports_never_expose_fixture_key_material_or_passphrase():
    from finding_adapters import normalize_crypto_inventory_df
    from scanner.crypto_inventory import scan_crypto_inventory
    from scanner.filesystem import scan_filesystem_findings

    findings = (
        scan_filesystem_findings(str(DEMO_TARGET))
        + normalize_crypto_inventory_df(scan_crypto_inventory(str(DEMO_TARGET)))
        + scan_filesystem_for_sensitive_data_findings(str(DEMO_TARGET))
    )
    json_report = findings_json(findings)
    markdown_report = format_markdown_report(
        findings, make_report_context(target_path=str(DEMO_TARGET))
    )

    for path in (DEMO_CERTIFICATE, DEMO_ENCRYPTED_KEY):
        for block in _pem_blocks(path.read_text()):
            for line in block.splitlines():
                if line.startswith("-----"):
                    continue
                assert line not in json_report
                assert line not in markdown_report

    assert DEMO_KEY_PASSPHRASE not in json_report
    assert DEMO_KEY_PASSPHRASE not in markdown_report


def test_corpus_stays_small_and_bounded():
    files = _corpus_files()

    assert 0 < len(files) <= 10
    for path in files:
        assert path.stat().st_size <= 16 * 1024, f"{path.name} is too large for a demo"


def test_no_corpus_file_matches_a_service_specific_credential_shape():
    # The whole corpus, not just leaked_config.env: nothing added here may
    # carry a value shaped like a live Slack, GitHub, or AWS credential.
    for path in _corpus_files():
        text = path.read_text(errors="ignore")

        assert SLACK_TOKEN_RE.search(text) is None, path.name
        assert GITHUB_TOKEN_RE.search(text) is None, path.name
        assert AWS_ACCESS_KEY_RE.search(text) is None, path.name


def _corpus_files() -> list[Path]:
    return sorted(path for path in DEMO_TARGET.rglob("*") if path.is_file())


def _pem_blocks(text: str) -> list[str]:
    blocks, current = [], None
    for line in text.splitlines():
        if line.startswith("-----BEGIN "):
            current = [line]
        elif current is not None:
            current.append(line)
            if line.startswith("-----END "):
                blocks.append("\n".join(current) + "\n")
                current = None
    return blocks
