"""HG-044 (GitHub issue #89): Kubernetes TLS Secret manifest evidence.

One aggregate finding per supported local `kubernetes.io/tls` Secret
*document* -- never one per encoded field, certificate, or key. The claim the
detector makes is deliberately narrow:

    this local manifest document structurally declares a Kubernetes v1 TLS
    Secret, and its effective `tls.crt`/`tls.key` values contain a supported
    X.509 certificate chain and a matching unencrypted private key

and nothing about cluster existence, workload use, certificate trust,
validity, Secret safety, or risk.

Positive coverage is grounded in real `kubectl create secret tls
--dry-run=client` manifests and real OpenSSL-generated disposable key material
under ``tests/fixtures/crypto_inventory/kubernetes_tls_secret/`` (see
``PROVENANCE.md``). Negative and adversarial manifests are built in this file
from that same real material, so a rejection is always attributable to the one
property under test rather than to fabricated bytes.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448

import harvestguard
import scanner.crypto_inventory as crypto_inventory
from scanner.crypto_inventory import (
    CRYPTO_DETECTORS,
    scan_crypto_inventory,
    scan_crypto_inventory_findings,
)
from scanner.errors import LocalScanError

# ---------------------------------------------------------------------------
# Frozen contract constants (Issue #89 "Finding Contract" / "Detector
# Declaration")
# ---------------------------------------------------------------------------

RULE_ID = "kubernetes_secret:tls"
ASSET_TYPE = "Kubernetes TLS Secret"
EVIDENCE = (
    "Kubernetes TLS Secret manifest with matching certificate and private key "
    "detected"
)
CONFIDENCE = "High"
PRIORITY = 83
JSON_FORMAT = "Kubernetes JSON Manifest"
YAML_FORMAT = "Kubernetes YAML Manifest"

# The frozen neighbouring priorities HG-044 was placed against (Issue #89
# "Final numeric priority" and "Post-HG-043 Implementation Delta
# Verification").
FROZEN_PRIORITIES = {
    "certificate:pem": 70,
    "private_key:legacy_pem_encrypted": 75,
    "openssh_host_identity:private_key": 76,
    "private_key:pem": 80,
    "openssh_host_identity:public_key": 81,
    "openssh_host_identity:host_certificate": 82,
    RULE_ID: 83,
    "public_key:ssh": 90,
}

FIXTURES = (
    Path(__file__).parent / "fixtures" / "crypto_inventory" / "kubernetes_tls_secret"
)

# Reserved test-only canaries. The certificate subject/SAN canary is baked into
# the committed fixture material; the rest are seeded by the manifests this
# file builds.
SUBJECT_CANARY = "hg044-rsa.example.invalid"
NAME_CANARY = "hg044-canary-name"
NAMESPACE_CANARY = "hg044-canary-namespace"
LABEL_CANARY = "HG044-CANARY-LABEL"
ANNOTATION_CANARY = "HG044-CANARY-ANNOTATION"
UNRELATED_VALUE_CANARY = "HG044-CANARY-UNRELATED-VALUE"
STRING_DATA_CANARY = "HG044-CANARY-STRINGDATA"
EXCEPTION_CANARY = "HG044-CANARY-SECRET"

CANARIES = (
    SUBJECT_CANARY,
    NAME_CANARY,
    NAMESPACE_CANARY,
    LABEL_CANARY,
    ANNOTATION_CANARY,
    UNRELATED_VALUE_CANARY,
    STRING_DATA_CANARY,
    EXCEPTION_CANARY,
)


# ---------------------------------------------------------------------------
# Fixture material and manifest builders
# ---------------------------------------------------------------------------


def _material(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


RSA_CRT = _material("rsa.crt")
RSA_KEY = _material("rsa.key")
RSA_PKCS1_KEY = _material("rsa_pkcs1.key")
OTHER_CRT = _material("other.crt")
OTHER_KEY = _material("other.key")
EC_CRT = _material("ec.crt")
EC_KEY = _material("ec.key")
EC_SEC1_KEY = _material("ec_sec1.key")
ED25519_CRT = _material("ed25519.crt")
ED25519_KEY = _material("ed25519.key")
CA_CRT = _material("ca.crt")


def _b64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def _indent(text: str, prefix: str = "    ") -> str:
    return "\n".join(prefix + line for line in text.splitlines())


def _yaml_manifest(
    data: dict[str, str] | None = None,
    string_data: dict[str, str] | None = None,
    metadata: str = "  name: hg044-secret\n",
    api_version: str = "v1",
    kind: str = "Secret",
    secret_type: str = "kubernetes.io/tls",
) -> str:
    """A YAML Secret manifest. ``data`` values are used verbatim (already
    encoded by the caller); ``string_data`` values become literal block
    scalars."""
    text = (
        f"apiVersion: {api_version}\n"
        f"kind: {kind}\n"
        "metadata:\n"
        f"{metadata}"
        f"type: {secret_type}\n"
    )
    if data is not None:
        text += "data:\n"
        for key, value in data.items():
            text += f"  {key}: {value}\n"
    if string_data is not None:
        text += "stringData:\n"
        for key, value in string_data.items():
            if value == "":
                text += f'  {key}: ""\n'
            else:
                text += f"  {key}: |\n{_indent(value)}\n"
    return text


def _encoded_manifest(cert: str = RSA_CRT, key: str = RSA_KEY, **kwargs) -> str:
    return _yaml_manifest(data={"tls.crt": _b64(cert), "tls.key": _b64(key)}, **kwargs)


def _json_manifest(cert: str = RSA_CRT, key: str = RSA_KEY, **overrides) -> str:
    document = {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {"name": "hg044-secret"},
        "type": "kubernetes.io/tls",
        "data": {"tls.crt": _b64(cert), "tls.key": _b64(key)},
    }
    document.update(overrides)
    return json.dumps(document, indent=2)


def _write(tmp_path: Path, name: str, text: str) -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def _findings(path: Path) -> list:
    """Every HG-044 finding record the registry produces for ``path``."""
    return [
        record
        for record in _records(path)
        if record.get("Rule ID") == RULE_ID
    ]


def _records(path: Path) -> list[dict]:
    df = scan_crypto_inventory(str(path))
    return [] if df.empty else df.to_dict("records")


def _match(tmp_path: Path, text: str, name: str = "secret.yaml") -> list[dict]:
    return _findings(_write(tmp_path, name, text))


# ---------------------------------------------------------------------------
# Detector declaration (Issue #89 "Detector Declaration")
# ---------------------------------------------------------------------------


def _detector():
    matches = [d for d in CRYPTO_DETECTORS if d.detector_id == RULE_ID]
    assert len(matches) == 1, "HG-044 must appear exactly once in the registry"
    return matches[0]


def test_detector_is_registered_exactly_once_with_the_frozen_declaration():
    detector = _detector()

    assert detector.priority == PRIORITY
    assert detector.scope == "file"
    assert detector.terminal is False
    assert detector.rule_id == RULE_ID
    assert detector.confidence == CONFIDENCE
    assert detector.evidence == EVIDENCE
    assert detector.metadata_keys == frozenset({"Algorithm", "Key Size", "Format"})


def test_registry_priorities_are_unique_and_no_neighbour_was_renumbered():
    priorities = [d.priority for d in CRYPTO_DETECTORS]
    assert len(priorities) == len(set(priorities))

    declared = {d.detector_id: d.priority for d in CRYPTO_DETECTORS}
    for detector_id, priority in FROZEN_PRIORITIES.items():
        assert declared[detector_id] == priority


def test_priority_places_hg044_after_generic_pem_and_before_generic_ssh_public():
    order = [d.detector_id for d in CRYPTO_DETECTORS]

    assert order.index("certificate:pem") < order.index(RULE_ID)
    assert order.index("private_key:pem") < order.index(RULE_ID)
    assert order.index(RULE_ID) < order.index("public_key:ssh")


# ---------------------------------------------------------------------------
# Required positive coverage (Issue #89 "Required Positive Tests")
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("fixture", "algorithm", "key_size", "manifest_format"),
    [
        ("rsa_data_secret.yaml", "RSA", 2048, YAML_FORMAT),
        ("rsa_data_secret.json", "RSA", 2048, JSON_FORMAT),
        ("ec_data_secret.yaml", "EC (secp256r1)", 256, YAML_FORMAT),
        ("ed25519_data_secret.yaml", "Ed25519", 256, YAML_FORMAT),
        ("multi_cert_secret.yaml", "RSA", 2048, YAML_FORMAT),
        ("rsa_stringdata_secret.yaml", "RSA", 2048, YAML_FORMAT),
        ("rsa_mixed_secret.yaml", "RSA", 2048, YAML_FORMAT),
        ("rsa_override_secret.yaml", "RSA", 2048, YAML_FORMAT),
    ],
)
def test_real_kubectl_and_derived_fixtures_produce_one_exact_finding(
    fixture, algorithm, key_size, manifest_format
):
    records = _findings(FIXTURES / fixture)

    assert len(records) == 1
    record = records[0]
    assert record["Asset Type"] == ASSET_TYPE
    assert record["Rule ID"] == RULE_ID
    assert record["Confidence"] == CONFIDENCE
    assert record["Evidence"] == EVIDENCE
    assert record["Algorithm"] == algorithm
    assert record["Key Size"] == key_size
    assert record["Format"] == manifest_format
    assert record["Location"].endswith(f"{fixture}#document=1")


def test_override_precedence_is_stringdata_over_data():
    # The `data` tls.key in this fixture is the *non-matching* key; only
    # stringData winning produces the match.
    assert len(_findings(FIXTURES / "rsa_override_secret.yaml")) == 1


@pytest.mark.parametrize(
    ("cert", "key", "algorithm", "key_size"),
    [
        (RSA_CRT, RSA_KEY, "RSA", 2048),
        (RSA_CRT, RSA_PKCS1_KEY, "RSA", 2048),
        (EC_CRT, EC_KEY, "EC (secp256r1)", 256),
        (EC_CRT, EC_SEC1_KEY, "EC (secp256r1)", 256),
        (ED25519_CRT, ED25519_KEY, "Ed25519", 256),
    ],
)
def test_every_accepted_key_class_and_label(tmp_path, cert, key, algorithm, key_size):
    records = _match(tmp_path, _encoded_manifest(cert, key))

    assert len(records) == 1
    assert records[0]["Algorithm"] == algorithm
    assert records[0]["Key Size"] == key_size


def test_multi_certificate_chain_matches_on_the_first_certificate(tmp_path):
    records = _match(tmp_path, _encoded_manifest(RSA_CRT + CA_CRT, RSA_KEY))

    assert len(records) == 1


def test_key_matching_only_a_later_certificate_is_no_match(tmp_path):
    assert _match(tmp_path, _encoded_manifest(CA_CRT + RSA_CRT, RSA_KEY)) == []


def test_fingerprint_and_certificate_identity_fields_are_unset():
    record = _findings(FIXTURES / "rsa_data_secret.yaml")[0]

    for field in (
        "Fingerprint",
        "Subject",
        "Issuer",
        "Expiration",
        "Signature Algorithm",
        "Config Version",
        "Mode",
    ):
        assert record[field] is None


def test_extensionless_and_unprivileged_extensions_classify_identically(tmp_path):
    manifest = _encoded_manifest()
    locations = []
    for name in ("secret", "secret.yaml", "secret.yml", "secret.json", "secret.pem",
                 "secret.txt"):
        directory = tmp_path / name.replace(".", "_")
        directory.mkdir()
        records = _match(directory, manifest, name)
        assert len(records) == 1, name
        assert records[0]["Algorithm"] == "RSA"
        locations.append(records[0]["Location"])

    assert len({loc.rsplit("/", 1)[-1].split("#")[0] for loc in locations}) == 6


@pytest.mark.parametrize("extension", [".p12", ".pfx", ".cer", ".crt", ".der"])
def test_earlier_terminal_detector_ownership_is_preserved(tmp_path, extension):
    # These extensions are claimed by pkcs12:container / certificate:der before
    # priority 83 is ever reached. HG-044 must not reach in and take them back.
    records = _match(tmp_path, _encoded_manifest(), f"secret{extension}")

    assert records == []


# ---------------------------------------------------------------------------
# Multi-document identity (Issue #89 "Multi-Document YAML and Identity")
# ---------------------------------------------------------------------------


def test_multi_document_fixture_numbers_every_physical_document():
    records = _findings(FIXTURES / "multi_document.yaml")

    # Documents 1 (ConfigMap) and 2 (empty) do not match but still consume an
    # index; the two TLS Secrets are documents 3 and 4.
    assert [r["Location"].rsplit("#", 1)[1] for r in records] == [
        "document=3",
        "document=4",
    ]
    assert [r["Algorithm"] for r in records] == ["RSA", "EC (secp256r1)"]


def test_two_matching_documents_get_distinct_deterministic_locations(tmp_path):
    manifest = _encoded_manifest() + "---\n" + _encoded_manifest(EC_CRT, EC_KEY)
    records = _match(tmp_path, manifest)

    assert len(records) == 2
    assert records[0]["Location"] != records[1]["Location"]
    assert records[0]["Location"].endswith("#document=1")
    assert records[1]["Location"].endswith("#document=2")


def test_trailing_and_consecutive_markers_create_counted_empty_documents(tmp_path):
    # `---`, `---`, the Secret, `---`: the first marker opens an empty document
    # the second one closes, the Secret is document 2, and the trailing marker
    # opens a counted empty final document.
    manifest = "---\n---\n" + _encoded_manifest() + "---\n"
    records = _match(tmp_path, manifest)

    assert len(records) == 1
    assert records[0]["Location"].endswith("#document=2")


def test_comments_alone_do_not_create_a_document(tmp_path):
    manifest = "# a leading comment\n" + _encoded_manifest()
    records = _match(tmp_path, manifest)

    assert records[0]["Location"].endswith("#document=1")


def test_moving_the_object_to_another_index_changes_identity(tmp_path):
    a = tmp_path / "a"
    a.mkdir()
    b = tmp_path / "b"
    b.mkdir()
    before = _match(a, _encoded_manifest(), "secret.yaml")
    after = _match(b, "placeholder: x\n---\n" + _encoded_manifest(), "secret.yaml")

    assert before[0]["Location"].endswith("#document=1")
    assert after[0]["Location"].endswith("#document=2")


def test_metadata_name_alone_does_not_define_identity(tmp_path):
    same_name = _encoded_manifest(metadata="  name: identical\n")
    records = _match(tmp_path, same_name + "---\n" + same_name)

    assert len({r["Location"] for r in records}) == 2


def test_repeated_scans_are_stable(tmp_path):
    path = _write(tmp_path, "secret.yaml", _encoded_manifest())

    first = [r["Location"] for r in _findings(path)]
    second = [r["Location"] for r in _findings(path)]

    assert first == second


# ---------------------------------------------------------------------------
# Accounting (Issue #89 "Accounting")
# ---------------------------------------------------------------------------


def test_one_physical_file_is_counted_once_regardless_of_documents(tmp_path):
    _write(
        tmp_path,
        "secret.yaml",
        _encoded_manifest() + "---\n" + _encoded_manifest(EC_CRT, EC_KEY),
    )
    stats: dict[str, int] = {}

    df = scan_crypto_inventory(str(tmp_path), stats=stats)

    assert stats["files_inspected"] == 1
    assert len(df[df["Rule ID"] == RULE_ID]) == 2


# ---------------------------------------------------------------------------
# Object / schema rejection (Issue #89 "Document Schema")
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "manifest",
    [
        _encoded_manifest(api_version="v2"),
        _encoded_manifest(api_version="V1"),
        _encoded_manifest(kind="secret"),
        _encoded_manifest(kind="ConfigMap"),
        _encoded_manifest(secret_type="Opaque"),
        _encoded_manifest(secret_type="Kubernetes.io/tls"),
        _encoded_manifest(secret_type='"kubernetes.io/tls "'),
    ],
    ids=[
        "apiVersion",
        "apiVersion-case",
        "kind-case",
        "kind-configmap",
        "opaque",
        "type-case",
        "type-trailing-space",
    ],
)
def test_exact_case_sensitive_schema_strings_are_required(tmp_path, manifest):
    # Every one of these still contains all three gate tokens.
    assert _match(tmp_path, manifest) == []


def test_missing_data_and_stringdata_is_no_match(tmp_path):
    manifest = (
        "apiVersion: v1\nkind: Secret\nmetadata:\n  name: x\n"
        "type: kubernetes.io/tls\n"
        "# mentions tls.crt and tls.key only in a comment\n"
    )
    assert _match(tmp_path, manifest) == []


def test_metadata_is_optional(tmp_path):
    manifest = (
        "apiVersion: v1\nkind: Secret\ntype: kubernetes.io/tls\n"
        f"data:\n  tls.crt: {_b64(RSA_CRT)}\n  tls.key: {_b64(RSA_KEY)}\n"
    )
    assert len(_match(tmp_path, manifest)) == 1


@pytest.mark.parametrize(
    "manifest",
    [
        "apiVersion: v1\nkind: Secret\ntype: kubernetes.io/tls\ndata: tls.crt tls.key\n",
        "apiVersion: v1\nkind: Secret\ntype: kubernetes.io/tls\ndata:\n"
        "  - tls.crt\n  - tls.key\n",
        "apiVersion: v1\nkind: Secret\ntype: kubernetes.io/tls\ndata:\n"
        "  tls.crt:\n    nested: tls.key\n",
    ],
    ids=["scalar-section", "sequence-section", "non-scalar-value"],
)
def test_malformed_data_section_shape_is_no_match(tmp_path, manifest):
    assert _match(tmp_path, manifest) == []


@pytest.mark.parametrize(
    "data",
    [
        {"tls.crt": _b64(RSA_CRT)},
        {"tls.key": _b64(RSA_KEY)},
        {"tls.crt": "", "tls.key": _b64(RSA_KEY)},
        {"tls.crt": _b64(RSA_CRT), "tls.key": ""},
    ],
    ids=["no-key", "no-cert", "empty-cert", "empty-key"],
)
def test_missing_or_empty_required_values_are_no_match(tmp_path, data):
    assert _match(tmp_path, _yaml_manifest(data=data)) == []


def test_empty_stringdata_override_does_not_fall_back_to_data(tmp_path):
    manifest = _yaml_manifest(
        data={"tls.crt": _b64(RSA_CRT), "tls.key": _b64(RSA_KEY)},
        string_data={"tls.key": ""},
    )
    assert _match(tmp_path, manifest) == []


def test_unrelated_secret_values_are_permitted_but_never_decoded(tmp_path):
    manifest = _yaml_manifest(
        data={
            "tls.crt": _b64(RSA_CRT),
            "tls.key": _b64(RSA_KEY),
            # Deliberately not valid base64: HG-044 must never decode it.
            "unrelated": f"not*base64*{UNRELATED_VALUE_CANARY}",
        }
    )
    records = _match(tmp_path, manifest)

    assert len(records) == 1
    assert UNRELATED_VALUE_CANARY not in json.dumps(records[0], default=str)


@pytest.mark.parametrize(
    "manifest",
    [
        json.dumps(
            {
                "apiVersion": "v1",
                "kind": "List",
                "items": [{"type": "kubernetes.io/tls", "tls.crt": "", "tls.key": ""}],
            }
        ),
        json.dumps(
            {
                "apiVersion": "v1",
                "kind": "SecretList",
                "items": [{"type": "kubernetes.io/tls", "tls.crt": "", "tls.key": ""}],
            }
        ),
        json.dumps([json.loads(_json_manifest())]),
    ],
    ids=["list", "secretlist", "top-level-array"],
)
def test_list_and_top_level_array_shapes_are_no_match(tmp_path, manifest):
    assert _match(tmp_path, manifest, "secret.json") == []


def test_top_level_array_never_falls_back_to_yaml(tmp_path):
    # A YAML sequence whose single item is a valid Secret mapping: dispatch
    # selects JSON because of the leading `[`, strict JSON parsing fails, and
    # there is deliberately no YAML retry.
    manifest = "[\n" + _encoded_manifest() + "]\n"
    assert _match(tmp_path, manifest) == []


def test_json_candidate_failing_strict_parsing_does_not_fall_back_to_yaml(tmp_path):
    manifest = "{\n" + _encoded_manifest() + "}\n"
    assert _match(tmp_path, manifest) == []


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
def test_non_finite_json_constants_reject(tmp_path, constant):
    manifest = _json_manifest().rstrip()[:-1] + f',\n  "extra": {constant}\n}}'
    assert _match(tmp_path, manifest, "secret.json") == []


def test_duplicate_json_keys_reject_at_the_top_level(tmp_path):
    manifest = _json_manifest().rstrip()[:-1] + ',\n  "kind": "Secret"\n}'
    assert _match(tmp_path, manifest, "secret.json") == []


def test_duplicate_json_keys_reject_at_a_nested_level(tmp_path):
    manifest = _json_manifest().replace(
        '"metadata": {\n    "name": "hg044-secret"\n  }',
        '"metadata": {\n    "name": "a",\n    "name": "b"\n  }',
    )
    assert '"name": "a"' in manifest
    assert _match(tmp_path, manifest, "secret.json") == []


def test_json_bom_rejects(tmp_path):
    assert _match(tmp_path, "﻿" + _json_manifest(), "secret.json") == []


def test_yaml_bom_rejects(tmp_path):
    assert _match(tmp_path, "﻿" + _encoded_manifest()) == []


# ---------------------------------------------------------------------------
# YAML safety profile and bounds (Issue #89 "YAML Grammar and Safety Profile")
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "fixture",
    ["duplicate_key_secret.yaml", "anchor_alias_secret.yaml", "explicit_tag_secret.yaml"],
)
def test_adversarial_yaml_control_fixtures_reject_the_whole_file(fixture):
    assert _findings(FIXTURES / fixture) == []


def test_a_rejected_yaml_file_rejects_every_document_in_it(tmp_path):
    # A perfectly good Secret document sharing a file with an aliased one:
    # rejection is whole-file, before any document is evaluated.
    bad = "x: &a 1\ny: *a\n" + f"tls.crt: {_b64(RSA_CRT)}\ntls.key: {_b64(RSA_KEY)}\n"
    assert _match(tmp_path, _encoded_manifest() + "---\n" + bad) == []


def test_merge_key_rejects(tmp_path):
    manifest = _encoded_manifest() + "extra:\n  <<: {}\n"
    assert _match(tmp_path, manifest) == []


def test_quoted_merge_key_also_rejects(tmp_path):
    manifest = _encoded_manifest() + 'extra:\n  "<<": {}\n'
    assert _match(tmp_path, manifest) == []


def test_complex_mapping_key_rejects(tmp_path):
    manifest = _encoded_manifest() + "extra:\n  ? [a, b]\n  : c\n"
    assert _match(tmp_path, manifest) == []


def test_yaml_directive_rejects(tmp_path):
    assert _match(tmp_path, "%YAML 1.2\n---\n" + _encoded_manifest()) == []


def test_tag_directive_rejects(tmp_path):
    manifest = "%TAG !e! tag:example.invalid,2000:\n---\n" + _encoded_manifest()
    assert _match(tmp_path, manifest) == []


def test_more_than_sixty_four_documents_rejects_the_whole_file(tmp_path):
    manifest = _encoded_manifest() + ("---\nplaceholder: x\n" * 64)
    assert _match(tmp_path, manifest) == []


def test_exactly_sixty_four_documents_is_accepted(tmp_path):
    manifest = _encoded_manifest() + ("---\nplaceholder: x\n" * 63)
    assert len(_match(tmp_path, manifest)) == 1


def test_excess_collection_nesting_rejects_the_whole_file(tmp_path):
    deep = "[" * 70 + "]" * 70
    assert _match(tmp_path, _encoded_manifest() + f"deep: {deep}\n") == []


def test_excess_parse_events_rejects_the_whole_file(tmp_path):
    wide = "[" + ",".join(["1"] * 100_001) + "]"
    assert _match(tmp_path, _encoded_manifest() + f"wide: {wide}\n") == []


def test_implicit_scalar_spellings_stay_exact_text(tmp_path):
    # BaseLoader keeps `v1` a string; a document whose apiVersion is the
    # unquoted YAML null spelling stays the literal text "null", not None, and
    # is an ordinary schema no-match rather than a crash.
    assert _match(tmp_path, _encoded_manifest(api_version="null")) == []


def test_quoted_schema_values_are_accepted(tmp_path):
    assert len(_match(tmp_path, _encoded_manifest(api_version='"v1"'))) == 1


# ---------------------------------------------------------------------------
# Strict base64 profile (Issue #89 "Strict `data` Base64 Profile")
# ---------------------------------------------------------------------------


def _padded_key_text() -> str:
    """The real private key plus enough permitted trailing whitespace that its
    base64 encoding genuinely carries `=` padding -- so the unpadded case below
    tests padding, not some other property of the value."""
    text = RSA_KEY
    while len(text.encode("utf-8")) % 3 == 0:
        text += "\n"
    return text


@pytest.mark.parametrize(
    "encoded",
    [
        _b64(RSA_KEY).replace("A", "*", 1),
        _b64(RSA_KEY)[:20] + "\n" + _b64(RSA_KEY)[20:],
        _b64(RSA_KEY)[:20] + " " + _b64(RSA_KEY)[20:],
        base64.urlsafe_b64encode(("x" * 200 + RSA_KEY).encode()).decode(),
        _b64(_padded_key_text()).rstrip("="),
        "",
    ],
    ids=["alphabet", "newline", "space", "urlsafe", "unpadded", "empty"],
)
def test_strict_base64_rejections(tmp_path, encoded):
    manifest = _yaml_manifest(data={"tls.crt": _b64(RSA_CRT), "tls.key": encoded})
    assert _match(tmp_path, manifest) == []


def test_the_padded_control_for_the_unpadded_rejection_matches(tmp_path):
    # Same bytes, canonical padding restored: the only difference between this
    # and the `unpadded` case above is the `=` characters.
    encoded = _b64(_padded_key_text())
    assert encoded.endswith("=")
    manifest = _yaml_manifest(data={"tls.crt": _b64(RSA_CRT), "tls.key": encoded})

    assert len(_match(tmp_path, manifest)) == 1


def test_noncanonical_final_quantum_rejects(tmp_path):
    # `AQ==` decodes to b"\x01"; `AR==` decodes to the same byte under a lenient
    # decoder but does not re-encode to itself.
    assert crypto_inventory._kubernetes_strict_base64("AQ==") == b"\x01"
    assert crypto_inventory._kubernetes_strict_base64("AR==") is None


def test_empty_decode_rejects():
    assert crypto_inventory._kubernetes_strict_base64("") is None


# ---------------------------------------------------------------------------
# Certificate profile (Issue #89 "`tls.crt` Profile")
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "certificate_value",
    [
        "-----BEGIN CERTIFICATE-----\nbm90IGEgY2VydA==\n-----END CERTIFICATE-----\n",
        "trailing text after the block\n" + RSA_CRT,
        RSA_CRT + "trailing text after the block\n",
        RSA_CRT + RSA_KEY,
        RSA_KEY,
        "",
        RSA_CRT + "-----BEGIN CERTIFICATE-----\nbad\n-----END CERTIFICATE-----\n",
        "﻿" + RSA_CRT,
    ],
    ids=[
        "malformed",
        "prefix-text",
        "suffix-text",
        "certificate-plus-key",
        "no-certificate",
        "zero-certificates",
        "malformed-later-certificate",
        "bom",
    ],
)
def test_certificate_profile_rejections(tmp_path, certificate_value):
    manifest = _yaml_manifest(
        data={"tls.crt": _b64(certificate_value) or "", "tls.key": _b64(RSA_KEY)}
    )
    assert _match(tmp_path, manifest) == []


def test_permitted_inter_block_whitespace_is_accepted(tmp_path):
    chain = RSA_CRT + "\x0b\x0c \t\r\n" + CA_CRT
    manifest = _yaml_manifest(data={"tls.crt": _b64(chain), "tls.key": _b64(RSA_KEY)})

    assert len(_match(tmp_path, manifest)) == 1


def test_delimiter_line_with_trailing_content_rejects(tmp_path):
    broken = RSA_CRT.replace(
        "-----BEGIN CERTIFICATE-----", "-----BEGIN CERTIFICATE----- x", 1
    )
    manifest = _yaml_manifest(data={"tls.crt": _b64(broken), "tls.key": _b64(RSA_KEY)})

    assert _match(tmp_path, manifest) == []


# Codex principal review (PR #110), round 2: the first fix still stripped the
# *whole value* for permitted outer whitespace before ever validating a final
# block's own END line, so a genuinely final "-----END CERTIFICATE----- \n"
# was reduced to an apparent EOF boundary before the check ever ran, and a
# bare CR (not followed by LF) was still accepted as a line terminator
# anywhere. `_kubernetes_pem_blocks` no longer strips the value up front: each
# delimiter marker's own terminator is now validated directly against the
# unstripped bytes at its own position, so this must hold for a final block,
# not only a block a chain member follows.
_END_DELIMITER_TRAILING_CONTENT_CASES = [
    ("SP then LF", " \n"),
    ("HT then LF", "\t\n"),
    ("VT then LF", "\x0b\n"),
    ("FF then LF", "\x0c\n"),
    ("bare CR", "\r"),
]


@pytest.mark.parametrize(
    ("case", "suffix"),
    _END_DELIMITER_TRAILING_CONTENT_CASES,
    ids=[case for case, _ in _END_DELIMITER_TRAILING_CONTENT_CASES],
)
def test_final_certificate_end_delimiter_trailing_content_rejects(tmp_path, case, suffix):
    # An otherwise-valid single certificate whose only defect is what follows
    # its own (final, and only) END marker.
    broken = RSA_CRT.rstrip("\n") + suffix
    manifest = _yaml_manifest(data={"tls.crt": _b64(broken), "tls.key": _b64(RSA_KEY)})

    assert _match(tmp_path, manifest) == []


@pytest.mark.parametrize(
    ("case", "suffix"),
    _END_DELIMITER_TRAILING_CONTENT_CASES,
    ids=[case for case, _ in _END_DELIMITER_TRAILING_CONTENT_CASES],
)
def test_final_private_key_end_delimiter_trailing_content_rejects(tmp_path, case, suffix):
    # An otherwise-valid single private-key block whose only defect is what
    # follows its own END marker -- deliberately not a second key block or any
    # other independent no-match condition, so a pass here can only mean the
    # END-line check itself let it through.
    broken = RSA_KEY.rstrip("\n") + suffix
    manifest = _yaml_manifest(data={"tls.crt": _b64(RSA_CRT), "tls.key": _b64(broken)})

    assert _match(tmp_path, manifest) == []


def test_intermediate_certificate_end_delimiter_trailing_content_rejects(tmp_path):
    # The same defect on a non-final block in a chain: trailing spaces on the
    # first certificate's END line, immediately before a second, otherwise
    # valid certificate.
    broken = RSA_CRT.rstrip("\n") + "   \n" + CA_CRT
    manifest = _yaml_manifest(data={"tls.crt": _b64(broken), "tls.key": _b64(RSA_KEY)})

    assert _match(tmp_path, manifest) == []


def test_end_delimiter_followed_by_lf_is_accepted(tmp_path):
    manifest = _yaml_manifest(
        data={
            "tls.crt": _b64(RSA_CRT.rstrip("\n") + "\n"),
            "tls.key": _b64(RSA_KEY.rstrip("\n") + "\n"),
        }
    )

    assert len(_match(tmp_path, manifest)) == 1


def test_end_delimiter_followed_by_crlf_is_accepted(tmp_path):
    manifest = _yaml_manifest(
        data={
            "tls.crt": _b64(RSA_CRT.rstrip("\n") + "\r\n"),
            "tls.key": _b64(RSA_KEY.rstrip("\n") + "\r\n"),
        }
    )

    assert len(_match(tmp_path, manifest)) == 1


def test_end_delimiter_immediately_at_end_of_value_is_accepted(tmp_path):
    # A value whose final byte is exactly the closing dash of
    # "-----END CERTIFICATE-----"/"-----END PRIVATE KEY-----", with no
    # trailing newline at all, must remain a match -- the fix must not
    # require a newline to always follow the END marker, only that nothing
    # illegitimate does.
    manifest = _yaml_manifest(
        data={"tls.crt": _b64(RSA_CRT.rstrip("\n")), "tls.key": _b64(RSA_KEY.rstrip("\n"))}
    )

    assert len(_match(tmp_path, manifest)) == 1


def test_private_key_with_permitted_outer_whitespace_only_is_accepted(tmp_path):
    padded = " \t\r\n" + RSA_KEY + "\x0b\x0c "
    manifest = _yaml_manifest(data={"tls.crt": _b64(RSA_CRT), "tls.key": _b64(padded)})

    assert len(_match(tmp_path, manifest)) == 1


# ---------------------------------------------------------------------------
# Private-key profile (Issue #89 "`tls.key` Profile")
# ---------------------------------------------------------------------------


def _pem(key) -> str:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")


def _encrypted_pkcs8() -> str:
    key = serialization.load_pem_private_key(RSA_KEY.encode(), password=None)
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(b"hg044-fixture-not-a-real-secret"),
    ).decode("ascii")


def _encrypted_traditional() -> str:
    key = serialization.load_pem_private_key(RSA_KEY.encode(), password=None)
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.BestAvailableEncryption(b"hg044-fixture-not-a-real-secret"),
    ).decode("ascii")


def _key_cases():
    return [
        ("malformed", "-----BEGIN PRIVATE KEY-----\nbm90IGEga2V5\n-----END PRIVATE KEY-----\n"),
        ("encrypted-pkcs8", _encrypted_pkcs8()),
        ("encrypted-traditional", _encrypted_traditional()),
        ("dsa", _pem(dsa.generate_private_key(key_size=2048))),
        ("ed448", _pem(ed448.Ed448PrivateKey.generate())),
        (
            "unsupported-curve",
            _pem(ec.generate_private_key(ec.SECP224R1())),
        ),
        ("multiple-keys", RSA_KEY + OTHER_KEY),
        ("key-plus-certificate", RSA_KEY + RSA_CRT),
        ("prefix-text", "leading junk\n" + RSA_KEY),
        ("suffix-text", RSA_KEY + "trailing junk\n"),
        ("certificate-only", RSA_CRT),
    ]


@pytest.mark.parametrize(
    ("case", "key_value"), _key_cases(), ids=[case for case, _ in _key_cases()]
)
def test_private_key_profile_rejections(tmp_path, case, key_value):
    manifest = _yaml_manifest(
        data={"tls.crt": _b64(RSA_CRT), "tls.key": _b64(key_value)}
    )
    assert _match(tmp_path, manifest) == []


def test_der_private_key_is_no_match(tmp_path):
    key = serialization.load_pem_private_key(RSA_KEY.encode(), password=None)
    der = key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    manifest = _yaml_manifest(
        data={
            "tls.crt": _b64(RSA_CRT),
            "tls.key": base64.b64encode(der).decode("ascii"),
        }
    )
    assert _match(tmp_path, manifest) == []


def test_no_password_is_ever_supplied_to_the_key_loader(tmp_path, monkeypatch):
    seen: list[object] = []
    real = crypto_inventory.serialization.load_pem_private_key

    def _record(data, password, *args, **kwargs):
        seen.append(password)
        return real(data, password, *args, **kwargs)

    monkeypatch.setattr(
        crypto_inventory.serialization, "load_pem_private_key", _record
    )
    assert len(_match(tmp_path, _encoded_manifest())) == 1
    assert seen and all(password is None for password in seen)


# ---------------------------------------------------------------------------
# Correspondence (Issue #89 "Certificate / Key Correspondence")
# ---------------------------------------------------------------------------


def test_mismatched_pair_fixture_is_no_match():
    assert _findings(FIXTURES / "mismatched_secret.yaml") == []


def test_mismatched_pair_built_from_real_material(tmp_path):
    assert _match(tmp_path, _encoded_manifest(RSA_CRT, OTHER_KEY)) == []


class _StubCertificate:
    """A certificate stand-in whose ``public_key()`` raises, for the
    ``cryptography`` version-compatibility boundary."""

    def __init__(self, error: BaseException):
        self._error = error

    def public_key(self):
        raise self._error


@pytest.mark.parametrize(
    "error",
    [ValueError("unsupported"), UnsupportedAlgorithm("unsupported")],
    ids=["value-error", "unsupported-algorithm"],
)
def test_certificate_public_key_compatibility_errors_are_ordinary_no_match(
    tmp_path, monkeypatch, error
):
    monkeypatch.setattr(
        crypto_inventory.x509,
        "load_pem_x509_certificate",
        lambda *a, **kw: _StubCertificate(error),
    )
    assert _match(tmp_path, _encoded_manifest()) == []


# ---------------------------------------------------------------------------
# Error boundary (Issue #89 "Parsing Error Contract" / "Error-Boundary Tests")
# ---------------------------------------------------------------------------


def _expect_sanitized_failure(tmp_path) -> str:
    with pytest.raises(LocalScanError) as excinfo:
        scan_crypto_inventory_findings(str(tmp_path))
    message = str(excinfo.value)
    assert RULE_ID in message
    assert "RuntimeError" in message
    assert EXCEPTION_CANARY not in message
    assert "#document=" not in message
    for canary in CANARIES:
        assert canary not in message
    return message


def test_unexpected_manifest_parser_failure_is_sanitized(tmp_path, monkeypatch):
    _write(tmp_path, "secret.yaml", _encoded_manifest())

    def _boom(*args, **kwargs):
        raise RuntimeError(EXCEPTION_CANARY)

    monkeypatch.setattr(crypto_inventory.yaml, "load_all", _boom)
    _expect_sanitized_failure(tmp_path)


def test_unexpected_certificate_parser_failure_is_sanitized(tmp_path, monkeypatch):
    _write(tmp_path, "secret.yaml", _encoded_manifest())

    def _boom(*args, **kwargs):
        raise RuntimeError(EXCEPTION_CANARY)

    monkeypatch.setattr(crypto_inventory.x509, "load_pem_x509_certificate", _boom)
    _expect_sanitized_failure(tmp_path)


def test_unexpected_private_key_parser_failure_is_sanitized(tmp_path, monkeypatch):
    _write(tmp_path, "secret.yaml", _encoded_manifest())

    def _boom(*args, **kwargs):
        raise RuntimeError(EXCEPTION_CANARY)

    monkeypatch.setattr(
        crypto_inventory.serialization, "load_pem_private_key", _boom
    )
    _expect_sanitized_failure(tmp_path)


def test_unexpected_certificate_public_key_failure_is_sanitized(tmp_path, monkeypatch):
    _write(tmp_path, "secret.yaml", _encoded_manifest())
    monkeypatch.setattr(
        crypto_inventory.x509,
        "load_pem_x509_certificate",
        lambda *a, **kw: _StubCertificate(RuntimeError(EXCEPTION_CANARY)),
    )
    _expect_sanitized_failure(tmp_path)


def test_error_location_is_the_physical_file_not_a_virtual_document(
    tmp_path, monkeypatch
):
    _write(
        tmp_path,
        "secret.yaml",
        _encoded_manifest() + "---\n" + _encoded_manifest(EC_CRT, EC_KEY),
    )
    real = crypto_inventory.serialization.load_pem_private_key
    calls = {"n": 0}

    def _boom_on_second(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] >= 2:
            raise RuntimeError(EXCEPTION_CANARY)
        return real(*args, **kwargs)

    monkeypatch.setattr(
        crypto_inventory.serialization, "load_pem_private_key", _boom_on_second
    )
    message = _expect_sanitized_failure(tmp_path)

    assert str(tmp_path / "secret.yaml") in message


def test_findings_for_earlier_documents_are_not_returned_after_a_failure(
    tmp_path, monkeypatch
):
    _write(
        tmp_path,
        "secret.yaml",
        _encoded_manifest() + "---\n" + _encoded_manifest(EC_CRT, EC_KEY),
    )
    real = crypto_inventory.serialization.load_pem_private_key
    calls = {"n": 0}

    def _boom_on_second(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] >= 2:
            raise RuntimeError(EXCEPTION_CANARY)
        return real(*args, **kwargs)

    monkeypatch.setattr(
        crypto_inventory.serialization, "load_pem_private_key", _boom_on_second
    )
    with pytest.raises(LocalScanError) as excinfo:
        scan_crypto_inventory_findings(str(tmp_path))

    assert [f for f in excinfo.value.partial_findings if f.rule_id == RULE_ID] == []


def test_document_count_mismatch_is_a_defect_not_a_no_match(tmp_path, monkeypatch):
    _write(tmp_path, "secret.yaml", _encoded_manifest())
    monkeypatch.setattr(crypto_inventory, "_kubernetes_yaml_preflight", lambda text: 7)

    with pytest.raises(LocalScanError) as excinfo:
        scan_crypto_inventory_findings(str(tmp_path))

    assert "_KubernetesDocumentCountMismatch" in str(excinfo.value)


# ---------------------------------------------------------------------------
# Privacy (Issue #89 "Privacy Contract" / "Canary tests")
# ---------------------------------------------------------------------------


def _canary_manifest() -> str:
    metadata = (
        f"  name: {NAME_CANARY}\n"
        f"  namespace: {NAMESPACE_CANARY}\n"
        "  uid: hg044-canary-uid\n"
        "  resourceVersion: hg044-canary-resource-version\n"
        "  labels:\n"
        f"    hg044/label: {LABEL_CANARY}\n"
        "  annotations:\n"
        f"    hg044/annotation: {ANNOTATION_CANARY}\n"
    )
    return _yaml_manifest(
        data={
            "tls.crt": _b64(RSA_CRT),
            "tls.key": _b64(RSA_KEY),
            "unrelated": _b64(UNRELATED_VALUE_CANARY),
        },
        metadata=metadata,
    )


def _canary_target(tmp_path: Path) -> Path:
    return _write(tmp_path, "canary-secret.yaml", _canary_manifest())


def test_no_canary_reaches_the_scanner_finding(tmp_path):
    records = _findings(_canary_target(tmp_path))

    assert len(records) == 1
    payload = json.dumps(records[0], default=str)
    for canary in CANARIES:
        assert canary not in payload


def test_no_canary_reaches_the_normalized_finding(tmp_path):
    _canary_target(tmp_path)
    findings = [
        f for f in scan_crypto_inventory_findings(str(tmp_path)) if f.rule_id == RULE_ID
    ]

    assert len(findings) == 1
    finding = findings[0]
    assert finding.asset_type == ASSET_TYPE
    assert finding.evidence == EVIDENCE
    assert finding.confidence == CONFIDENCE
    assert finding.source_type == "crypto_inventory"
    assert finding.technical_metadata.get("Algorithm") == "RSA"
    assert finding.technical_metadata.get("Key Size") == 2048
    assert finding.technical_metadata.get("Format") == YAML_FORMAT
    assert finding.technical_metadata.get("Fingerprint") is None
    assert finding.location.endswith("canary-secret.yaml#document=1")

    payload = json.dumps(
        {
            "location": finding.location,
            "metadata": finding.technical_metadata,
            "evidence": finding.evidence,
            "errors": finding.errors,
        },
        default=str,
    )
    for canary in CANARIES:
        assert canary not in payload


def test_no_canary_reaches_json_or_markdown_exports(tmp_path, capsys):
    _canary_target(tmp_path)

    assert (
        harvestguard.main(["scan", str(tmp_path), "--type", "crypto", "--json", "--quiet"])
        == 0
    )
    json_out = capsys.readouterr().out
    assert RULE_ID in json_out

    assert harvestguard.main(["scan", str(tmp_path), "--type", "crypto", "--quiet"]) == 0
    markdown_out = capsys.readouterr().out

    for payload in (json_out, markdown_out):
        for canary in CANARIES:
            assert canary not in payload


def test_evidence_store_round_trip_preserves_the_finding_and_the_privacy_contract(
    tmp_path, capsys
):
    target = tmp_path / "target"
    target.mkdir()
    _canary_target(target)
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
    records = [r for r in json.loads(live) if r["rule_id"] == RULE_ID]
    assert len(records) == 1
    record = records[0]
    assert record["asset_type"] == ASSET_TYPE
    assert record["evidence"] == EVIDENCE
    assert record["confidence"] == CONFIDENCE
    assert record["technical_metadata"]["Algorithm"] == "RSA"
    assert record["technical_metadata"]["Key Size"] == 2048
    assert record["technical_metadata"]["Format"] == YAML_FORMAT
    assert record["technical_metadata"].get("Fingerprint") is None
    assert record["location"].endswith("canary-secret.yaml#document=1")
    scan_id = record["scan_id"]
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
            [
                "evidence",
                "export",
                scan_id,
                "--evidence-db",
                str(db),
                "--markdown",
                "--quiet",
            ]
        )
        == 0
    )
    markdown = capsys.readouterr().out
    assert ASSET_TYPE in markdown

    for payload in (live, stored, markdown):
        for canary in CANARIES:
            assert canary not in payload


def test_finding_identity_is_deterministic_across_scans(tmp_path):
    _canary_target(tmp_path)

    first = [
        f.finding_id
        for f in scan_crypto_inventory_findings(str(tmp_path), scan_id="fixed")
        if f.rule_id == RULE_ID
    ]
    second = [
        f.finding_id
        for f in scan_crypto_inventory_findings(str(tmp_path), scan_id="fixed")
        if f.rule_id == RULE_ID
    ]

    assert first == second


def test_two_documents_in_one_file_get_distinct_finding_ids(tmp_path):
    _write(
        tmp_path,
        "secret.yaml",
        _encoded_manifest() + "---\n" + _encoded_manifest(EC_CRT, EC_KEY),
    )

    ids = [
        f.finding_id
        for f in scan_crypto_inventory_findings(str(tmp_path), scan_id="fixed")
        if f.rule_id == RULE_ID
    ]

    assert len(ids) == 2
    assert len(set(ids)) == 2


# ---------------------------------------------------------------------------
# Runtime security boundary (Issue #89 "Runtime Security Boundary")
# ---------------------------------------------------------------------------


def test_detection_runs_no_subprocess_and_opens_no_extra_file(tmp_path, monkeypatch):
    import subprocess

    def _forbidden(*args, **kwargs):
        raise AssertionError("HG-044 must never invoke a subprocess")

    for name in ("run", "Popen", "call", "check_call", "check_output"):
        monkeypatch.setattr(subprocess, name, _forbidden)

    target = _write(tmp_path, "secret.yaml", _encoded_manifest())
    opened: list[str] = []
    real_read_bytes = Path.read_bytes

    def _record(self):
        opened.append(str(self))
        return real_read_bytes(self)

    monkeypatch.setattr(Path, "read_bytes", _record)

    assert len(_findings(target)) == 1
    assert opened == [str(target)]


def test_decoded_secret_values_are_never_dispatched_to_other_detectors(tmp_path):
    # A base64 `data` manifest carries no literal PEM text, so the only finding
    # is HG-044's aggregate one: the decoded certificate and key are validation
    # evidence and are never resubmitted to certificate:pem / private_key:pem.
    records = _records(_write(tmp_path, "secret.yaml", _encoded_manifest()))

    assert [r["Rule ID"] for r in records] == [RULE_ID]
    assert len(records) == 1


def test_physical_source_findings_coexist_with_the_aggregate_finding():
    # A stringData manifest embeds literal PEM text, which the pre-existing
    # physical-file detectors read independently. Coexistence, not suppression.
    records = _records(FIXTURES / "rsa_stringdata_secret.yaml")
    by_type = {r["Asset Type"]: r for r in records}

    assert "PEM Certificate" in by_type
    assert "PEM Private Key" in by_type
    assert ASSET_TYPE in by_type
    assert by_type["PEM Certificate"]["Location"].endswith("rsa_stringdata_secret.yaml")
    assert by_type["PEM Private Key"]["Location"].endswith("rsa_stringdata_secret.yaml")
    assert by_type[ASSET_TYPE]["Location"].endswith("#document=1")


def test_no_relationship_record_is_created(tmp_path, monkeypatch):
    # HG-034's relationship model stays untouched: the certificate/key
    # correspondence is an internal boolean, and no synthetic endpoint pair is
    # invented to justify a `corresponds_to` record.
    import scanner.crypto_relationships as crypto_relationships

    def _forbidden(*args, **kwargs):
        raise AssertionError("HG-044 must not populate the relationship model")

    monkeypatch.setattr(crypto_relationships, "build_relationship", _forbidden)
    _write(tmp_path, "secret.yaml", _encoded_manifest())

    findings = [
        f for f in scan_crypto_inventory_findings(str(tmp_path)) if f.rule_id == RULE_ID
    ]

    assert len(findings) == 1
    source = (
        Path(crypto_inventory.__file__).read_text(encoding="utf-8")
    )
    assert "crypto_relationships" not in source


# ---------------------------------------------------------------------------
# Adjacent-detector regression (Issue #89 "Ownership / Regression Tests")
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "expected_types"),
    [
        ("rsa_cert.pem", {"PEM Certificate"}),
        ("valid_key.pem", {"PEM Private Key"}),
        ("encrypted_key.pem", {"Encrypted PKCS#8 Private Key"}),
        ("ssh_key.pub", {"OpenSSH Public Key"}),
    ],
)
def test_unrelated_pem_inputs_are_unaffected(name, expected_types):
    source = FIXTURES.parent / name
    records = _records(source)

    assert {r["Asset Type"] for r in records} & expected_types
    assert all(r["Rule ID"] != RULE_ID for r in records)


def test_a_manifest_missing_one_gate_token_falls_through_untouched(tmp_path):
    # Same manifest with `tls.key` spelled only through a YAML escape: a
    # deliberate HG-044 false negative, and nothing else changes.
    manifest = _encoded_manifest().replace("tls.key", '"tls\\x2ekey"')
    assert "tls.key" not in manifest
    assert _match(tmp_path, manifest) == []


def test_a_malformed_manifest_falls_through_to_the_generic_detectors(tmp_path):
    manifest = _yaml_manifest(string_data={"tls.crt": RSA_CRT, "tls.key": RSA_KEY})
    broken = manifest.replace("kind: Secret", "kind: Secret\nkind: Secret")
    records = _records(_write(tmp_path, "secret.yaml", broken))

    assert all(r["Rule ID"] != RULE_ID for r in records)
    assert {"PEM Certificate", "PEM Private Key"} <= {r["Asset Type"] for r in records}
