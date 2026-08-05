"""Regression coverage for the internal cryptographic relationship model (HG-034).

HG-034 introduces an internal-only model and **no** new detection capability and
**no** public output, so this file has two jobs.

The first is the model's own contract, which nothing else can see: the fixed
vocabulary, endpoint existence, direction versus symmetry, deterministic
identity and what identity excludes, deterministic duplicate suppression,
evidence-only wording, the supported confidence vocabulary, provenance, and the
structural privacy boundary (no metadata dictionary, no raw material, no
serialization path).

The second is the *boundary*: that creating relationships changes nothing a user
can observe. The existing suites (tests/test_crypto_inventory.py,
tests/test_crypto_detector_framework.py, the OpenSSL/OpenPGP/gocryptfs
detection suites, tests/test_cli.py, tests/test_reports.py,
tests/test_product_claims.py, tests/test_release_identity.py) still pin the
public behavior itself and pass unmodified; what is added here is that
relationship work does not perturb the DataFrame columns, the normalized-finding
JSON, the Markdown report, console summary counts, or crypto scan accounting,
and that no public surface imports the model at all.

Fixtures are synthetic internal findings on purpose: HG-034 does not require any
current detector to emit production relationships.
"""

from __future__ import annotations

import json
import random
from collections.abc import Mapping
from dataclasses import FrozenInstanceError, asdict, fields
from datetime import datetime, timezone
from pathlib import Path

import pytest

import reports
from findings import NormalizedFinding, findings_to_dicts
from scanner.crypto_inventory import (
    CRYPTO_DETECTORS,
    scan_crypto_inventory,
    scan_crypto_inventory_findings,
)
from scanner.crypto_relationships import (
    DIRECTIONAL_RELATIONSHIP_TYPES,
    MAX_TEXT_FIELD_CHARS,
    RELATIONSHIP_MODEL_COMPONENT,
    SUPPORTED_RELATIONSHIP_CONFIDENCE,
    SYMMETRIC_RELATIONSHIP_TYPES,
    CryptoRelationship,
    MalformedRelationshipError,
    MissingEndpointError,
    RelationshipCollection,
    RelationshipOutcome,
    RelationshipType,
    RelationshipValidationError,
    SelfRelationshipError,
    UnknownRelationshipTypeError,
    build_relationship,
    canonical_endpoints,
    canonical_record_key,
    collect_relationships,
    deduplicate_relationships,
    derive_relationship_id,
    index_finding_ids,
    validate_endpoints,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIR = Path(__file__).parent / "fixtures" / "crypto_inventory"

# The complete relationship vocabulary HG-034 allows. A new entry here means a
# new relationship type, which must be an explicit code and test change -- this
# list is what makes that reviewable.
EXPECTED_RELATIONSHIP_TYPES = [
    "contains",
    "corresponds_to",
    "references",
    "member_of",
    "issued_by",
]

# Vague, assessment-flavored, or dependency-flavored relations the vocabulary
# deliberately excludes.
REJECTED_RELATIONSHIP_TYPES = [
    "related_to",
    "depends_on",
    "uses",
    "protects",
    "owned_by",
    "belongs_to",
    "impacts",
    "at_risk_from",
]

# Evidence wording used by every High-confidence fixture below: direct
# structural observation only, no validity/trust/ownership/business claim and no
# inference from names, paths, proximity, or co-location.
CONTAINS_EVIDENCE = "Parsed PKCS#12 container directly contains this certificate object"
CORRESPONDS_EVIDENCE = (
    "Public key material derived from the certificate matches public key material "
    "derived from the private key"
)
ISSUED_BY_EVIDENCE = (
    "Parsed certificate issuer field matches the parsed subject field of the other "
    "certificate"
)


def _finding(location: str, asset_type: str, identity_key: str | None = None) -> NormalizedFinding:
    """A synthetic internal finding, shaped like a crypto-inventory finding."""
    return NormalizedFinding(
        source_type="local_filesystem",
        asset_type=asset_type,
        location=location,
        scanner_name="crypto_inventory",
        evidence=f"{asset_type} parsed successfully",
        confidence="High",
        identity_key=identity_key,
    )


@pytest.fixture
def universe() -> dict[str, NormalizedFinding]:
    """Three synthetic findings: a container and the two objects inside it."""
    return {
        "container": _finding("/tmp/bundle.p12", "PKCS#12 Container"),
        "certificate": _finding("/tmp/bundle.p12", "X.509 Certificate", identity_key="cert-fp"),
        "private_key": _finding("/tmp/bundle.p12", "PEM Private Key", identity_key="key-fp"),
    }


@pytest.fixture
def known_ids(universe) -> frozenset[str]:
    return index_finding_ids(universe.values())


def _contains(universe, known_ids, **overrides) -> CryptoRelationship:
    kwargs = {
        "relationship_type": RelationshipType.CONTAINS,
        "source_finding_id": universe["container"].finding_id,
        "target_finding_id": universe["certificate"].finding_id,
        "evidence": CONTAINS_EVIDENCE,
        "confidence": "High",
        "relationship_rule_id": "container_contains:pkcs12",
        "created_by": "crypto_inventory.pkcs12",
        "scan_id": "scan-1",
        "repeatable": True,
    }
    kwargs.update(overrides)
    return build_relationship(known_ids, **kwargs)


def _corresponds(universe, known_ids, reverse: bool = False, **overrides) -> CryptoRelationship:
    endpoints = [universe["certificate"].finding_id, universe["private_key"].finding_id]
    if reverse:
        endpoints.reverse()
    kwargs = {
        "relationship_type": RelationshipType.CORRESPONDS_TO,
        "source_finding_id": endpoints[0],
        "target_finding_id": endpoints[1],
        "evidence": CORRESPONDS_EVIDENCE,
        "confidence": "High",
        "relationship_rule_id": "key_match:public_key_fingerprint",
        "created_by": "crypto_inventory.keypair",
        "scan_id": "scan-1",
        "repeatable": True,
    }
    kwargs.update(overrides)
    return build_relationship(known_ids, **kwargs)


# --------------------------------------------------------------------------
# Vocabulary
# --------------------------------------------------------------------------


def test_relationship_vocabulary_is_fixed():
    assert [member.value for member in RelationshipType] == EXPECTED_RELATIONSHIP_TYPES


def test_every_relationship_type_declares_exactly_one_direction_behavior():
    assert DIRECTIONAL_RELATIONSHIP_TYPES | SYMMETRIC_RELATIONSHIP_TYPES == set(
        RelationshipType
    )
    assert not DIRECTIONAL_RELATIONSHIP_TYPES & SYMMETRIC_RELATIONSHIP_TYPES
    assert {member.value for member in SYMMETRIC_RELATIONSHIP_TYPES} == {"corresponds_to"}


@pytest.mark.parametrize("relationship_type", REJECTED_RELATIONSHIP_TYPES)
def test_vague_relationship_types_are_rejected(universe, known_ids, relationship_type):
    with pytest.raises(UnknownRelationshipTypeError):
        _contains(universe, known_ids, relationship_type=relationship_type)


@pytest.mark.parametrize("relationship_type", ["CONTAINS", "Contains", "contains ", "", 5, None])
def test_invalid_relationship_type_values_are_rejected(universe, known_ids, relationship_type):
    with pytest.raises(UnknownRelationshipTypeError):
        _contains(universe, known_ids, relationship_type=relationship_type)


def test_invalid_relationship_type_is_a_distinguishable_outcome(universe, known_ids):
    collection = collect_relationships(
        [
            {
                "relationship_type": "depends_on",
                "source_finding_id": universe["container"].finding_id,
                "target_finding_id": universe["certificate"].finding_id,
                "evidence": CONTAINS_EVIDENCE,
                "confidence": "High",
                "relationship_rule_id": "container_contains:pkcs12",
                "scan_id": "scan-1",
            }
        ],
        known_ids,
    )
    assert collection.outcomes == (RelationshipOutcome.INVALID_TYPE,)
    assert collection.relationships == ()


# --------------------------------------------------------------------------
# Endpoints
# --------------------------------------------------------------------------


def test_valid_relationship_references_two_known_findings(universe, known_ids):
    relationship = _contains(universe, known_ids)
    assert relationship.source_finding_id == universe["container"].finding_id
    assert relationship.target_finding_id == universe["certificate"].finding_id
    validate_endpoints(relationship, known_ids)


def test_dangling_source_endpoint_is_rejected(universe, known_ids):
    with pytest.raises(MissingEndpointError):
        _contains(universe, known_ids, source_finding_id="a" * 64)


def test_dangling_target_endpoint_is_rejected(universe, known_ids):
    with pytest.raises(MissingEndpointError):
        _contains(universe, known_ids, target_finding_id="b" * 64)


def test_dangling_relationship_is_a_distinguishable_outcome(universe, known_ids):
    unknown = _finding("/tmp/other.pem", "PEM Certificate")
    collection = collect_relationships(
        [
            {
                "relationship_type": RelationshipType.CONTAINS,
                "source_finding_id": universe["container"].finding_id,
                "target_finding_id": unknown.finding_id,
                "evidence": CONTAINS_EVIDENCE,
                "confidence": "High",
                "relationship_rule_id": "container_contains:pkcs12",
                "scan_id": "scan-1",
            }
        ],
        known_ids,
    )
    assert collection.outcomes == (RelationshipOutcome.MISSING_ENDPOINT,)
    assert collection.relationships == ()


def test_relationships_do_not_create_synthetic_assets(universe, known_ids):
    relationship = _contains(universe, known_ids)
    assert {relationship.source_finding_id, relationship.target_finding_id} <= known_ids
    # Endpoints are references, not embedded assets: nothing on the relationship
    # carries an asset type, location, or any other finding field.
    field_names = {model_field.name for model_field in fields(CryptoRelationship)}
    assert not field_names & {"asset_type", "location", "asset_name", "source_type"}


@pytest.mark.parametrize("endpoint", ["/tmp/bundle.p12", "not-a-hash", "", "A" * 64, 7])
def test_endpoints_must_be_stable_finding_ids(universe, known_ids, endpoint):
    with pytest.raises(MalformedRelationshipError):
        _contains(universe, known_ids, source_finding_id=endpoint)


def test_self_relationship_is_rejected(universe, known_ids):
    with pytest.raises(SelfRelationshipError):
        _contains(
            universe,
            known_ids,
            target_finding_id=universe["container"].finding_id,
        )


def test_self_relationship_is_a_distinguishable_outcome(universe, known_ids):
    same = universe["certificate"].finding_id
    collection = collect_relationships(
        [
            {
                "relationship_type": RelationshipType.CORRESPONDS_TO,
                "source_finding_id": same,
                "target_finding_id": same,
                "evidence": CORRESPONDS_EVIDENCE,
                "confidence": "High",
                "relationship_rule_id": "key_match:public_key_fingerprint",
                "scan_id": "scan-1",
            }
        ],
        known_ids,
    )
    assert collection.outcomes == (RelationshipOutcome.SELF_RELATIONSHIP,)
    assert collection.relationships == ()


# --------------------------------------------------------------------------
# Direction and symmetry
# --------------------------------------------------------------------------


def test_directional_relationship_preserves_direction(universe, known_ids):
    forward = _contains(universe, known_ids)
    assert forward.source_finding_id == universe["container"].finding_id
    assert forward.target_finding_id == universe["certificate"].finding_id
    assert not forward.is_symmetric


def test_reversing_directional_endpoints_changes_identity(universe, known_ids):
    forward = _contains(universe, known_ids)
    reversed_relationship = _contains(
        universe,
        known_ids,
        source_finding_id=universe["certificate"].finding_id,
        target_finding_id=universe["container"].finding_id,
    )
    assert forward.relationship_id != reversed_relationship.relationship_id


def test_symmetric_relationship_canonicalizes_endpoint_order(universe, known_ids):
    forward = _corresponds(universe, known_ids)
    backward = _corresponds(universe, known_ids, reverse=True)
    assert forward.source_finding_id == backward.source_finding_id
    assert forward.target_finding_id == backward.target_finding_id
    assert forward.source_finding_id < forward.target_finding_id
    assert forward.is_symmetric


def test_reversing_symmetric_endpoints_preserves_identity(universe, known_ids):
    assert (
        _corresponds(universe, known_ids).relationship_id
        == _corresponds(universe, known_ids, reverse=True).relationship_id
    )


def test_canonical_endpoints_only_sorts_symmetric_types():
    assert canonical_endpoints(RelationshipType.CONTAINS, "b" * 64, "a" * 64) == (
        "b" * 64,
        "a" * 64,
    )
    assert canonical_endpoints(RelationshipType.CORRESPONDS_TO, "b" * 64, "a" * 64) == (
        "a" * 64,
        "b" * 64,
    )


# --------------------------------------------------------------------------
# Deterministic identity
# --------------------------------------------------------------------------


def test_repeated_construction_produces_the_same_id(universe, known_ids):
    ids = {_contains(universe, known_ids).relationship_id for _ in range(5)}
    assert len(ids) == 1


def test_identity_uses_only_type_endpoints_and_rule_id(universe, known_ids):
    relationship = _contains(universe, known_ids)
    assert relationship.relationship_id == derive_relationship_id(
        RelationshipType.CONTAINS,
        universe["container"].finding_id,
        universe["certificate"].finding_id,
        "container_contains:pkcs12",
    )


@pytest.mark.parametrize(
    "overrides",
    [
        {"observed_at": "2020-01-01T00:00:00+00:00"},
        {"scan_id": "some-other-scan"},
        {"evidence": "Parsed PKCS#12 container directly contains the certificate object"},
        {"confidence": "Medium"},
        {"confidence": "Low"},
        {"created_by": "some.other.component"},
        {"repeatable": False},
        {"limitations": ("container entry order was not recorded",)},
        {"errors": ("one container entry could not be parsed",)},
    ],
    ids=[
        "timestamp",
        "scan_id",
        "evidence_prose",
        "confidence_medium",
        "confidence_low",
        "provenance_component",
        "repeatability",
        "limitations",
        "errors",
    ],
)
def test_identity_excludes_volatile_fields(universe, known_ids, overrides):
    assert (
        _contains(universe, known_ids, **overrides).relationship_id
        == _contains(universe, known_ids).relationship_id
    )


def test_identity_changes_with_relationship_type(universe, known_ids):
    contains = _contains(universe, known_ids)
    references = _contains(
        universe, known_ids, relationship_type=RelationshipType.REFERENCES
    )
    assert contains.relationship_id != references.relationship_id


def test_identity_changes_with_rule_id(universe, known_ids):
    other_rule = _contains(universe, known_ids, relationship_rule_id="container_contains:jks")
    assert other_rule.relationship_id != _contains(universe, known_ids).relationship_id


def test_a_supplied_relationship_id_must_match_the_derived_identity(universe, known_ids):
    derived = _contains(universe, known_ids).relationship_id
    assert _contains(universe, known_ids, relationship_id=derived).relationship_id == derived
    with pytest.raises(MalformedRelationshipError):
        _contains(universe, known_ids, relationship_id="c" * 64)


# --------------------------------------------------------------------------
# Deduplication
# --------------------------------------------------------------------------


def test_duplicate_relationships_deduplicate_to_one_canonical_record(universe, known_ids):
    duplicates = [_contains(universe, known_ids) for _ in range(4)]
    deduplicated = deduplicate_relationships(duplicates)
    assert len(deduplicated) == 1
    assert deduplicated[0].relationship_id == duplicates[0].relationship_id


def test_reversed_symmetric_observations_deduplicate(universe, known_ids):
    deduplicated = deduplicate_relationships(
        [_corresponds(universe, known_ids), _corresponds(universe, known_ids, reverse=True)]
    )
    assert len(deduplicated) == 1


def test_different_relationship_types_do_not_deduplicate(universe, known_ids):
    deduplicated = deduplicate_relationships(
        [
            _contains(universe, known_ids),
            _contains(universe, known_ids, relationship_type=RelationshipType.REFERENCES),
        ]
    )
    assert len(deduplicated) == 2


def test_different_rule_ids_do_not_deduplicate(universe, known_ids):
    deduplicated = deduplicate_relationships(
        [
            _contains(universe, known_ids),
            _contains(universe, known_ids, relationship_rule_id="container_contains:jks"),
        ]
    )
    assert len(deduplicated) == 2


def test_reversed_directional_observations_do_not_deduplicate(universe, known_ids):
    deduplicated = deduplicate_relationships(
        [
            _contains(universe, known_ids),
            _contains(
                universe,
                known_ids,
                source_finding_id=universe["certificate"].finding_id,
                target_finding_id=universe["container"].finding_id,
            ),
        ]
    )
    assert len(deduplicated) == 2


def test_duplicate_is_a_distinguishable_outcome(universe, known_ids):
    relationship = _contains(universe, known_ids)
    collection = collect_relationships([relationship, relationship], known_ids)
    assert collection.outcomes == (
        RelationshipOutcome.VALID,
        RelationshipOutcome.DUPLICATE,
    )
    assert len(collection.relationships) == 1
    assert collection.counts()["duplicate"] == 1


def test_duplicate_suppression_keeps_deterministic_evidence_wording(universe, known_ids):
    first = _contains(universe, known_ids)
    second = _contains(
        universe,
        known_ids,
        evidence="Parsed PKCS#12 container directly contains the certificate object",
    )
    deduplicated = deduplicate_relationships([first, second])
    assert len(deduplicated) == 1
    # One canonical record, no evidence-history aggregation in HG-034: the
    # surviving evidence is one of the observed wordings verbatim, never a merge.
    assert deduplicated[0].evidence in {first.evidence, second.evidence}
    assert deduplicated[0] in {first, second}


# The volatile fields two same-identity candidates can disagree on. Selecting a
# canonical record must not depend on which of them arrived first, so each pair
# below is deduplicated in both orders.
DIVERGENT_DUPLICATE_OVERRIDES = [
    {"evidence": "Parsed PKCS#12 container directly contains the certificate object"},
    {"confidence": "Medium"},
    {"created_by": "crypto_inventory.other"},
    {"scan_id": "scan-2"},
    {"observed_at": "2020-01-01T00:00:00+00:00"},
    {"repeatable": False},
    {"limitations": ("container entry order was not recorded",)},
    {"errors": ("one container entry could not be parsed",)},
]


@pytest.mark.parametrize("overrides", DIVERGENT_DUPLICATE_OVERRIDES)
def test_duplicate_selection_is_independent_of_input_order(universe, known_ids, overrides):
    first = _contains(universe, known_ids)
    second = _contains(universe, known_ids, **overrides)
    assert first.relationship_id == second.relationship_id
    assert first != second

    forward = deduplicate_relationships([first, second])
    reversed_order = deduplicate_relationships([second, first])
    assert len(forward) == len(reversed_order) == 1
    # The same record, field for field -- not merely the same identity.
    assert forward[0] == reversed_order[0]


@pytest.mark.parametrize("overrides", DIVERGENT_DUPLICATE_OVERRIDES)
def test_collect_relationships_selects_the_same_record_in_either_order(
    universe, known_ids, overrides
):
    first = _contains(universe, known_ids)
    second = _contains(universe, known_ids, **overrides)
    forward = collect_relationships([first, second], known_ids)
    reversed_order = collect_relationships([second, first], known_ids)
    assert forward.relationships == reversed_order.relationships
    # Outcomes stay positional: the first arrival of an identity is valid and the
    # later repeat is a duplicate, whichever record is retained.
    assert forward.outcomes == reversed_order.outcomes == (
        RelationshipOutcome.VALID,
        RelationshipOutcome.DUPLICATE,
    )


def test_every_non_identity_field_is_covered_by_canonical_selection(universe, known_ids):
    """Order-independent selection has to consider every field duplicates can
    differ on, so a new field must extend the tie-break key -- otherwise two
    records differing only in that field would tie and input order would decide
    again."""
    identity_fields = {
        "relationship_type",
        "source_finding_id",
        "target_finding_id",
        "relationship_rule_id",
        "relationship_id",
    }
    volatile_fields = {
        model_field.name for model_field in fields(CryptoRelationship)
    } - identity_fields
    covered = {name for overrides in DIVERGENT_DUPLICATE_OVERRIDES for name in overrides}
    assert covered == volatile_fields

    baseline = _contains(universe, known_ids)
    for overrides in DIVERGENT_DUPLICATE_OVERRIDES:
        divergent = _contains(universe, known_ids, **overrides)
        assert canonical_record_key(divergent) != canonical_record_key(baseline)


def test_canonical_duplicate_selection_is_stable_across_shuffles(universe, known_ids):
    variants = [_contains(universe, known_ids)] + [
        _contains(universe, known_ids, **overrides)
        for overrides in DIVERGENT_DUPLICATE_OVERRIDES
    ]
    expected = deduplicate_relationships(variants)
    assert len(expected) == 1
    shuffler = random.Random(20260805)
    for _ in range(10):
        shuffled = list(variants)
        shuffler.shuffle(shuffled)
        assert deduplicate_relationships(shuffled) == expected
        assert collect_relationships(shuffled, known_ids).relationships == expected


def test_relationship_ordering_is_deterministic(universe, known_ids):
    relationships = [
        _contains(universe, known_ids),
        _contains(universe, known_ids, relationship_type=RelationshipType.REFERENCES),
        _contains(universe, known_ids, relationship_rule_id="container_contains:jks"),
        _corresponds(universe, known_ids),
        _corresponds(universe, known_ids, reverse=True),
    ]
    expected = deduplicate_relationships(relationships)
    shuffler = random.Random(20260804)
    for _ in range(5):
        shuffled = list(relationships)
        shuffler.shuffle(shuffled)
        assert [r.relationship_id for r in deduplicate_relationships(shuffled)] == [
            r.relationship_id for r in expected
        ]


def test_large_duplicate_set_deduplicates_without_changing_semantics(universe, known_ids):
    distinct = [
        _contains(universe, known_ids),
        _contains(universe, known_ids, relationship_type=RelationshipType.REFERENCES),
        _contains(universe, known_ids, relationship_rule_id="container_contains:jks"),
        _corresponds(universe, known_ids),
    ]
    # No performance claim is made or implied here: this asserts semantics only.
    collection = collect_relationships(distinct * 250, known_ids)
    assert [r.relationship_id for r in collection.relationships] == [
        r.relationship_id for r in deduplicate_relationships(distinct)
    ]
    counts = collection.counts()
    assert counts["valid"] == 4
    assert counts["duplicate"] == 996


def test_empty_relationship_collections_behave_cleanly():
    assert deduplicate_relationships([]) == ()
    collection = collect_relationships([], frozenset())
    assert collection == RelationshipCollection()
    assert collection.relationships == ()
    assert collection.outcomes == ()
    assert collection.rejections == ()
    assert not collection.has_model_errors
    assert set(collection.counts().values()) == {0}


# --------------------------------------------------------------------------
# Evidence, confidence, provenance
# --------------------------------------------------------------------------


@pytest.mark.parametrize("evidence", ["", "   ", None, 7, "x" * (MAX_TEXT_FIELD_CHARS + 1)])
def test_evidence_is_required(universe, known_ids, evidence):
    with pytest.raises(MalformedRelationshipError):
        _contains(universe, known_ids, evidence=evidence)


@pytest.mark.parametrize(
    "evidence",
    [
        "Certificate and key are in the same directory",
        "Filenames are similar, so the key matches the certificate",
        "Matching basename observed between the certificate and the key",
        "The key probably belongs to this certificate",
        "The certificate likely corresponds to this key",
        "Assumed keypair based on the file extension",
        "Inferred application dependency between the manifest and the key",
    ],
)
def test_inference_wording_is_rejected(universe, known_ids, evidence):
    with pytest.raises(MalformedRelationshipError):
        _contains(universe, known_ids, evidence=evidence)


@pytest.mark.parametrize(
    "evidence",
    [
        "Container holds a trusted certificate",
        "Certificate chain is valid, so the key is secure",
        "Weak key material observed in the container entry",
        "This container relationship raises quantum risk",
        "The relationship indicates a compliance gap",
        "Container ownership confirmed for this certificate",
        "High business impact relationship between container and certificate",
        "Remediation of the container entry is required",
    ],
)
def test_assessment_claims_in_evidence_are_rejected(universe, known_ids, evidence):
    with pytest.raises(MalformedRelationshipError):
        _contains(universe, known_ids, evidence=evidence)


def test_structural_evidence_wording_is_accepted(universe, known_ids):
    for evidence in (CONTAINS_EVIDENCE, CORRESPONDS_EVIDENCE, ISSUED_BY_EVIDENCE):
        assert _contains(universe, known_ids, evidence=evidence).evidence == evidence


@pytest.mark.parametrize("confidence", SUPPORTED_RELATIONSHIP_CONFIDENCE)
def test_supported_confidence_values_are_accepted(universe, known_ids, confidence):
    assert _contains(universe, known_ids, confidence=confidence).confidence == confidence


@pytest.mark.parametrize(
    "confidence", ["Certain", "high", "HIGH", "", None, 1.0, True, "Very High"]
)
def test_invalid_confidence_is_rejected(universe, known_ids, confidence):
    with pytest.raises(MalformedRelationshipError):
        _contains(universe, known_ids, confidence=confidence)


def test_high_confidence_fixtures_are_direct_structural_relationships(universe, known_ids):
    # HG-034 exercises High confidence only where the evidence is direct
    # structural proof: container containment and matching public key material.
    for relationship in (_contains(universe, known_ids), _corresponds(universe, known_ids)):
        assert relationship.confidence == "High"
        assert "directly contains" in relationship.evidence or "matches" in relationship.evidence


def test_provenance_is_present_and_safe(universe, known_ids):
    relationship = _contains(universe, known_ids)
    provenance = relationship.provenance
    assert provenance.created_by == "crypto_inventory.pkcs12"
    assert provenance.relationship_rule_id == "container_contains:pkcs12"
    assert provenance.scan_id == "scan-1"
    assert provenance.repeatable is True
    assert provenance.collected_at
    assert provenance.collected_at.startswith("20")


def test_default_provenance_component_is_the_relationship_model(universe, known_ids):
    relationship = _contains(universe, known_ids, created_by=RELATIONSHIP_MODEL_COMPONENT)
    assert relationship.created_by == RELATIONSHIP_MODEL_COMPONENT
    assert CryptoRelationship.created_by == RELATIONSHIP_MODEL_COMPONENT


def test_repeatability_is_represented_and_must_be_boolean(universe, known_ids):
    assert _contains(universe, known_ids, repeatable=True).repeatable is True
    assert _contains(universe, known_ids, repeatable=False).repeatable is False
    for value in ("yes", 1, None):
        with pytest.raises(MalformedRelationshipError):
            _contains(universe, known_ids, repeatable=value)


def test_observed_at_defaults_to_a_collection_timestamp(universe, known_ids):
    relationship = _contains(universe, known_ids, observed_at=None)
    assert relationship.observed_at and relationship.observed_at.endswith("+00:00")
    # Always a real timestamp, whether defaulted or supplied.
    assert datetime.fromisoformat(relationship.observed_at).tzinfo is not None


@pytest.mark.parametrize(
    "value, expected",
    [
        ("2026-08-04T12:30:05+00:00", "2026-08-04T12:30:05+00:00"),
        ("2026-08-04T12:30:05Z", "2026-08-04T12:30:05+00:00"),
        ("2026-08-04T12:30:05.123456+00:00", "2026-08-04T12:30:05+00:00"),
        ("2026-08-04T12:30:05", "2026-08-04T12:30:05+00:00"),
        (datetime(2026, 8, 4, 12, 30, 5, tzinfo=timezone.utc), "2026-08-04T12:30:05+00:00"),
        (datetime(2026, 8, 4, 12, 30, 5), "2026-08-04T12:30:05+00:00"),
    ],
)
def test_observed_at_accepts_and_normalizes_iso_timestamps(
    universe, known_ids, value, expected
):
    assert _contains(universe, known_ids, observed_at=value).observed_at == expected


@pytest.mark.parametrize(
    "value",
    [
        "recently",
        "scan time unknown",
        "2026-08-04",
        "04/08/2026 12:30",
        "not-a-timestamp",
        "2026-13-40T99:99:99+00:00",
        "",
        "   ",
        7,
        1754308205,
    ],
)
def test_arbitrary_observed_at_strings_are_rejected(universe, known_ids, value):
    with pytest.raises(MalformedRelationshipError):
        _contains(universe, known_ids, observed_at=value)


def test_scan_context_is_required(universe, known_ids):
    kwargs = {
        "relationship_type": RelationshipType.CONTAINS,
        "source_finding_id": universe["container"].finding_id,
        "target_finding_id": universe["certificate"].finding_id,
        "evidence": CONTAINS_EVIDENCE,
        "confidence": "High",
        "relationship_rule_id": "container_contains:pkcs12",
    }
    # Omitting the scan context is not a relationship with unknown provenance;
    # there is no such record to construct.
    with pytest.raises(TypeError):
        build_relationship(known_ids, **kwargs)
    assert build_relationship(known_ids, scan_id="scan-1", **kwargs).scan_id == "scan-1"


@pytest.mark.parametrize("scan_id", [None, "", "   ", "scan 1", "scan;1", 5])
def test_invalid_scan_context_is_rejected(universe, known_ids, scan_id):
    with pytest.raises(MalformedRelationshipError):
        _contains(universe, known_ids, scan_id=scan_id)


def test_missing_scan_context_candidate_is_a_malformed_outcome(universe, known_ids):
    collection = collect_relationships(
        [
            {
                "relationship_type": RelationshipType.CONTAINS,
                "source_finding_id": universe["container"].finding_id,
                "target_finding_id": universe["certificate"].finding_id,
                "evidence": CONTAINS_EVIDENCE,
                "confidence": "High",
                "relationship_rule_id": "container_contains:pkcs12",
            },
            {
                "relationship_type": RelationshipType.CONTAINS,
                "source_finding_id": universe["container"].finding_id,
                "target_finding_id": universe["certificate"].finding_id,
                "evidence": CONTAINS_EVIDENCE,
                "confidence": "High",
                "relationship_rule_id": "container_contains:pkcs12",
                "scan_id": "scan-1",
                "observed_at": "sometime during the scan",
            },
        ],
        known_ids,
    )
    assert collection.outcomes == (
        RelationshipOutcome.MALFORMED,
        RelationshipOutcome.MALFORMED,
    )
    assert collection.relationships == ()


@pytest.mark.parametrize("rule_id", ["", "   ", None, "contains certificates", "rule;drop", 5])
def test_relationship_rule_id_must_be_a_machine_identifier(universe, known_ids, rule_id):
    with pytest.raises(MalformedRelationshipError):
        _contains(universe, known_ids, relationship_rule_id=rule_id)


def test_limitations_and_errors_accept_only_safe_text(universe, known_ids):
    relationship = _contains(
        universe,
        known_ids,
        limitations=("container entry order was not recorded",),
        errors=("one container entry could not be parsed",),
    )
    assert relationship.limitations == ("container entry order was not recorded",)
    assert relationship.errors == ("one container entry could not be parsed",)
    for bad in ("a string, not a sequence", {"key": "value"}, [""], [None]):
        with pytest.raises(MalformedRelationshipError):
            _contains(universe, known_ids, limitations=bad)


# --------------------------------------------------------------------------
# Privacy boundary and immutability
# --------------------------------------------------------------------------


RAW_MATERIAL_SAMPLES = [
    "-----BEGIN PRIVATE KEY-----MIIEvQIBADANBg",
    "-----BEGIN CERTIFICATE-----MIIDdzCCAl+gAw",
    "-----BEGIN PGP MESSAGE-----hQEMA0Ab",
    "Salted__\x01\x02",
    "PuTTY-User-Key-File-2: ssh-rsa",
]


@pytest.mark.parametrize("payload", RAW_MATERIAL_SAMPLES)
def test_raw_cryptographic_material_is_rejected_from_evidence(universe, known_ids, payload):
    with pytest.raises(MalformedRelationshipError):
        _contains(universe, known_ids, evidence=payload)


@pytest.mark.parametrize("payload", RAW_MATERIAL_SAMPLES)
def test_raw_cryptographic_material_is_rejected_from_limitations_and_errors(
    universe, known_ids, payload
):
    with pytest.raises(MalformedRelationshipError):
        _contains(universe, known_ids, limitations=(payload,))
    with pytest.raises(MalformedRelationshipError):
        _contains(universe, known_ids, errors=(payload,))


def test_relationship_has_no_metadata_or_free_form_field():
    annotations = {
        model_field.name: str(model_field.type) for model_field in fields(CryptoRelationship)
    }
    assert not any(
        "dict" in annotation or "Mapping" in annotation or "Any" in annotation
        for annotation in annotations.values()
    )
    assert not {"technical_metadata", "metadata", "details", "raw", "payload"} & set(annotations)


@pytest.mark.parametrize(
    "extra",
    [
        {"technical_metadata": {"Private Key": "secret"}},
        {"metadata": {"passphrase": "hunter2"}},
        {"raw_config": "cipherdir contents"},
        {"packet_body": b"\x85\x01\x0c"},
    ],
)
def test_unknown_metadata_cannot_be_attached(universe, known_ids, extra):
    # An unknown keyword is a malformed candidate, not a model defect: there is no
    # metadata field to absorb it. That the keyword *name* cannot reach the
    # rejection text is pinned by
    # `test_secret_bearing_unknown_keys_do_not_leak_into_rejections`.
    with pytest.raises(MalformedRelationshipError):
        _contains(universe, known_ids, **extra)


def test_unknown_metadata_candidate_is_a_malformed_outcome(universe, known_ids):
    collection = collect_relationships(
        [
            {
                "relationship_type": RelationshipType.CONTAINS,
                "source_finding_id": universe["container"].finding_id,
                "target_finding_id": universe["certificate"].finding_id,
                "evidence": CONTAINS_EVIDENCE,
                "confidence": "High",
                "relationship_rule_id": "container_contains:pkcs12",
                "scan_id": "scan-1",
                "technical_metadata": {"passphrase": "hunter2"},
            }
        ],
        known_ids,
    )
    assert collection.outcomes == (RelationshipOutcome.MALFORMED,)
    assert collection.relationships == ()
    assert "hunter2" not in " ".join(collection.rejections)


# A rejected candidate value is untrusted content: a defective caller could pass
# a passphrase, a key fragment, a config line, or a parser payload where an
# identifier, a confidence, a timestamp, or a finding ID belonged. Validation
# messages and `RelationshipCollection.rejections` must therefore name the
# refused field only -- these tokens stand in for whatever a caller passed, and
# must not survive anywhere in a rejection.
LEAK_SENTINEL = "hunter2 TOP-SECRET-PASSPHRASE"
LEAK_SENTINEL_TOKENS = ("hunter2", "TOP-SECRET-PASSPHRASE")

# One entry per field that can refuse a value. The sentinel is invalid for every
# one of them: it is outside both closed vocabularies, is not a machine
# identifier, is not a 64-hex finding ID, and is not an ISO-8601 date-time.
LEAKABLE_FIELDS = [
    "relationship_type",
    "confidence",
    "scan_id",
    "relationship_rule_id",
    "created_by",
    "source_finding_id",
    "target_finding_id",
    "observed_at",
]


def _assert_no_sentinel(text: str) -> None:
    for token in LEAK_SENTINEL_TOKENS:
        assert token not in text
        assert token.lower() not in text.lower()


@pytest.mark.parametrize("field", LEAKABLE_FIELDS)
def test_rejected_candidate_values_do_not_leak_into_exceptions(universe, known_ids, field):
    with pytest.raises(RelationshipValidationError) as excinfo:
        _contains(universe, known_ids, **{field: LEAK_SENTINEL})
    # The field name is enough to locate the caller's defect; the value is not.
    assert field in str(excinfo.value)
    _assert_no_sentinel(str(excinfo.value))
    _assert_no_sentinel(repr(excinfo.value))


@pytest.mark.parametrize("field", LEAKABLE_FIELDS)
def test_rejected_candidate_values_do_not_leak_into_rejections(universe, known_ids, field):
    base = {
        "relationship_type": RelationshipType.CONTAINS,
        "source_finding_id": universe["container"].finding_id,
        "target_finding_id": universe["certificate"].finding_id,
        "evidence": CONTAINS_EVIDENCE,
        "confidence": "High",
        "relationship_rule_id": "container_contains:pkcs12",
        "scan_id": "scan-1",
    }
    collection = collect_relationships([{**base, field: LEAK_SENTINEL}], known_ids)
    assert collection.relationships == ()
    assert collection.outcomes != (RelationshipOutcome.VALID,)
    assert collection.rejections
    _assert_no_sentinel(" ".join(collection.rejections))


def test_secret_bearing_unknown_keys_do_not_leak_into_rejections(universe, known_ids):
    """A candidate mapping's *keys* are untrusted caller text too.

    A defective caller can just as easily pass a passphrase as a keyword *name* as
    it can pass one as a value. Left to the dataclass, that name comes back inside
    a ``TypeError`` quoting it verbatim, which `collect_relationships` would then
    retain as rejection text -- so an unrecognized keyword must be refused by count
    rather than by name.
    """
    base = {
        "relationship_type": RelationshipType.CONTAINS,
        "source_finding_id": universe["container"].finding_id,
        "target_finding_id": universe["certificate"].finding_id,
        "evidence": CONTAINS_EVIDENCE,
        "confidence": "High",
        "relationship_rule_id": "container_contains:pkcs12",
        "scan_id": "scan-1",
    }
    collection = collect_relationships(
        [
            {**base, LEAK_SENTINEL: "attached anyway"},
            {**base, LEAK_SENTINEL: {"nested": LEAK_SENTINEL}},
            # An otherwise-valid candidate whose only defect is the extra keyword
            # must still be refused: there is no metadata field to absorb it.
            {**base, "passphrase": LEAK_SENTINEL},
        ],
        known_ids,
    )
    assert collection.outcomes == (RelationshipOutcome.MALFORMED,) * 3
    assert collection.relationships == ()
    assert collection.rejections
    _assert_no_sentinel(" ".join(collection.rejections))

    with pytest.raises(MalformedRelationshipError) as excinfo:
        _contains(universe, known_ids, **{LEAK_SENTINEL: "attached anyway"})
    _assert_no_sentinel(str(excinfo.value))
    _assert_no_sentinel(repr(excinfo.value))


# Direct `CryptoRelationship(...)` construction is a boundary of its own:
# `build_relationship` prevalidates its keywords, but a caller constructing the
# dataclass directly would otherwise reach the generated `__init__`, whose raw
# `TypeError` quotes the unknown keyword name verbatim. These tests pin the
# `_RejectsUnknownKeywords` metaclass boundary that closes that path.


def _valid_direct_kwargs(universe):
    return {
        "relationship_type": RelationshipType.CONTAINS,
        "source_finding_id": universe["container"].finding_id,
        "target_finding_id": universe["certificate"].finding_id,
        "evidence": CONTAINS_EVIDENCE,
        "confidence": "High",
        "relationship_rule_id": "container_contains:pkcs12",
        "scan_id": "scan-1",
    }


def test_direct_construction_with_unknown_secret_key_is_malformed_and_leak_free(universe):
    with pytest.raises(MalformedRelationshipError) as excinfo:
        CryptoRelationship(**{**_valid_direct_kwargs(universe), LEAK_SENTINEL: "attached"})
    # Neither the secret-shaped keyword name nor its value survives into the
    # exception's str() or repr().
    _assert_no_sentinel(str(excinfo.value))
    _assert_no_sentinel(repr(excinfo.value))
    assert "attached" not in str(excinfo.value)
    assert "attached" not in repr(excinfo.value)


def test_direct_construction_with_multiple_unknown_keys_reports_count_only(universe):
    with pytest.raises(MalformedRelationshipError) as excinfo:
        CryptoRelationship(
            **{
                **_valid_direct_kwargs(universe),
                LEAK_SENTINEL: "one",
                "passphrase": LEAK_SENTINEL,
            }
        )
    message = str(excinfo.value)
    # Reported by count alone: the number appears, the names and values do not.
    assert "2" in message
    assert "passphrase" not in message
    assert "one" not in message
    _assert_no_sentinel(message)
    _assert_no_sentinel(repr(excinfo.value))


def test_direct_positional_construction_still_works(universe):
    kwargs = _valid_direct_kwargs(universe)
    positional = CryptoRelationship(
        kwargs["relationship_type"],
        kwargs["source_finding_id"],
        kwargs["target_finding_id"],
        kwargs["evidence"],
        kwargs["confidence"],
        kwargs["relationship_rule_id"],
        kwargs["scan_id"],
    )
    by_keyword = CryptoRelationship(**kwargs)
    # The metaclass boundary changes nothing about valid construction: the two
    # spellings produce equal records with the same deterministic identity, and
    # frozen-dataclass semantics survive.
    assert positional == by_keyword
    assert hash(positional) == hash(by_keyword)
    assert positional.relationship_id == by_keyword.relationship_id
    with pytest.raises(FrozenInstanceError):
        positional.evidence = "mutated"


def test_direct_keyword_construction_still_works(universe):
    relationship = CryptoRelationship(**_valid_direct_kwargs(universe))
    assert relationship.relationship_type is RelationshipType.CONTAINS
    assert relationship.relationship_id is not None
    assert {model_field.name for model_field in fields(CryptoRelationship)} >= set(
        _valid_direct_kwargs(universe)
    )


def test_build_relationship_still_works_after_constructor_boundary(universe, known_ids):
    relationship = _contains(universe, known_ids)
    assert relationship.relationship_id is not None


def test_collect_relationships_still_classifies_unknown_key_mappings_as_malformed(
    universe, known_ids
):
    collection = collect_relationships(
        [{**_valid_direct_kwargs(universe), LEAK_SENTINEL: "attached"}], known_ids
    )
    assert collection.outcomes == (RelationshipOutcome.MALFORMED,)
    assert collection.relationships == ()
    _assert_no_sentinel(" ".join(collection.rejections))


@pytest.mark.parametrize(
    "evidence",
    [
        f"{LEAK_SENTINEL} was found in the same directory as the certificate",
        f"The container probably holds {LEAK_SENTINEL}",
        f"Container relationship carries business impact for {LEAK_SENTINEL}",
    ],
)
def test_rejected_evidence_prose_does_not_leak_into_rejections(
    universe, known_ids, evidence
):
    with pytest.raises(MalformedRelationshipError) as excinfo:
        _contains(universe, known_ids, evidence=evidence)
    _assert_no_sentinel(str(excinfo.value))
    collection = collect_relationships(
        [
            {
                "relationship_type": RelationshipType.CONTAINS,
                "source_finding_id": universe["container"].finding_id,
                "target_finding_id": universe["certificate"].finding_id,
                "evidence": evidence,
                "confidence": "High",
                "relationship_rule_id": "container_contains:pkcs12",
                "scan_id": "scan-1",
            }
        ],
        known_ids,
    )
    assert collection.outcomes == (RelationshipOutcome.MALFORMED,)
    _assert_no_sentinel(" ".join(collection.rejections))


@pytest.mark.parametrize("payload", RAW_MATERIAL_SAMPLES)
def test_rejected_raw_material_does_not_leak_into_rejections(universe, known_ids, payload):
    for field in ("evidence", "scan_id", "relationship_rule_id"):
        with pytest.raises(MalformedRelationshipError) as excinfo:
            _contains(universe, known_ids, **{field: payload})
        assert payload not in str(excinfo.value)
    collection = collect_relationships(
        [
            {
                "relationship_type": RelationshipType.CONTAINS,
                "source_finding_id": universe["container"].finding_id,
                "target_finding_id": universe["certificate"].finding_id,
                "evidence": payload,
                "confidence": "High",
                "relationship_rule_id": "container_contains:pkcs12",
                "scan_id": "scan-1",
            },
            payload,
            (payload,),
        ],
        known_ids,
    )
    assert collection.relationships == ()
    assert payload not in " ".join(collection.rejections)


def test_rejected_limitations_and_errors_do_not_leak_into_exceptions(universe, known_ids):
    for field in ("limitations", "errors"):
        with pytest.raises(MalformedRelationshipError) as excinfo:
            _contains(universe, known_ids, **{field: (LEAK_SENTINEL * 40,)})
        assert field in str(excinfo.value)
        _assert_no_sentinel(str(excinfo.value))


def test_relationship_is_immutable(universe, known_ids):
    relationship = _contains(universe, known_ids)
    with pytest.raises(FrozenInstanceError):
        relationship.confidence = "Low"
    with pytest.raises(FrozenInstanceError):
        relationship.relationship_id = "d" * 64
    assert isinstance(relationship.limitations, tuple)
    assert isinstance(relationship.errors, tuple)


def test_relationship_is_json_compatible_when_converted_in_tests(universe, known_ids):
    payload = json.loads(json.dumps(asdict(_contains(universe, known_ids))))
    assert payload["relationship_type"] == "contains"
    assert payload["confidence"] == "High"


# --------------------------------------------------------------------------
# Validation and error behavior
# --------------------------------------------------------------------------


def test_malformed_candidate_object_is_a_distinguishable_outcome(known_ids):
    collection = collect_relationships(["not a relationship", 42, None], known_ids)
    assert collection.outcomes == (RelationshipOutcome.MALFORMED,) * 3
    assert collection.relationships == ()


class _ExplodingMapping(Mapping):
    """A candidate that fails unexpectedly, standing in for a model/caller defect
    rather than an invalid relationship."""

    def keys(self):
        raise RuntimeError("relationship candidate blew up")

    def __getitem__(self, key):  # pragma: no cover - keys() raises first
        raise KeyError(key)

    def __iter__(self):  # pragma: no cover - keys() raises first
        return iter(())

    def __len__(self) -> int:  # pragma: no cover - keys() raises first
        return 0


def test_unexpected_failure_is_not_silently_absence_of_relationship(known_ids):
    collection = collect_relationships([_ExplodingMapping()], known_ids)
    assert collection.outcomes == (RelationshipOutcome.MODEL_ERROR,)
    assert collection.has_model_errors
    assert collection.relationships == ()
    # Attributed by stage and exception type only -- never the exception message,
    # which could quote content the parser choked on.
    assert "model_error" in collection.rejections[0]
    assert "RuntimeError" in collection.rejections[0]
    assert "blew up" not in collection.rejections[0]


def test_every_validation_outcome_is_distinguishable(universe, known_ids):
    valid = _contains(universe, known_ids)
    unknown = _finding("/tmp/other.pem", "PEM Certificate")
    base = {
        "relationship_type": RelationshipType.CONTAINS,
        "source_finding_id": universe["container"].finding_id,
        "target_finding_id": universe["certificate"].finding_id,
        "evidence": CONTAINS_EVIDENCE,
        "confidence": "High",
        "relationship_rule_id": "container_contains:pkcs12",
        "scan_id": "scan-1",
    }
    collection = collect_relationships(
        [
            valid,
            valid,
            {**base, "target_finding_id": unknown.finding_id},
            {**base, "relationship_type": "related_to"},
            {**base, "target_finding_id": universe["container"].finding_id},
            {**base, "confidence": "Certain"},
            _ExplodingMapping(),
        ],
        known_ids,
    )
    assert collection.outcomes == (
        RelationshipOutcome.VALID,
        RelationshipOutcome.DUPLICATE,
        RelationshipOutcome.MISSING_ENDPOINT,
        RelationshipOutcome.INVALID_TYPE,
        RelationshipOutcome.SELF_RELATIONSHIP,
        RelationshipOutcome.MALFORMED,
        RelationshipOutcome.MODEL_ERROR,
    )
    assert [r.relationship_id for r in collection.relationships] == [valid.relationship_id]


def test_validation_errors_share_one_base_type(universe, known_ids):
    for error in (
        UnknownRelationshipTypeError,
        MissingEndpointError,
        SelfRelationshipError,
        MalformedRelationshipError,
    ):
        assert issubclass(error, RelationshipValidationError)
        assert issubclass(error, ValueError)


# --------------------------------------------------------------------------
# Findings are untouched
# --------------------------------------------------------------------------


def test_relationship_construction_does_not_mutate_findings(universe, known_ids):
    before = [finding.to_dict() for finding in universe.values()]
    _contains(universe, known_ids)
    _corresponds(universe, known_ids)
    collect_relationships([_contains(universe, known_ids)], known_ids)
    assert [finding.to_dict() for finding in universe.values()] == before


def test_relationship_construction_does_not_change_finding_ids(universe, known_ids):
    before = {name: finding.finding_id for name, finding in universe.items()}
    _contains(universe, known_ids)
    _corresponds(universe, known_ids, reverse=True)
    assert {name: finding.finding_id for name, finding in universe.items()} == before
    assert index_finding_ids(universe.values()) == known_ids


def test_index_finding_ids_ignores_everything_but_the_stable_id(universe):
    ids = index_finding_ids(list(universe.values()) + [object()])
    assert ids == {finding.finding_id for finding in universe.values()}
    assert isinstance(ids, frozenset)


def test_normalized_finding_has_no_relationship_fields():
    names = {model_field.name for model_field in fields(NormalizedFinding)}
    assert not any("relationship" in name for name in names)
    finding = _finding("/tmp/bundle.p12", "PKCS#12 Container")
    assert not any("relationship" in key for key in finding.to_dict())


# --------------------------------------------------------------------------
# No public output, no accounting change
# --------------------------------------------------------------------------


PUBLIC_SURFACES = [
    "harvestguard.py",
    "findings.py",
    "finding_adapters.py",
    "reports.py",
    "main.py",
    "scanner/crypto_inventory.py",
    "scanner/crypto_detectors.py",
    "dashboard/visualizations.py",
]


@pytest.mark.parametrize("surface", PUBLIC_SURFACES)
def test_no_public_surface_imports_the_relationship_model(surface):
    source = (REPO_ROOT / surface).read_text(encoding="utf-8")
    assert "crypto_relationships" not in source
    assert "CryptoRelationship" not in source


def test_relationship_model_exposes_no_serialization_path():
    import scanner.crypto_relationships as module

    for name in ("to_dict", "to_record", "to_json", "relationships_to_dicts", "dumps"):
        assert not hasattr(module, name)
        assert not hasattr(CryptoRelationship, name)


def test_relationship_model_implements_no_graph_behavior():
    import scanner.crypto_relationships as module

    source = (REPO_ROOT / "scanner" / "crypto_relationships.py").read_text(encoding="utf-8")
    for library in ("networkx", "igraph", "graph_tool", "neo4j", "rdflib", "graphlib"):
        assert f"import {library}" not in source
    forbidden = ("traverse", "closure", "shortest", "neighbors", "adjacency", "walk_graph")
    for name in dir(module):
        assert not any(term in name.lower() for term in forbidden), name


def test_no_graph_library_dependency_is_declared():
    for manifest in ("requirements.txt", "requirements-dev.txt", "pyproject.toml"):
        text = (REPO_ROOT / manifest).read_text(encoding="utf-8").lower()
        for library in ("networkx", "python-igraph", "graph-tool", "neo4j", "rdflib"):
            assert library not in text


def test_relationship_model_declares_no_asset_types_or_finding_rule_ids():
    source = (REPO_ROOT / "scanner" / "crypto_relationships.py").read_text(encoding="utf-8")
    assert "asset_type" not in source
    assert "Asset Type" not in source
    detector_rule_ids = {
        detector.rule_id for detector in CRYPTO_DETECTORS if detector.rule_id
    }
    for rule_id in detector_rule_ids:
        assert rule_id not in source


def test_relationship_rule_ids_do_not_collide_with_detector_rule_ids(universe, known_ids):
    detector_rule_ids = {
        detector.rule_id for detector in CRYPTO_DETECTORS if detector.rule_id
    }
    relationships = [_contains(universe, known_ids), _corresponds(universe, known_ids)]
    assert not {r.relationship_rule_id for r in relationships} & detector_rule_ids


def test_relationships_do_not_change_crypto_scan_output_or_accounting(universe, known_ids):
    baseline_stats: dict[str, int] = {}
    baseline_df = scan_crypto_inventory(str(FIXTURE_DIR), stats=baseline_stats)
    baseline_findings = scan_crypto_inventory_findings(str(FIXTURE_DIR))
    baseline_json = reports.findings_json(baseline_findings)
    context = reports.make_report_context(
        str(FIXTURE_DIR),
        scan_type="crypto",
        scanners=["crypto_inventory"],
        crypto_files_inspected=baseline_stats["files_inspected"],
    )
    baseline_markdown = reports.format_markdown_report(baseline_findings, context)
    baseline_summary = reports.summarize_findings(baseline_findings)
    baseline_console = reports.format_console_summary(baseline_findings, context)

    # Build relationships over the real findings, then re-run the same scan.
    relationships = collect_relationships(
        [_contains(universe, known_ids), _corresponds(universe, known_ids)],
        index_finding_ids(list(universe.values()) + baseline_findings),
    )
    assert len(relationships.relationships) == 2

    after_stats: dict[str, int] = {}
    after_df = scan_crypto_inventory(str(FIXTURE_DIR), stats=after_stats)
    after_findings = scan_crypto_inventory_findings(str(FIXTURE_DIR))

    assert list(after_df.columns) == list(baseline_df.columns)
    assert not any("relationship" in str(column).lower() for column in after_df.columns)
    assert len(after_df) == len(baseline_df)
    assert after_stats == baseline_stats
    assert [f.finding_id for f in after_findings] == [
        f.finding_id for f in baseline_findings
    ]
    # Rendering the same findings again after relationship work produces byte-
    # identical output (a re-scan's own collection timestamps differ by design,
    # which is why identity, columns, counts, and accounting are compared across
    # the two scans and the rendered documents are compared for one).
    assert reports.findings_json(baseline_findings) == baseline_json
    assert reports.summarize_findings(after_findings) == baseline_summary
    assert reports.summarize_findings(baseline_findings) == baseline_summary
    assert reports.format_console_summary(baseline_findings, context) == baseline_console
    assert reports.format_markdown_report(baseline_findings, context) == baseline_markdown
    assert "relationship" not in baseline_markdown.lower()
    assert "relationship" not in baseline_console.lower()
    for payload in findings_to_dicts(after_findings):
        assert not any("relationship" in key for key in payload)


def test_relationship_creation_does_not_increment_file_accounting(tmp_path, universe, known_ids):
    (tmp_path / "note.txt").write_text("no crypto here", encoding="utf-8")
    stats: dict[str, int] = {}
    scan_crypto_inventory(str(tmp_path), stats=stats)
    inspected = stats["files_inspected"]
    for _ in range(10):
        _contains(universe, known_ids)
    collect_relationships([_contains(universe, known_ids)] * 5, known_ids)
    assert stats["files_inspected"] == inspected


def test_relationship_counts_are_internal_bookkeeping_only(universe, known_ids):
    collection = collect_relationships([_contains(universe, known_ids)], known_ids)
    counts = collection.counts()
    assert counts["valid"] == 1
    assert "files_scanned" not in counts
    assert "files_inspected" not in counts
    assert not set(counts) & set(reports.SUMMARY_CATEGORIES)
