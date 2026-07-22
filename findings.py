from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Any

import pandas as pd

SCHEMA_VERSION = "1.0.0"


@dataclass(frozen=True)
class NormalizedFinding:
    """HarvestGuard's evidence-only scanner finding contract.

    This model intentionally excludes assessment fields such as business
    impact, severity, remediation cost, quantum risk, ownership, and executive
    priority. Scanner-specific observed values belong in technical_metadata.
    """

    source_type: str
    asset_type: str
    location: str
    scanner_name: str
    evidence: str
    confidence: str
    technical_metadata: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    asset_name: str | None = None
    scan_id: str | None = None
    observed_at: str | datetime | None = None
    scanner_version: str = "unknown"
    schema_version: str = SCHEMA_VERSION
    finding_id: str | None = None
    # Confidence is confidence in the observation itself, never severity,
    # priority, or business impact. The rationale explains what evidence
    # quality produced that confidence level.
    confidence_rationale: str | None = None
    # Provenance: how this specific observation was collected, so it can be
    # independently verified or reproduced.
    collection_method: str | None = None
    collection_source: str | None = None
    rule_id: str | None = None
    repeatable: bool | None = None
    verification_rationale: str | None = None
    # Technical ownership signals only (uid/gid/mode/etc.) -- never business
    # ownership, department, or accountable-executive inference.
    ownership_signals: dict[str, Any] = field(default_factory=dict)
    # Distinct from `errors`: unknowns are things HarvestGuard cannot
    # establish at all (e.g. business ownership from filesystem metadata);
    # limitations are conditions that constrained this specific observation
    # (e.g. permission denied, volume-level fallback used).
    unknowns: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    # Optional, scanner-supplied technical discriminator for when
    # source_type/asset_type/location/scanner_name/rule_id alone don't
    # distinguish two logically separate findings -- e.g. two certificates
    # parsed from the same PKCS#12 or PEM file share every one of those
    # fields. Must be stable across equivalent repeated scans and derived
    # only from the observation itself (a cryptographic fingerprint is the
    # canonical example) -- never from timestamps, confidence, ownership
    # signals, unknowns/limitations, or other mutable environment metadata.
    # Purely a technical identity discriminator: never a recommendation or
    # business concept.
    identity_key: str | None = None

    def __post_init__(self) -> None:
        observed_at = _normalize_timestamp(self.observed_at)
        # Recursively frozen (MappingProxyType/tuple) so `frozen=True` on this
        # dataclass can't be bypassed by mutating a nested dict/list in place
        # after construction. _json_safe() runs first to normalize numpy
        # scalars/timestamps/NaN into plain values before freezing.
        metadata = _freeze(_json_safe(self.technical_metadata))
        errors = tuple(str(error) for error in self.errors if str(error))
        unknowns = tuple(str(item) for item in self.unknowns if str(item))
        limitations = tuple(str(item) for item in self.limitations if str(item))
        ownership_signals = _freeze(_json_safe(self.ownership_signals))
        asset_name = self.asset_name or _asset_name_from_location(self.location)

        object.__setattr__(self, "observed_at", observed_at)
        object.__setattr__(self, "technical_metadata", metadata)
        object.__setattr__(self, "errors", errors)
        object.__setattr__(self, "unknowns", unknowns)
        object.__setattr__(self, "limitations", limitations)
        object.__setattr__(self, "ownership_signals", ownership_signals)
        object.__setattr__(self, "asset_name", asset_name)
        if self.finding_id is None:
            object.__setattr__(self, "finding_id", self._generate_id())

    @property
    def provenance(self) -> "Provenance":
        """Typed, read-only view over this Finding's provenance fields.

        Additive convenience only: the underlying flat fields (scanner_name,
        scanner_version, collection_method, collection_source, rule_id,
        observed_at, repeatable, verification_rationale) are unchanged, so
        every existing adapter call site keeps constructing NormalizedFinding
        exactly as before. This gives callers that want structured access a
        single `finding.provenance` object instead of reading each flat field
        individually.
        """
        return Provenance(
            scanner_name=self.scanner_name,
            scanner_version=self.scanner_version,
            collection_method=self.collection_method,
            source=self.collection_source,
            rule_id=self.rule_id,
            collected_at=self.observed_at,
            repeatable=self.repeatable,
            verification_rationale=self.verification_rationale,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "scan_id": self.scan_id,
            "source_type": self.source_type,
            "asset_type": self.asset_type,
            "location": self.location,
            "asset_name": self.asset_name,
            "scanner_name": self.scanner_name,
            "scanner_version": self.scanner_version,
            "observed_at": self.observed_at,
            "evidence": self.evidence,
            "confidence": self.confidence,
            "confidence_rationale": self.confidence_rationale,
            "collection_method": self.collection_method,
            "collection_source": self.collection_source,
            "rule_id": self.rule_id,
            "repeatable": self.repeatable,
            "verification_rationale": self.verification_rationale,
            # Additive: a nested, typed view of the same provenance fields
            # already flattened above. New provenance fields can grow here
            # without perturbing the flat keys existing callers depend on.
            "provenance": self.provenance.to_dict(),
            "identity_key": self.identity_key,
            "ownership_signals": _json_safe(self.ownership_signals),
            "unknowns": list(self.unknowns),
            "limitations": list(self.limitations),
            "errors": list(self.errors),
            "technical_metadata": _json_safe(self.technical_metadata),
            "schema_version": self.schema_version,
        }

    def _generate_id(self) -> str:
        """Finding identity is deliberately narrow: a small, logical identity,
        not "most of the object".

        It must survive re-scanning the same unchanged asset even when
        volatile facts differ between runs (a touched mtime, a chmod, a
        different collection host, a resolved-vs-unresolved owner name, a
        slightly reworded confidence rationale or evidence sentence) -- none
        of those mean the *finding* changed. It must still change whenever
        the logical finding itself changes, including when two logically
        separate findings would otherwise share every other identity field
        (e.g. two certificates parsed from the same PKCS#12/PEM file --
        identity_key exists precisely for this case).

        Included (the canonical identity): source_type, asset_type, location
        (the stable asset identifier), scanner_name, rule_id (which
        detection path fired, or the equivalent machine-stable observation
        type), and identity_key when the scanner supplied one.

        Deliberately excluded: schema_version and evidence (human-readable
        wording and schema-format changes must not churn ids -- if the
        identity algorithm itself ever needs an incompatible redesign, that
        should be an explicit id-algorithm/version concept, not
        schema_version), scan_id, scanner_version, observed_at (collection
        timestamp), collection_source (collection environment), confidence
        and confidence_rationale, ownership_signals, unknowns, limitations,
        errors, and technical_metadata (size, mtime, mode, and other
        scanner-observed detail).
        """
        payload = {
            "source_type": self.source_type,
            "asset_type": self.asset_type,
            "location": self.location,
            "scanner_name": self.scanner_name,
            "rule_id": self.rule_id,
        }
        if self.identity_key is not None:
            payload["identity_key"] = self.identity_key
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class Provenance:
    """Typed grouping of a Finding's provenance fields.

    NormalizedFinding keeps these as flat fields (see its docstring) for
    backward compatibility with every existing scanner adapter's constructor
    call; this type exists so callers that want structured access can use
    `finding.provenance` instead of reading each flat field individually,
    without requiring a wider migration of adapters in this change.
    """

    scanner_name: str
    scanner_version: str
    collection_method: str | None
    source: str | None
    rule_id: str | None
    collected_at: str | datetime | None
    repeatable: bool | None
    verification_rationale: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "scanner_name": self.scanner_name,
            "scanner_version": self.scanner_version,
            "collection_method": self.collection_method,
            "source": self.source,
            "rule_id": self.rule_id,
            "collected_at": self.collected_at,
            "repeatable": self.repeatable,
            "verification_rationale": self.verification_rationale,
        }


def findings_to_dicts(findings: list[NormalizedFinding]) -> list[dict[str, Any]]:
    return [finding.to_dict() for finding in findings]


def _normalize_timestamp(value: str | datetime | None) -> str:
    if value is None:
        value = datetime.now(timezone.utc)
    if isinstance(value, pd.Timestamp):
        value = value.to_pydatetime()
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.replace(microsecond=0).isoformat()
    return str(value)


def _asset_name_from_location(location: str) -> str | None:
    if "://" in location:
        return location.rstrip("/").rsplit("/", 1)[-1] or None
    name = Path(location).name
    return name or None


def _freeze(value: Any) -> Any:
    """Recursively convert dict/list/set into immutable equivalents so a
    frozen dataclass's `frozen=True` can't be bypassed by mutating a nested
    structure in place (e.g. `finding.technical_metadata["x"] = "y"` or
    `finding.unknowns.append(...)`).
    """
    if isinstance(value, dict):
        return MappingProxyType({k: _freeze(v) for k, v in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(v) for v in value)
    if isinstance(value, (set, frozenset)):
        return frozenset(_freeze(v) for v in value)
    return value


def _json_safe(value: Any) -> Any:
    if isinstance(value, (dict, MappingProxyType)):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_json_safe(v) for v in value]
    if isinstance(value, pd.Timestamp):
        return _normalize_timestamp(value)
    if isinstance(value, datetime):
        return _normalize_timestamp(value)
    # numpy scalars (e.g. int64/bool_ from a DataFrame round-trip via stat
    # fields like uid/gid) aren't JSON-serializable directly; .item() converts
    # to the equivalent native Python type without requiring a numpy import.
    if hasattr(value, "item") and hasattr(value, "dtype"):
        return _json_safe(value.item())
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            return None
        if value.is_integer():
            return int(value)
    if pd.isna(value):
        return None
    return value
