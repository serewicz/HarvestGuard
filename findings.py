from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
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

    def __post_init__(self) -> None:
        observed_at = _normalize_timestamp(self.observed_at)
        metadata = _json_safe(self.technical_metadata)
        errors = [str(error) for error in self.errors if str(error)]
        unknowns = [str(item) for item in self.unknowns if str(item)]
        limitations = [str(item) for item in self.limitations if str(item)]
        ownership_signals = _json_safe(self.ownership_signals)
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
            "ownership_signals": _json_safe(self.ownership_signals),
            "unknowns": list(self.unknowns),
            "limitations": list(self.limitations),
            "errors": list(self.errors),
            "technical_metadata": _json_safe(self.technical_metadata),
            "schema_version": self.schema_version,
        }

    def _generate_id(self) -> str:
        payload = {
            "schema_version": self.schema_version,
            "scan_id": self.scan_id,
            "source_type": self.source_type,
            "asset_type": self.asset_type,
            "location": self.location,
            "asset_name": self.asset_name,
            "scanner_name": self.scanner_name,
            "scanner_version": self.scanner_version,
            "evidence": self.evidence,
            "confidence": self.confidence,
            "confidence_rationale": self.confidence_rationale,
            "collection_method": self.collection_method,
            "collection_source": self.collection_source,
            "rule_id": self.rule_id,
            "repeatable": self.repeatable,
            "verification_rationale": self.verification_rationale,
            "ownership_signals": self.ownership_signals,
            "unknowns": self.unknowns,
            "limitations": self.limitations,
            "errors": self.errors,
            "technical_metadata": self.technical_metadata,
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


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


def _json_safe(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
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
