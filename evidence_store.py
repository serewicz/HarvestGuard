"""HarvestGuard's local SQLite evidence store for completed scan runs.

Why this exists: before this module, a scan's normalized findings and the scan
context needed to interpret them lived only in the running process. Once the
CLI exited, nothing bound a shared JSON or Markdown artifact to one specific
scan run, and a reviewer could not regenerate that artifact without rescanning
the target.

What is stored, and how:

- one immutable scan-run row per ``scan_id`` (the run's identity, timing,
  target, selected scanners and their versions, exclusions, scope constraints,
  scanner errors, crypto-file accounting, the HarvestGuard version that
  executed the scan, and the normalized-finding schema version);
- one immutable serialized ``NormalizedFinding`` snapshot per retained finding,
  keyed by ``(scan_id, ordinal)`` in canonical report order;
- a SHA-256 digest over the canonical run payload plus those ordered snapshots.

Per-scan snapshots, not one row per finding: the same logical `finding_id` can
be observed on many runs with a different `observed_at`, scanner version,
confidence, limitations, errors, ownership signals, or technical metadata.
`finding_id` is therefore indexed but is never a primary key, is never unique
within a scan (so a colliding ID is preserved rather than silently dropped),
and a finding is never updated in place. The store API is append-only: there is
no update, upsert, delete, or purge operation, and reusing a `scan_id` fails
instead of replacing prior evidence.

What the digest is, and is not: recomputing it detects that a stored run has
become internally inconsistent -- a truncated write, a corrupted page, an
edited payload. It is *not* a signature, an attestation, or a chain of custody.
Anyone who can write to the SQLite file can change both the payload and the
digest. Signing and external timestamping are deliberately out of scope here.

The database is a sensitive evidence artifact: it retains everything a
normalized finding already carries, including file paths, object names,
certificate subjects and issuers, and technical ownership signals. It is not
encrypted at rest. Persistence is opt-in for exactly that reason -- see
``harvestguard scan --evidence-db`` in docs/CLI.md.

Standard-library ``sqlite3`` only: no ORM, no migration framework, no service,
and no new runtime dependency.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from findings import SCHEMA_VERSION as FINDING_SCHEMA_VERSION
from findings import NormalizedFinding, finding_from_dict
from harvestguard_version import __version__ as HARVESTGUARD_VERSION
from reports import ScanReportContext, sort_findings

# Evidence-store schema version, recorded in the database's own
# `PRAGMA user_version`. HG-046 supports creating and reading v1 only: a
# database written by a newer schema is refused rather than guessed at, and
# general migration tooling is deliberately deferred until a v2 exists.
SCHEMA_VERSION = 1

_RUN_TABLE = "scan_runs"
_FINDING_TABLE = "scan_findings"
_REQUIRED_TABLES = frozenset({_RUN_TABLE, _FINDING_TABLE})

_SCHEMA_STATEMENTS = (
    f"""
    CREATE TABLE {_RUN_TABLE} (
        scan_id TEXT PRIMARY KEY NOT NULL,
        scan_time TEXT NOT NULL,
        duration_seconds REAL,
        target_path TEXT NOT NULL,
        scan_type TEXT,
        scanners TEXT NOT NULL,
        scanner_versions TEXT NOT NULL,
        excluded_paths TEXT NOT NULL,
        scope_constraints TEXT NOT NULL,
        scanner_errors TEXT NOT NULL,
        crypto_files_inspected INTEGER,
        harvestguard_version TEXT NOT NULL,
        finding_schema_version TEXT NOT NULL,
        finding_count INTEGER NOT NULL,
        evidence_digest TEXT NOT NULL
    )
    """,
    # (scan_id, ordinal) rather than finding_id: two scans that observed the
    # same logical finding keep two snapshots, and a within-scan finding_id
    # collision is preserved by ordinal instead of colliding on insert.
    f"""
    CREATE TABLE {_FINDING_TABLE} (
        scan_id TEXT NOT NULL,
        ordinal INTEGER NOT NULL,
        finding_id TEXT,
        finding_json TEXT NOT NULL,
        PRIMARY KEY (scan_id, ordinal),
        FOREIGN KEY (scan_id) REFERENCES {_RUN_TABLE}(scan_id)
    )
    """,
    f"CREATE INDEX idx_{_FINDING_TABLE}_finding_id ON {_FINDING_TABLE}(finding_id)",
)

# Run-record keys whose value is a structured list/dict. Stored as deterministic
# JSON text in a single column; carried as native values in the canonical
# digest payload so the digest never depends on column-encoding details.
_STRUCTURED_RUN_KEYS = (
    "scanners",
    "scanner_versions",
    "excluded_paths",
    "scope_constraints",
    "scanner_errors",
)

# Column order for the run row, used for both INSERT and digest reconstruction.
_RUN_KEYS = (
    "scan_id",
    "scan_time",
    "duration_seconds",
    "target_path",
    "scan_type",
    "scanners",
    "scanner_versions",
    "excluded_paths",
    "scope_constraints",
    "scanner_errors",
    "crypto_files_inspected",
    "harvestguard_version",
    "finding_schema_version",
    "finding_count",
)


class EvidenceStoreError(Exception):
    """Any failure to open, write, read, or trust the local evidence store."""


class EvidenceIntegrityError(EvidenceStoreError):
    """A stored run's recomputed digest does not match the stored digest.

    Corruption or inconsistency detection only -- never proof of tampering or
    of its absence (see this module's docstring).
    """


class ScanRunNotFoundError(EvidenceStoreError):
    """No run with the requested scan ID exists in this database."""


class DuplicateScanRunError(EvidenceStoreError):
    """A run with this scan ID is already stored; evidence is never replaced."""


@dataclass(frozen=True)
class StoredRunSummary:
    """One row of ``harvestguard evidence list``.

    ``has_scanner_errors`` records only *whether* scanner errors were stored,
    so a zero-finding run that failed is still visibly distinct from a
    zero-finding run that completed cleanly.
    """

    scan_id: str
    scan_time: str
    scan_type: str | None
    target_path: str
    finding_count: int
    has_scanner_errors: bool


@dataclass(frozen=True)
class StoredScanRun:
    """A verified stored run, reconstructed for the existing report formatters.

    ``harvestguard_version`` is the release that *executed* the stored scan,
    which is not necessarily the release performing a later export.
    """

    scan_id: str
    context: ScanReportContext
    findings: list[NormalizedFinding]
    harvestguard_version: str
    finding_schema_version: str
    evidence_digest: str


def store_scan_run(
    db_path: str | Path,
    scan_id: str,
    context: ScanReportContext,
    findings: list[NormalizedFinding],
    harvestguard_version: str = HARVESTGUARD_VERSION,
) -> str:
    """Append one complete scan run and return its evidence digest.

    The run row and every finding snapshot are written in a single transaction:
    a failure part-way through leaves no partial run behind. Findings are
    stored in canonical report order (`reports.sort_findings`) so a later
    stored export reproduces the same deterministic output.
    """
    if not isinstance(scan_id, str) or not scan_id.strip():
        raise EvidenceStoreError("scan ID must be a non-empty string")

    ordered = sort_findings(list(findings))
    try:
        finding_dicts = [finding.to_dict() for finding in ordered]
        run = _run_record(scan_id, context, len(finding_dicts), harvestguard_version)
        digest = compute_evidence_digest(run, finding_dicts)
        finding_rows = [
            (scan_id, ordinal, payload.get("finding_id"), _snapshot_json(payload))
            for ordinal, payload in enumerate(finding_dicts)
        ]
    except (TypeError, ValueError) as exc:
        raise EvidenceStoreError(f"scan evidence could not be serialized: {exc}") from exc

    placeholders = ", ".join("?" for _ in _RUN_KEYS)
    columns = ", ".join(_RUN_KEYS)
    connection = _connect(db_path, create=True)
    try:
        with connection:
            connection.execute(
                f"INSERT INTO {_RUN_TABLE} ({columns}, evidence_digest) "
                f"VALUES ({placeholders}, ?)",
                (*_run_row_values(run), digest),
            )
            connection.executemany(
                f"INSERT INTO {_FINDING_TABLE} "
                "(scan_id, ordinal, finding_id, finding_json) VALUES (?, ?, ?, ?)",
                finding_rows,
            )
    except sqlite3.IntegrityError as exc:
        if f"{_RUN_TABLE}.scan_id" in str(exc):
            raise DuplicateScanRunError(
                f"scan ID {scan_id} is already stored in {db_path}; "
                "stored evidence is never replaced"
            ) from exc
        raise EvidenceStoreError(f"could not store scan run {scan_id}: {exc}") from exc
    except sqlite3.Error as exc:
        raise EvidenceStoreError(f"could not store scan run {scan_id}: {exc}") from exc
    finally:
        connection.close()
    return digest


def list_scan_runs(db_path: str | Path) -> list[StoredRunSummary]:
    """Every stored run, oldest scan time first.

    Required for discoverability: a zero-finding run is a real, complete
    evidence record, but bare-array JSON of an empty run carries no
    finding-level scan ID to find it by.
    """
    connection = _connect(db_path, create=False)
    try:
        rows = connection.execute(
            f"SELECT scan_id, scan_time, scan_type, target_path, finding_count, "
            f"scanner_errors FROM {_RUN_TABLE} ORDER BY scan_time, scan_id"
        ).fetchall()
    except sqlite3.Error as exc:
        raise EvidenceStoreError(f"could not read evidence database {db_path}: {exc}") from exc
    finally:
        connection.close()

    summaries = []
    for row in rows:
        errors = _decode_structured(row["scanner_errors"], "scanner_errors")
        summaries.append(
            StoredRunSummary(
                scan_id=row["scan_id"],
                scan_time=row["scan_time"],
                scan_type=row["scan_type"],
                target_path=row["target_path"],
                finding_count=row["finding_count"],
                has_scanner_errors=bool(errors),
            )
        )
    return summaries


def load_scan_run(db_path: str | Path, scan_id: str) -> StoredScanRun:
    """Load one stored run, verifying its digest before returning anything.

    Fails closed: a digest mismatch raises `EvidenceIntegrityError` instead of
    returning a payload a caller might emit as verified evidence.
    """
    connection = _connect(db_path, create=False)
    try:
        run_row = connection.execute(
            f"SELECT * FROM {_RUN_TABLE} WHERE scan_id = ?", (scan_id,)
        ).fetchone()
        if run_row is None:
            raise ScanRunNotFoundError(
                f"no stored scan run with scan ID {scan_id} in {db_path}"
            )
        finding_rows = connection.execute(
            f"SELECT finding_json FROM {_FINDING_TABLE} WHERE scan_id = ? ORDER BY ordinal",
            (scan_id,),
        ).fetchall()
    except sqlite3.Error as exc:
        raise EvidenceStoreError(f"could not read evidence database {db_path}: {exc}") from exc
    finally:
        connection.close()

    finding_dicts = [
        _decode_structured(row["finding_json"], "finding snapshot") for row in finding_rows
    ]
    run = {key: run_row[key] for key in _RUN_KEYS}
    for key in _STRUCTURED_RUN_KEYS:
        run[key] = _decode_structured(run_row[key], key)

    recomputed = compute_evidence_digest(run, finding_dicts)
    stored_digest = run_row["evidence_digest"]
    if recomputed != stored_digest:
        raise EvidenceIntegrityError(
            f"stored scan run {scan_id} failed integrity verification: expected digest "
            f"{stored_digest}, recomputed {recomputed}. The stored evidence is "
            "inconsistent and was not emitted."
        )

    try:
        findings = [finding_from_dict(payload) for payload in finding_dicts]
    except (TypeError, ValueError) as exc:
        raise EvidenceStoreError(
            f"stored scan run {scan_id} contains an unreadable finding snapshot: {exc}"
        ) from exc

    context = ScanReportContext(
        target_path=run["target_path"],
        scan_time=run["scan_time"],
        duration_seconds=run["duration_seconds"],
        excluded_paths=list(run["excluded_paths"]),
        scanner_errors=list(run["scanner_errors"]),
        scan_type=run["scan_type"],
        scanners=list(run["scanners"]),
        scope_constraints=list(run["scope_constraints"]),
        scanner_versions=dict(run["scanner_versions"]),
        crypto_files_inspected=run["crypto_files_inspected"],
        scan_id=run["scan_id"],
    )
    return StoredScanRun(
        scan_id=run["scan_id"],
        context=context,
        findings=findings,
        harvestguard_version=run["harvestguard_version"],
        finding_schema_version=run["finding_schema_version"],
        evidence_digest=stored_digest,
    )


def verify_scan_run(db_path: str | Path, scan_id: str) -> StoredScanRun:
    """Recompute and check one stored run's digest.

    Same path as `load_scan_run` on purpose: verification is not a separate
    implementation that could drift from what export actually trusts.
    """
    return load_scan_run(db_path, scan_id)


def compute_evidence_digest(
    run: dict[str, Any], finding_dicts: list[dict[str, Any]]
) -> str:
    """SHA-256 over the canonical run payload plus its ordered snapshots.

    Corruption/inconsistency detection only -- not a signature, attestation, or
    chain of custody (see this module's docstring). The finding count is part of
    the run payload, so a removed snapshot row changes the recomputed digest.
    """
    payload = {
        "evidence_store_schema_version": SCHEMA_VERSION,
        "scan_run": run,
        "findings": finding_dicts,
    }
    return hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


def _run_record(
    scan_id: str,
    context: ScanReportContext,
    finding_count: int,
    harvestguard_version: str,
) -> dict[str, Any]:
    """The scan-level record, restricted to fields reporting already emits.

    Nothing about the host environment is captured: no environment variables,
    process IDs, hostnames, credentials, authentication state, or raw exception
    objects. Scanner errors are stored as the same already-safe strings the
    console and Markdown reports print.
    """
    return {
        "scan_id": scan_id,
        "scan_time": context.scan_time,
        "duration_seconds": context.duration_seconds,
        "target_path": context.target_path,
        "scan_type": context.scan_type,
        "scanners": [str(name) for name in context.scanners],
        "scanner_versions": {
            str(name): str(version) for name, version in context.scanner_versions.items()
        },
        "excluded_paths": [str(pattern) for pattern in context.excluded_paths],
        "scope_constraints": [str(item) for item in context.scope_constraints],
        "scanner_errors": [str(error) for error in context.scanner_errors],
        "crypto_files_inspected": context.crypto_files_inspected,
        "harvestguard_version": harvestguard_version,
        "finding_schema_version": FINDING_SCHEMA_VERSION,
        "finding_count": finding_count,
    }


def _run_row_values(run: dict[str, Any]) -> tuple[Any, ...]:
    return tuple(
        _canonical_json(run[key]) if key in _STRUCTURED_RUN_KEYS else run[key]
        for key in _RUN_KEYS
    )


def _canonical_json(value: Any) -> str:
    """Key-sorted JSON, used only where a stable byte sequence is the point.

    The digest must not depend on dict iteration order, so it sorts keys.
    """
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _snapshot_json(payload: dict[str, Any]) -> str:
    """A finding snapshot, with its key order left exactly as the scanner
    produced it.

    Deliberately *not* key-sorted: `to_dict()`'s ordering (and the ordering of
    nested technical metadata) is part of what a stored export has to reproduce
    byte-for-byte through `findings_json()`, which does not sort keys either.
    The digest is computed separately over a key-sorted form, so integrity does
    not depend on this ordering.
    """
    return json.dumps(payload, separators=(",", ":"))


def _decode_structured(raw: Any, label: str) -> Any:
    try:
        return json.loads(raw)
    except (TypeError, ValueError) as exc:
        raise EvidenceIntegrityError(
            f"stored {label} is not readable JSON: {exc}"
        ) from exc


def _connect(db_path: str | Path, create: bool) -> sqlite3.Connection:
    path = Path(db_path)
    if not create and not path.exists():
        raise EvidenceStoreError(f"evidence database does not exist: {path}")
    try:
        connection = sqlite3.connect(str(path))
    except sqlite3.Error as exc:
        raise EvidenceStoreError(f"could not open evidence database {path}: {exc}") from exc
    connection.row_factory = sqlite3.Row
    try:
        _prepare_schema(connection, create=create)
    except Exception:
        connection.close()
        raise
    return connection


def _prepare_schema(connection: sqlite3.Connection, create: bool) -> None:
    """Create the v1 schema on a fresh database, or validate an existing one.

    A file that is not a readable SQLite database, one written by a different
    application, and one written by a future evidence-store schema all fail
    here rather than being partially interpreted.
    """
    try:
        user_version = connection.execute("PRAGMA user_version").fetchone()[0]
        tables = {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
            if not str(row[0]).startswith("sqlite_")
        }
    except sqlite3.DatabaseError as exc:
        raise EvidenceStoreError(f"not a readable evidence database: {exc}") from exc

    if not tables and user_version == 0:
        if not create:
            raise EvidenceStoreError(
                "evidence database contains no HarvestGuard evidence-store schema"
            )
        try:
            with connection:
                for statement in _SCHEMA_STATEMENTS:
                    connection.execute(statement)
                connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        except sqlite3.Error as exc:
            raise EvidenceStoreError(f"could not create evidence-store schema: {exc}") from exc
        return

    if user_version != SCHEMA_VERSION:
        raise EvidenceStoreError(
            f"unsupported evidence-store schema version {user_version}; this "
            f"HarvestGuard reads version {SCHEMA_VERSION}"
        )
    missing = sorted(_REQUIRED_TABLES - tables)
    if missing:
        raise EvidenceStoreError(
            "evidence database is missing required table(s): " + ", ".join(missing)
        )
