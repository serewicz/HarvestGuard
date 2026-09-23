#!/usr/bin/env python3
"""Regenerate the committed executive evidence view examples (GitHub issue #153).

Every sample in this directory is produced through the real shipped path:

    labelled synthetic fixture
      -> real evidence store (`evidence_store.store_scan_run`)
      -> verified load (`evidence_store.load_scan_run`)
      -> one shared projection (`executive_evidence.build_executive_evidence_view`)
      -> both serializers (`executive_reports.executive_json`,
         `executive_reports.format_executive_markdown`)

This is *example tooling*, not a second reporting pipeline and not a new public
CLI mode. It adds no projection, no serializer, no status policy and no verifier
of its own: it only builds fixtures, stores them, and calls the same APIs that
`harvestguard evidence export --executive-json/--executive-markdown` calls.

Where those APIs come from. When HarvestGuard is installed, they are imported
from the installed distribution and this helper adds nothing to `sys.path`;
`tests/test_executive_evidence_examples.py` regenerates the whole collection
and reruns both CLI export modes that way -- from a non-editable install, run
outside the checkout, with no repository import override -- and requires the
result to match the committed bytes. Only when nothing is installed to import
(a bare checkout) does this file fall back to the repository root, so that
`python docs/examples/.../generate_examples.py` still works before an install.

The one sample produced by running the CLI (the corruption diagnostic) is run
through the CLI of that same implementation: the installed distribution's own
console script, or the checkout's entry point. Before it runs, the helper checks
that the CLI subprocess would import exactly the module files this process
imported, and fails with `CliMismatchError` otherwise. It never falls back to a
`harvestguard` found on `PATH`, which could be an older install.

Determinism. The installed CLI reads its own UTC clock for the export time, by
design (there is deliberately no public override). Committed samples have to be
byte-stable, so this helper passes an explicit fixed `export_time` to the same
installed projection API the CLI uses. The only difference between a committed
sample and the equivalent live CLI export of the same fixture is therefore that
one `export_time` value; `tests/test_executive_evidence_examples.py` proves
that by running the real CLI and comparing the rest.

Every fixture is synthetic and labelled as such, in the scan ID, the target
path and the scope constraints, so no sample can be mistaken for evidence a
collector actually produced about a real environment. Historical gaps (an
unreadable scan time, an unsupported collection contract) are modelled as
purpose-built synthetic runs -- not by rewriting real stored evidence and not
by attributing them to a scanner that never produced them.

Usage:

    python docs/examples/executive-evidence-view/generate_examples.py
    python docs/examples/executive-evidence-view/generate_examples.py \\
        --output-dir /tmp/out --work-dir /tmp/work

The generated evidence database is a sensitive-by-default artifact, so it is
*not* committed: without `--work-dir` it is built in a temporary directory and
discarded. Pass `--work-dir` when you want to keep it and run the documented
CLI commands against it yourself -- it must be a new or empty directory. This
helper never deletes or overwrites an existing evidence database, because it
cannot tell a disposable fixture from evidence someone needs to keep.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

# The installed distribution comes first: issue #153 requires the committed
# samples to be reproducible from an installed release, so an install must
# never be shadowed by this checkout. The repository root -- four levels above
# this file -- is added only when there is no installed package to import,
# which is the uninstalled-checkout case.
_REPO_ROOT = Path(__file__).resolve().parents[3]
if importlib.util.find_spec("evidence_store") is None:  # pragma: no cover - bootstrap
    sys.path.insert(0, str(_REPO_ROOT))

import evidence_store  # noqa: E402
from evidence_store import (  # noqa: E402
    compute_evidence_digest,
    load_scan_run,
    store_scan_run,
)
from executive_evidence import (  # noqa: E402
    EXECUTIVE_POLICY_VERSION,
    EXECUTIVE_SCHEMA_VERSION,
    build_executive_evidence_view,
)
from executive_reports import executive_json, format_executive_markdown  # noqa: E402
from findings import SCHEMA_VERSION as FINDING_SCHEMA_VERSION  # noqa: E402
from findings import NormalizedFinding  # noqa: E402
from harvestguard_version import __version__ as HARVESTGUARD_VERSION  # noqa: E402
from reports import ScanReportContext, make_report_context  # noqa: E402

# --- fixed inputs ----------------------------------------------------------

#: The one explicit export time every committed sample is generated with.
EXPORT_TIME = "2026-01-15T00:00:00+00:00"

#: The recorded scan time of the synthetic runs. Historical derivations are
#: dated against this, never against today's clock.
SCAN_TIME = datetime(2025, 11, 4, 9, 30, 0, tzinfo=timezone.utc)

#: Path of the imaginary target. Deliberately not a real-looking user path.
TARGET_PATH = "/synthetic/example-target"

#: Carried in every fixture's scope constraints so the label survives into both
#: generated formats, not only into this directory's README.
SYNTHETIC_LABEL = (
    "SYNTHETIC EXAMPLE FIXTURE: purpose-built evidence for HarvestGuard "
    "documentation. Not a real environment, not a real scan, no customer, "
    "personal or confidential data."
)

DB_NAME = "example-evidence.sqlite"
SAMPLES_DIR = "samples"
MANIFEST_NAME = "manifest.json"
CORRUPTION_DB_NAME = "corrupted-copy.sqlite"
CORRUPTION_DIAGNOSTIC = "failed-integrity-corruption.stderr.txt"
#: The output path the corruption example asks the CLI for, which the CLI must
#: refuse to write. Nothing here may overwrite a file that is already there.
REJECTED_OUTPUT_NAME = "rejected-run.md"

#: Every name `generate` writes inside the work directory. If any of them
#: already exists, the directory is not a disposable work directory.
WORK_DIR_ARTIFACTS = (DB_NAME, CORRUPTION_DB_NAME, REJECTED_OUTPUT_NAME)


# --- fixture builders ------------------------------------------------------


def _context(
    scan_id: str,
    *,
    scanner_versions: dict[str, str] | None = None,
    scanner_errors: list[str] | None = None,
    scanners: list[str] | None = None,
    scan_type: str = "code",
) -> ScanReportContext:
    return make_report_context(
        target_path=TARGET_PATH,
        started_at=SCAN_TIME,
        duration_seconds=1.5,
        scan_type=scan_type,
        scanners=scanners if scanners is not None else ["code analysis"],
        scanner_versions=(
            {"semgrep_crypto_rules": "0.2.0"} if scanner_versions is None else scanner_versions
        ),
        scanner_errors=scanner_errors or [],
        scope_constraints=[SYNTHETIC_LABEL],
        crypto_files_inspected=12,
        scan_id=scan_id,
    )


def _code_finding(
    scan_id: str,
    location: str,
    *,
    full_provenance: bool = True,
    **kwargs,
) -> NormalizedFinding:
    provenance: dict[str, object] = {}
    if full_provenance:
        provenance = {
            "collection_method": "static source-text match",
            "collection_source": "vendored semgrep rule set",
            "repeatable": True,
            "verification_rationale": "re-running the same rule set reproduces the match",
        }
    provenance.update(kwargs)
    scanner_version = provenance.pop("scanner_version", "0.2.0")
    return NormalizedFinding(
        scan_id=scan_id,
        source_type="code_analysis",
        asset_type="source_code",
        location=location,
        scanner_name="semgrep_crypto_rules",
        scanner_version=scanner_version,
        observed_at=SCAN_TIME,
        evidence="Semgrep rule matched: weak-hash-md5",
        confidence="High",
        rule_id="weak-hash-md5",
        technical_metadata={"Rule": "weak-hash-md5"},
        **provenance,
    )


def _build_verified(scan_id: str) -> tuple[ScanReportContext, list[NormalizedFinding]]:
    return (
        _context(scan_id),
        [
            _code_finding(scan_id, f"{TARGET_PATH}/app/crypto_utils.py:14"),
            _code_finding(scan_id, f"{TARGET_PATH}/app/legacy_digest.py:31"),
        ],
    )


def _build_zero_findings(scan_id: str) -> tuple[ScanReportContext, list[NormalizedFinding]]:
    return _context(scan_id), []


def _build_warning(scan_id: str) -> tuple[ScanReportContext, list[NormalizedFinding]]:
    return (
        _context(scan_id),
        [
            _code_finding(scan_id, f"{TARGET_PATH}/app/crypto_utils.py:14"),
            _code_finding(
                scan_id, f"{TARGET_PATH}/app/legacy_digest.py:31", full_provenance=False
            ),
        ],
    )


def _build_partial_execution(scan_id: str) -> tuple[ScanReportContext, list[NormalizedFinding]]:
    return (
        _context(
            scan_id,
            scanner_errors=[
                "code analysis: semgrep exited nonzero after 1 of 2 rule files; "
                "partial findings retained"
            ],
        ),
        [_code_finding(scan_id, f"{TARGET_PATH}/app/crypto_utils.py:14")],
    )


def _build_unknown_scan_time(scan_id: str) -> tuple[ScanReportContext, list[NormalizedFinding]]:
    """A historical run whose recorded scan time cannot be read.

    Built directly rather than through `make_report_context`, which normalizes
    a real datetime: the point of the fixture is evidence that *already* has an
    unreadable stamp. No collection time is invented to paper over it.
    """
    context = ScanReportContext(
        target_path=TARGET_PATH,
        scan_time="unknown",
        duration_seconds=1.5,
        scan_type="code",
        scanners=["code analysis"],
        scanner_versions={"semgrep_crypto_rules": "0.2.0"},
        scope_constraints=[SYNTHETIC_LABEL],
        crypto_files_inspected=12,
        scan_id=scan_id,
    )
    return context, [_code_finding(scan_id, f"{TARGET_PATH}/app/crypto_utils.py:14")]


def _build_unsupported_contract(scan_id: str) -> tuple[ScanReportContext, list[NormalizedFinding]]:
    """Both historical-interpretation gaps at once, on one synthetic run.

    The declared scanner version is a collection contract this policy version
    does not document, and the stored snapshot declares a finding schema
    version this release does not recognize. Neither can silently pass.
    """
    return (
        _context(scan_id, scanner_versions={"semgrep_crypto_rules": "0.1.0"}),
        [
            _code_finding(
                scan_id,
                f"{TARGET_PATH}/app/crypto_utils.py:14",
                scanner_version="0.1.0",
                schema_version="0.0.9",
            )
        ],
    )


def _build_failed_reference(scan_id: str) -> tuple[ScanReportContext, list[NormalizedFinding]]:
    """A stored snapshot that names a different run than the one holding it."""
    return (
        _context(scan_id),
        [_code_finding("synthetic-some-other-run", f"{TARGET_PATH}/app/crypto_utils.py:14")],
    )


def _build_duplicate_ids(scan_id: str) -> tuple[ScanReportContext, list[NormalizedFinding]]:
    """Two distinct occurrences that share one finding ID."""
    return (
        _context(scan_id),
        [
            _code_finding(
                scan_id,
                f"{TARGET_PATH}/app/crypto_utils.py:14",
                finding_id="synthetic-shared-finding-id",
            ),
            _code_finding(
                scan_id,
                f"{TARGET_PATH}/app/crypto_utils.py:88",
                finding_id="synthetic-shared-finding-id",
            ),
        ],
    )


#: A synthetic, deliberately secret-shaped-but-worthless value, stored only in
#: an *unrecognized* snapshot field. It exists so a test can prove a withheld
#: value appears in no generated artifact. It matches no real credential shape.
CANARY = "SYNTHETIC-CANARY-VALUE-0000-NOT-A-REAL-SECRET"


def _add_unrecognized_fields(snapshot: dict) -> dict:
    """Model a snapshot written by a writer this release does not fully know.

    Both an unknown top-level field and an unknown direct provenance member,
    each carrying the canary value. The exporting release must disclose the
    field *names* and withhold their values.
    """
    updated = dict(snapshot)
    updated["experimental_attribution"] = CANARY
    provenance = dict(updated.get("provenance") or {})
    provenance["experimental_collector_note"] = CANARY
    updated["provenance"] = provenance
    return updated


def _build_unrecognized_fields(scan_id: str) -> tuple[ScanReportContext, list[NormalizedFinding]]:
    return (
        _context(scan_id),
        [_code_finding(scan_id, f"{TARGET_PATH}/app/crypto_utils.py:14")],
    )


def _rewrite_snapshots(db: Path, scan_id: str, mutate: Callable[[dict], dict]) -> None:
    """Rewrite stored snapshots and re-digest, as a different writer would have.

    The result is a genuinely self-consistent stored run -- the real loader
    accepts it -- rather than corruption. Used only to build a synthetic
    fixture that carries fields this release does not recognize; it never
    touches evidence that a collector actually produced.
    """
    connection = sqlite3.connect(str(db))
    connection.row_factory = sqlite3.Row
    try:
        with connection:
            row = connection.execute(
                "SELECT * FROM scan_runs WHERE scan_id = ?", (scan_id,)
            ).fetchone()
            run = {key: row[key] for key in evidence_store._RUN_KEYS}
            for key in evidence_store._STRUCTURED_RUN_KEYS:
                run[key] = json.loads(row[key])
            snapshots = [
                mutate(json.loads(record["finding_json"]))
                for record in connection.execute(
                    "SELECT finding_json FROM scan_findings WHERE scan_id = ? ORDER BY ordinal",
                    (scan_id,),
                )
            ]
            for ordinal, snapshot in enumerate(snapshots):
                connection.execute(
                    "UPDATE scan_findings SET finding_json = ? WHERE scan_id = ? AND ordinal = ?",
                    (json.dumps(snapshot, separators=(",", ":")), scan_id, ordinal),
                )
            connection.execute(
                "UPDATE scan_runs SET evidence_digest = ? WHERE scan_id = ?",
                (compute_evidence_digest(run, snapshots), scan_id),
            )
    finally:
        connection.close()


@dataclass(frozen=True)
class Scenario:
    """One required outcome, its fixture, and what the sample demonstrates."""

    slug: str
    title: str
    scan_id: str
    expected_status: str
    covers: tuple[str, ...]
    purpose: str
    build: Callable[[str], tuple[ScanReportContext, list[NormalizedFinding]]]
    #: Applied to the stored snapshots after storage, re-digesting the run, for
    #: fixtures that have to model what another writer version stored.
    rewrite: Callable[[dict], dict] | None = None


SCENARIOS: tuple[Scenario, ...] = (
    Scenario(
        slug="verified",
        title="Evidence evaluation: VERIFIED",
        scan_id="synthetic-verified-001",
        expected_status="VERIFIED",
        covers=("VERIFIED",),
        purpose=(
            "Every required check passes and no defined exception applies, so the "
            "evaluation is VERIFIED for the declared scope only."
        ),
        build=_build_verified,
    ),
    Scenario(
        slug="verified-zero-findings",
        title="Evidence evaluation: VERIFIED with a legitimate zero-finding run",
        scan_id="synthetic-zero-findings-001",
        expected_status="VERIFIED",
        covers=("VERIFIED", "legitimate zero-finding run"),
        purpose=(
            "A complete run of a documented collection contract that recorded no "
            "findings and no errors: a valid empty result, distinguishable from "
            "output that was never produced."
        ),
        build=_build_zero_findings,
    ),
    Scenario(
        slug="warning-optional-provenance",
        title="Evidence evaluation: WARNING",
        scan_id="synthetic-warning-001",
        expected_status="WARNING",
        covers=("WARNING",),
        purpose=(
            "Required checks pass, but one occurrence omits optional collection "
            "provenance, which is a specifically defined exception naming that "
            "occurrence."
        ),
        build=_build_warning,
    ),
    Scenario(
        slug="incomplete-partial-execution",
        title="Evidence evaluation: INCOMPLETE with matching integrity",
        scan_id="synthetic-partial-001",
        expected_status="INCOMPLETE",
        covers=(
            "INCOMPLETE",
            "matching integrity with incomplete execution",
            "partial findings plus a recorded scanner failure",
        ),
        build=_build_partial_execution,
        purpose=(
            "The stored digest matches and the partial findings are retained and "
            "referenced, yet a recorded scanner failure means completion was never "
            "established: integrity passing does not make execution complete."
        ),
    ),
    Scenario(
        slug="incomplete-unknown-scan-time",
        title="Evidence evaluation: INCOMPLETE with an unreadable historical scan time",
        scan_id="synthetic-unknown-time-001",
        expected_status="INCOMPLETE",
        covers=("INCOMPLETE", "missing or invalid historical scan time"),
        purpose=(
            "The recorded scan time cannot be read, so every time-based derivation "
            "is reported as unknown. No collection time is invented, and the "
            "exporting clock is never substituted for the historical one."
        ),
        build=_build_unknown_scan_time,
    ),
    Scenario(
        slug="incomplete-unsupported-history",
        title="Evidence evaluation: INCOMPLETE with an unsupported historical contract",
        scan_id="synthetic-unsupported-001",
        expected_status="INCOMPLETE",
        covers=("INCOMPLETE", "unsupported historical schema or collection contract"),
        purpose=(
            "A declared collection contract this policy does not document, and a "
            "stored finding schema version this release does not recognize. The "
            "evidence is still retained and referenced, but neither gap can "
            "silently become VERIFIED."
        ),
        build=_build_unsupported_contract,
    ),
    Scenario(
        slug="failed-reference-consistency",
        title="Evidence evaluation: FAILED",
        scan_id="synthetic-failed-001",
        expected_status="FAILED",
        covers=("FAILED",),
        purpose=(
            "A required reference-consistency check completed and failed: a stored "
            "snapshot names a different scan than the run that holds it."
        ),
        build=_build_failed_reference,
    ),
    Scenario(
        slug="warning-unrecognized-fields",
        title="Evidence evaluation: WARNING with withheld unrecognized field values",
        scan_id="synthetic-unrecognized-fields-001",
        expected_status="WARNING",
        covers=(
            "WARNING",
            "unknown-field name disclosure and value withholding",
            "local-retention disclosure",
        ),
        purpose=(
            "A stored snapshot carrying an unknown top-level field and an unknown "
            "direct provenance member, written by a writer this release does not "
            "fully recognize. Both formats disclose the field names, withhold the "
            "values, and state that the values remain in the local verified store "
            "under the existing digest."
        ),
        build=_build_unrecognized_fields,
        rewrite=_add_unrecognized_fields,
    ),
    Scenario(
        slug="duplicate-finding-ids",
        title="Duplicate finding IDs that stay separate occurrences",
        scan_id="synthetic-duplicate-ids-001",
        expected_status="VERIFIED",
        covers=("duplicate finding IDs that remain separate by ordinal",),
        purpose=(
            "Two occurrences share one finding ID. They are referenced separately "
            "by scan ID plus ordinal plus finding ID, and are never collapsed into "
            "one piece of evidence."
        ),
        build=_build_duplicate_ids,
    ),
)


# --- generation ------------------------------------------------------------


#: Every module the CLI export path runs through. The CLI subprocess must
#: resolve each one to the very file this process imported, so the committed
#: corruption diagnostic can never come from a different implementation than
#: the samples beside it.
_CLI_MODULES = (
    "harvestguard",
    "harvestguard_version",
    "evidence_store",
    "executive_evidence",
    "executive_reports",
    "findings",
    "reports",
)


class CliMismatchError(RuntimeError):
    """The CLI available to run is not the implementation this helper imported."""


def _imported_from_checkout() -> bool:
    return Path(evidence_store.__file__).resolve().parent == _REPO_ROOT


def _installed_console_script() -> Path:
    """The console script installed by the distribution this helper imported.

    Only the script next to the running interpreter is considered, and only if
    the installed distribution that owns the imported `evidence_store` also
    records that script and declares this release's version. Nothing is looked
    up on `PATH`: an older install elsewhere on the machine must never answer
    for the code under review.
    """
    from importlib import metadata

    imported = Path(evidence_store.__file__).resolve()
    script_name = "harvestguard.exe" if os.name == "nt" else "harvestguard"
    # Not resolved: a virtual environment's `bin/python` is a symlink to the
    # base interpreter, and resolving it would look for the console script next
    # to *that* instead of in the environment actually in use.
    script = Path(sys.executable).parent / script_name
    for distribution in metadata.distributions(name="harvestguard"):
        owned = {
            Path(str(distribution.locate_file(entry))).resolve()
            for entry in distribution.files or ()
        }
        if imported not in owned:
            continue
        if distribution.version != HARVESTGUARD_VERSION:
            raise CliMismatchError(
                f"installed harvestguard distribution is {distribution.version}, "
                f"but the imported modules report {HARVESTGUARD_VERSION}"
            )
        if not script.exists() or script.resolve() not in owned:
            raise CliMismatchError(
                f"{script} is not the console script installed with the imported "
                f"harvestguard distribution ({imported.parent})"
            )
        return script
    raise CliMismatchError(
        f"no installed harvestguard distribution owns the imported {imported}"
    )


def _verify_cli_imports(python: str, environment: dict[str, str], cwd: Path) -> None:
    """Fail unless a CLI subprocess would import exactly what this process did."""
    expected = {name: str(Path(sys.modules[name].__file__).resolve()) for name in _CLI_MODULES}
    probe = (
        "import importlib, json, pathlib\n"
        f"names = {list(_CLI_MODULES)!r}\n"
        "print(json.dumps({n: str(pathlib.Path(importlib.import_module(n).__file__)"
        ".resolve()) for n in names}))\n"
    )
    completed = subprocess.run(
        [python, "-c", probe],
        capture_output=True,
        text=True,
        cwd=str(cwd),
        env=environment,
        check=False,
    )
    if completed.returncode != 0:
        raise CliMismatchError(
            f"could not confirm the CLI's modules: {completed.stderr.strip()[-500:]}"
        )
    actual = json.loads(completed.stdout)
    mismatched = {name: actual.get(name) for name in expected if actual.get(name) != expected[name]}
    if mismatched:
        raise CliMismatchError(
            "the CLI would import a different implementation than this helper: "
            + "; ".join(f"{name}: {mismatched[name]} != {expected[name]}" for name in mismatched)
        )


def _cli_invocation(cwd: Path) -> tuple[list[str], dict[str, str]]:
    """The real CLI for the implementation this helper imported, verified.

    Imported from an installed distribution, that distribution's own console
    script is used. Imported from this checkout, the same entry point is run
    as a module with the repository root first on `PYTHONPATH`. Either way the
    subprocess's module resolution is checked against this process' before
    anything runs, and a mismatch raises `CliMismatchError` rather than mixing
    implementations. No fallback to a `harvestguard` found on `PATH` exists.
    """
    import harvestguard  # noqa: F401 - imported so its origin can be compared

    environment = dict(os.environ)
    if _imported_from_checkout():
        existing = environment.get("PYTHONPATH")
        environment["PYTHONPATH"] = (
            f"{_REPO_ROOT}{os.pathsep}{existing}" if existing else str(_REPO_ROOT)
        )
        command = [sys.executable, "-m", "harvestguard"]
    else:
        command = [str(_installed_console_script())]
    _verify_cli_imports(sys.executable, environment, cwd)
    return command, environment


def export_command(scan_id: str, db_path: str, mode: str, output: str) -> str:
    """The exact documented CLI command for one export, for the manifest."""
    return (
        f"harvestguard evidence export {scan_id} --evidence-db {db_path} "
        f"--{mode} {output}"
    )


def _corrupt_one_snapshot(db: Path, scan_id: str) -> None:
    """Change a stored snapshot without re-digesting it.

    Runs against a disposable copy only: the original fixture database, and any
    real evidence, is left exactly as it was. This models on-disk corruption or
    modification, which the existing loader must reject.
    """
    connection = sqlite3.connect(str(db))
    try:
        with connection:
            row = connection.execute(
                "SELECT finding_json FROM scan_findings WHERE scan_id = ? ORDER BY ordinal "
                "LIMIT 1",
                (scan_id,),
            ).fetchone()
            if row is None:
                raise RuntimeError(f"no stored snapshot to corrupt for {scan_id}")
            snapshot = json.loads(row[0])
            snapshot["location"] = f"{TARGET_PATH}/app/MODIFIED-AFTER-STORAGE.py:1"
            connection.execute(
                "UPDATE scan_findings SET finding_json = ? WHERE scan_id = ? AND ordinal = 0",
                (json.dumps(snapshot, separators=(",", ":")), scan_id),
            )
    finally:
        connection.close()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _artifact_record(root: Path, path: Path) -> dict[str, object]:
    return {
        "path": path.relative_to(root).as_posix(),
        "bytes": path.stat().st_size,
        "sha256": _sha256(path),
    }


def _write(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def _refuse_occupied_work_dir(work_dir: Path) -> None:
    """Never write over something already in the work directory.

    This helper cannot tell a leftover fixture database from an evidence
    database someone needs to keep, so it refuses both rather than deleting or
    overwriting either. Checked before anything is created, so a refused run
    leaves the directory exactly as it was.
    """
    occupied = [name for name in WORK_DIR_ARTIFACTS if (work_dir / name).exists()]
    if occupied:
        raise FileExistsError(
            f"refusing to write into {work_dir}: it already holds "
            f"{', '.join(occupied)}. This helper never deletes or overwrites an "
            "existing evidence database or output file. Pass --work-dir pointing "
            "at a new or empty directory, or omit it to use a temporary one."
        )


def generate(output_dir: Path, work_dir: Path) -> dict[str, object]:
    """Generate every sample plus the provenance manifest. Returns the manifest."""
    output_dir = Path(output_dir)
    # Pinned absolute while this process' working directory is still the
    # caller's: the corruption example runs the real CLI with `cwd` set to the
    # work directory, so a relative `--work-dir` (the documented `./eev-work`)
    # would otherwise be resolved a second time against that cwd and point at
    # `eev-work/eev-work/...`.
    work_dir = Path(work_dir).resolve()
    _refuse_occupied_work_dir(work_dir)
    work_dir.mkdir(parents=True, exist_ok=True)
    samples_dir = output_dir / SAMPLES_DIR
    samples_dir.mkdir(parents=True, exist_ok=True)

    db = work_dir / DB_NAME

    scenario_records: list[dict[str, object]] = []

    for scenario in SCENARIOS:
        context, findings = scenario.build(scenario.scan_id)
        digest = store_scan_run(
            db, scan_id=scenario.scan_id, context=context, findings=findings
        )
        if scenario.rewrite is not None:
            _rewrite_snapshots(db, scenario.scan_id, scenario.rewrite)
        # The verifying loader, then the one shared projection, then both
        # serializers -- exactly what the CLI export modes do.
        stored = load_scan_run(db, scenario.scan_id)
        digest = stored.evidence_digest
        view = build_executive_evidence_view(stored, export_time=EXPORT_TIME)
        if view.status != scenario.expected_status:
            raise RuntimeError(
                f"{scenario.slug}: fixture produced {view.status}, "
                f"expected {scenario.expected_status}"
            )
        json_path = _write(samples_dir / f"{scenario.slug}.json", executive_json(view) + "\n")
        markdown_path = _write(
            samples_dir / f"{scenario.slug}.md", format_executive_markdown(view)
        )
        scenario_records.append({
            "slug": scenario.slug,
            "title": scenario.title,
            "covers": list(scenario.covers),
            "purpose": scenario.purpose,
            "evidence_label": "synthetic",
            "scan_id": scenario.scan_id,
            "evidence_evaluation": view.status,
            "recorded_scan_time": context.scan_time,
            "scan_time_basis": view.scan_time_basis,
            "export_time": view.export_time,
            "scope": {
                "target_path": context.target_path,
                "scan_type": context.scan_type,
                "scanners": list(context.scanners),
                "scanner_versions": dict(context.scanner_versions),
                "excluded_paths": list(context.excluded_paths),
                "scope_constraints": list(context.scope_constraints),
                "crypto_files_inspected": context.crypto_files_inspected,
            },
            "scanner_errors": list(context.scanner_errors),
            "collection_provenance": sorted({
                f"{finding.collection_method or 'unrecorded'} / "
                f"{finding.collection_source or 'unrecorded'}"
                for finding in findings
            }),
            "stored_finding_count": len(findings),
            "evidence_digest": digest,
            "commands": [
                export_command(
                    scenario.scan_id, f"./{DB_NAME}", "executive-json", f"{scenario.slug}.json"
                ),
                export_command(
                    scenario.scan_id, f"./{DB_NAME}", "executive-markdown", f"{scenario.slug}.md"
                ),
            ],
            "artifacts": [
                _artifact_record(output_dir, json_path),
                _artifact_record(output_dir, markdown_path),
            ],
        })

    corruption = _generate_corruption_example(output_dir, work_dir, db)
    scenario_records.append(corruption)

    manifest = {
        "collection": "docs/examples/executive-evidence-view",
        "issue": "https://github.com/serewicz/HarvestGuard/issues/153",
        "evidence_label": SYNTHETIC_LABEL,
        "regeneration": {
            "command": (
                "python docs/examples/executive-evidence-view/generate_examples.py"
            ),
            "deterministic": True,
            "explicit_export_time": EXPORT_TIME,
            "export_time_note": (
                "The installed CLI reads its own UTC clock for the export time and "
                "has no public override, so committed samples are generated by "
                "passing this explicit export time to the same installed "
                "projection API the CLI calls. A live CLI export of the same "
                "fixture differs only in export_time."
            ),
            "evidence_database": (
                f"{DB_NAME} is generated into a work directory and is not committed; "
                "treat any generated evidence database or report as a sensitive "
                "artifact."
            ),
        },
        "versions": {
            "producing_harvestguard_version": HARVESTGUARD_VERSION,
            "exporting_harvestguard_version": HARVESTGUARD_VERSION,
            "executive_schema_version": EXECUTIVE_SCHEMA_VERSION,
            "executive_policy_version": EXECUTIVE_POLICY_VERSION,
            "finding_schema_version": FINDING_SCHEMA_VERSION,
            "evidence_store_schema_version": evidence_store.SCHEMA_VERSION,
            "version_note": (
                "Producer and exporter are the same release here because these "
                "fixtures are generated, not historical. The stored runs that "
                "model historical gaps declare unsupported contract and schema "
                "versions in their own evidence; no historical record is upgraded "
                "or rewritten to match this release."
            ),
        },
        "scenarios": scenario_records,
    }
    _write(output_dir / MANIFEST_NAME, json.dumps(manifest, indent=2, sort_keys=False) + "\n")
    return manifest


def _generate_corruption_example(
    output_dir: Path, work_dir: Path, source_db: Path
) -> dict[str, object]:
    """Capture the bounded diagnostic a corrupted run produces -- and no report.

    The corruption happens in a disposable copy of the synthetic fixture. The
    real CLI is then asked for both executive exports; each must fail closed
    with a bounded stderr diagnostic naming the requested run and the failed
    check, emit no evidence payload, and write no file.

    Both work-directory paths used here -- the disposable copy and the output
    the CLI must refuse to write -- were checked as unoccupied before anything
    was generated, so nothing pre-existing is copied over.
    """
    scan_id = SCENARIOS[0].scan_id
    corrupted_db = work_dir / CORRUPTION_DB_NAME
    shutil.copy2(source_db, corrupted_db)
    _corrupt_one_snapshot(corrupted_db, scan_id)

    transcript: list[str] = [
        "# Bounded failure output for a corrupted stored run",
        "#",
        "# Generated by docs/examples/executive-evidence-view/generate_examples.py",
        "# against a disposable copy of the synthetic fixture database. One stored",
        "# snapshot was modified after storage without re-digesting it; the",
        "# original fixture is untouched.",
        "#",
        "# Both executive export modes fail closed: exit 1, a bounded stderr",
        "# diagnostic naming the requested run and the failed check, no evidence",
        "# payload on stdout, and no output file. No normal evidence report is",
        "# ever constructed from rejected evidence.",
        "",
    ]
    commands: list[str] = []
    command_prefix, environment = _cli_invocation(work_dir)
    for mode, destination in (
        ("executive-json", "-"),
        ("executive-markdown", REJECTED_OUTPUT_NAME),
    ):
        target = work_dir / destination if destination != "-" else None
        argv = [
            "evidence",
            "export",
            scan_id,
            "--evidence-db",
            str(corrupted_db),
            f"--{mode}",
            destination if destination == "-" else str(target),
        ]
        completed = subprocess.run(
            [*command_prefix, *argv],
            capture_output=True,
            text=True,
            cwd=str(work_dir),
            env=environment,
            check=False,
        )
        commands.append(
            export_command(scan_id, f"./{CORRUPTION_DB_NAME}", mode, destination)
        )
        transcript.extend([
            f"$ {commands[-1]}",
            f"exit status: {completed.returncode}",
            f"stdout bytes: {len(completed.stdout)}",
            "stderr:",
            completed.stderr.strip().replace(str(corrupted_db), f"./{CORRUPTION_DB_NAME}"),
            f"output file written: {'yes' if target and target.exists() else 'no'}",
            "",
        ])
        # A sample is only worth committing if it shows the *integrity* failure.
        # Any other nonzero exit (a broken invocation, say) would look like a
        # bounded rejection while proving nothing about failing closed.
        if (
            completed.returncode == 0
            or completed.stdout.strip()
            or "failed integrity verification" not in completed.stderr
            or (target is not None and target.exists())
        ):
            raise RuntimeError(
                f"corruption example did not fail closed for --{mode}: "
                f"exit {completed.returncode}, {len(completed.stdout)} stdout bytes, "
                f"stderr {completed.stderr.strip()!r}"
            )

    diagnostic = _write(
        output_dir / SAMPLES_DIR / CORRUPTION_DIAGNOSTIC, "\n".join(transcript)
    )
    corrupted_db.unlink()
    return {
        "slug": "failed-integrity-corruption",
        "title": "Rejected evidence: bounded failure, no report",
        "covers": (
            "bounded corruption or integrity failure that emits no normal evidence report",
        ),
        "purpose": (
            "A stored snapshot modified after storage without re-digesting it. The "
            "existing loader rejects the run, so no view is built and no evidence "
            "report is emitted -- only a bounded diagnostic."
        ),
        "evidence_label": "synthetic (disposable copy; original fixture preserved)",
        "scan_id": scan_id,
        "evidence_evaluation": "not evaluated: evidence rejected before projection",
        "commands": commands,
        "artifacts": [_artifact_record(output_dir, diagnostic)],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--output-dir",
        default=str(Path(__file__).resolve().parent),
        help="Where to write samples/ and the manifest (default: this directory)",
    )
    parser.add_argument(
        "--work-dir",
        default=None,
        help=(
            "Where to build the evidence database. Must be a new or empty "
            "directory: an existing database is never deleted or overwritten. "
            "Omitted, a temporary directory is used and the database is "
            "discarded; pass a path to keep it and run the documented CLI "
            "commands against it yourself."
        ),
    )
    args = parser.parse_args(argv)

    try:
        if args.work_dir:
            work_dir = Path(args.work_dir)
            manifest = generate(Path(args.output_dir), work_dir)
            print(f"Evidence database: {work_dir / DB_NAME} (sensitive artifact)")
        else:
            with tempfile.TemporaryDirectory(prefix="harvestguard-examples-") as temporary:
                manifest = generate(Path(args.output_dir), Path(temporary))
    except FileExistsError as refusal:
        print(refusal, file=sys.stderr)
        return 1

    scenarios = manifest["scenarios"]
    assert isinstance(scenarios, list)
    print(f"Wrote {len(scenarios)} scenarios to {Path(args.output_dir) / SAMPLES_DIR}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
