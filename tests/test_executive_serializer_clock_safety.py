"""Clock-free import and execution for the executive serializers (#152 review).

`executive_reports.py` used to discover the canonical recognized-field order by
constructing a throwaway `NormalizedFinding` probe at module import time.
`NormalizedFinding.__post_init__` calls `datetime.now(timezone.utc)` whenever
`observed_at` is not explicitly supplied, so importing the serializer read the
current clock -- silently, and only at import time, which the existing
in-process clock-trap test (`test_serializers_never_read_the_clock` in
`tests/test_executive_exports.py`) could not catch: by the time that test runs,
some earlier test module has already imported `executive_reports`, so the
probe construction (and its clock read) already happened before the trap was
installed.

These tests run in a fresh subprocess instead, so the trap can be installed
*before* `executive_reports` (or `findings`) is ever imported in that process,
actually exercising import time. The trap patches only the `datetime` name
inside each already-imported module's own namespace (the same technique the
existing `monkeypatch.setattr("executive_evidence.datetime", ForbiddenClock)`
test already uses) -- never the global `datetime.datetime` class itself.
Replacing the global class breaks pandas/numpy's C-level datetime bindings
(they cross-check `datetime.datetime`'s C struct layout at import time) and
was observed to hang the interpreter outright; a per-module attribute patch
touches nothing but a plain Python module's own `__dict__` and is safe.

The fix moved the field-order contract to two explicit tuples in findings.py
(`NORMALIZED_FINDING_FIELD_ORDER`, `PROVENANCE_FIELD_ORDER`) that `to_dict()`
itself is built from -- no NormalizedFinding is ever constructed merely to
discover order.
"""

from __future__ import annotations

import subprocess
import sys
import textwrap
from pathlib import Path

ROOT = Path(__file__).parent.parent

# Imports `datetime` for real (safe -- this never touches the global class),
# then replaces the `datetime` name inside `findings`', `reports`' and
# `executive_evidence`'s own already-imported module namespaces with a
# subclass whose `now()` raises. Any of those three modules calling
# `datetime.now()` afterward -- including as a side effect of importing
# `executive_reports`, which depends on `findings` -- fails loudly.
_CLOCK_TRAP_PREAMBLE = """
import datetime as _real_datetime_module

class ForbiddenClock(_real_datetime_module.datetime):
    @classmethod
    def now(cls, tz=None):
        raise AssertionError("must not read the clock: " + repr(tz))

import findings
import reports
findings.datetime = ForbiddenClock
reports.datetime = ForbiddenClock
"""


def _run(script: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-c", script],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


def test_serializer_import_does_not_read_the_clock():
    """Importing executive_reports (and executive_evidence) must not call
    datetime.now() through findings.py or reports.py.
    """
    script = _CLOCK_TRAP_PREAMBLE + textwrap.dedent(
        """
        import executive_evidence
        executive_evidence.datetime = ForbiddenClock

        import executive_reports  # noqa: F401
        print("import-ok")
        """
    )
    completed = _run(script)
    assert completed.returncode == 0, completed.stderr[-2000:]
    assert completed.stdout.strip() == "import-ok"


def test_serializer_execution_does_not_read_the_clock():
    """Building and serializing a stored run end to end, with the clock
    trapped before `executive_reports` is imported, must succeed without ever
    calling datetime.now().

    Constructs a real stored run and a real projection inside the subprocess
    (rather than passing one in), so field-order discovery, projection
    construction and both serializers are all covered by the same trap.
    """
    script = _CLOCK_TRAP_PREAMBLE + textwrap.dedent(
        """
        import json
        import tempfile
        from pathlib import Path

        import executive_evidence
        executive_evidence.datetime = ForbiddenClock

        from evidence_store import store_scan_run, load_scan_run
        from executive_evidence import build_executive_evidence_view
        from executive_reports import executive_json, format_executive_markdown
        from findings import NormalizedFinding
        from reports import make_report_context

        # A real datetime built with explicit arguments, never `.now()` --
        # safe even with the clock trapped.
        scan_time = _real_datetime_module.datetime(
            2024, 3, 4, 5, 6, 7, tzinfo=_real_datetime_module.timezone.utc
        )

        finding = NormalizedFinding(
            scan_id="run-1",
            source_type="code_analysis",
            asset_type="source_code",
            location="app.py:3",
            scanner_name="semgrep_crypto_rules",
            scanner_version="0.2.0",
            observed_at=scan_time,
            evidence="Semgrep rule matched: weak-hash-md5",
            confidence="High",
            rule_id="weak-hash-md5",
            collection_method="static source-text match",
            collection_source="vendored semgrep rule set",
            repeatable=True,
            verification_rationale="re-running the same rule set reproduces the match",
        )
        context = make_report_context(
            target_path="/target",
            started_at=scan_time,
            duration_seconds=1.5,
            scan_type="code",
            scanners=["code analysis"],
            scanner_versions={"semgrep_crypto_rules": "0.2.0"},
            scan_id="run-1",
        )
        db = Path(tempfile.mkdtemp()) / "clock-trap-run.sqlite"
        store_scan_run(db, scan_id="run-1", context=context, findings=[finding])
        stored = load_scan_run(db, "run-1")
        view = build_executive_evidence_view(
            stored, export_time="2026-09-10T00:00:00+00:00"
        )
        document = json.loads(executive_json(view))
        markdown = format_executive_markdown(view)
        assert document["scan_id"] == "run-1"
        assert markdown.startswith("# HarvestGuard Executive Evidence View")
        print("execution-ok")
        """
    )
    completed = _run(script)
    assert completed.returncode == 0, completed.stderr[-2000:]
    assert completed.stdout.strip().splitlines()[-1] == "execution-ok"
