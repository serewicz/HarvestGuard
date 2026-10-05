"""Regression coverage for the published executive-evidence examples (#153).

`docs/examples/executive-evidence-view/` publishes one sample per required
evaluation outcome so a reader can see the real output before installing
anything, and holds the acceptance materials for issue #153. Because those
files are published and are cited as acceptance evidence, they have to stay
true: regenerating them from the real implementation must reproduce them
byte-for-byte, every published command must be a command the shipped CLI
actually accepts, both formats must keep saying the same thing, no withheld
value may leak into them, and the acceptance records must not claim human
results that have not happened.

These tests exercise the implementation rather than searching for headings:
every assertion is made against output regenerated through
`evidence_store` -> verified load -> the shared projection -> both serializers,
or against the real CLI run as a subprocess.

Two levels of "real", kept apart deliberately. Most tests here regenerate the
collection in-process, which reaches this checkout's modules. That is not what
a reader installs, so the last section regenerates the whole collection again
from a *non-editable install*, runs the shipped console script from a directory
outside the checkout with no `PYTHONPATH` and no repository import override,
and requires the committed bytes either way.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import socket
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
COLLECTION = ROOT / "docs" / "examples" / "executive-evidence-view"
SAMPLES = COLLECTION / "samples"
MANIFEST = COLLECTION / "manifest.json"
GENERATOR = COLLECTION / "generate_examples.py"
README = COLLECTION / "README.md"

# Every outcome the issue requires the bounded collection to cover. The
# manifest's per-scenario `covers` entries are the claim; this list is the
# contract they are checked against.
REQUIRED_COVERAGE = (
    "VERIFIED",
    "WARNING",
    "INCOMPLETE",
    "FAILED",
    "legitimate zero-finding run",
    "matching integrity with incomplete execution",
    "partial findings plus a recorded scanner failure",
    "missing or invalid historical scan time",
    "unsupported historical schema or collection contract",
    "duplicate finding IDs that remain separate by ordinal",
    "bounded corruption or integrity failure that emits no normal evidence report",
    "unknown-field name disclosure and value withholding",
    "local-retention disclosure",
)

# Shapes that must never appear in a published artifact. These are the
# credential/secret forms a careless example could plausibly carry; the canary
# is the synthetic value the generator stores in an *unrecognized* field
# precisely so a disclosure view has something to withhold.
FORBIDDEN_PATTERNS = (
    re.compile(r"SYNTHETIC-CANARY-VALUE"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bghp_[A-Za-z0-9]{20,}"),
    re.compile(r"(?i)\b(password|passphrase|secret_key|api_key)\s*[=:]\s*\S+"),
    # An email address would be participant-identifying data.
    re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
)


def _load_generator():
    """Import generate_examples.py by path -- docs/ is not an importable package."""
    spec = importlib.util.spec_from_file_location("eev_generate_examples", GENERATOR)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # Registered before execution: the module defines a dataclass, and
    # `dataclasses` resolves annotations through `sys.modules[cls.__module__]`.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def generator():
    return _load_generator()


@pytest.fixture(scope="module")
def manifest():
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def regenerated(tmp_path_factory, generator):
    """One fresh generation of the whole collection, plus its evidence store."""
    output = tmp_path_factory.mktemp("eev-output")
    work = tmp_path_factory.mktemp("eev-work")
    result = generator.generate(output, work)
    return output, work, result


def _json_samples() -> list[Path]:
    return sorted(SAMPLES.glob("*.json"))


def _markdown_for(json_path: Path) -> Path:
    return json_path.with_suffix(".md")


def _references(document: dict) -> list[dict]:
    """Every evidence reference a document makes, from every record kind."""
    found = []
    for section in ("checks", "exceptions", "observations", "conclusions"):
        for record in document.get(section, []):
            found.extend(record.get("references", []))
    return found


# --- the collection is exactly what the implementation produces -------------


def test_committed_collection_matches_a_fresh_generation(regenerated):
    """Every committed byte is reproducible from the real path, with a fixed time."""
    output, _work, _result = regenerated
    generated = {
        path.relative_to(output).as_posix(): path.read_bytes()
        for path in sorted(output.rglob("*"))
        if path.is_file()
    }
    committed = {
        path.relative_to(COLLECTION).as_posix(): path.read_bytes()
        for path in [MANIFEST, *sorted(SAMPLES.iterdir())]
    }
    assert set(generated) == set(committed), (
        "regeneration produced a different set of artifacts; rerun "
        "`python docs/examples/executive-evidence-view/generate_examples.py`"
    )
    for name, content in committed.items():
        assert generated[name] == content, (
            f"{name} is stale; rerun the generator "
            "(a HarvestGuard version change also requires regeneration)"
        )


def test_generation_is_deterministic(tmp_path, generator):
    """Same fixtures, same explicit export time, same bytes -- twice over."""
    first = tmp_path / "first"
    second = tmp_path / "second"
    generator.generate(first, tmp_path / "work-1")
    generator.generate(second, tmp_path / "work-2")
    for path in sorted(first.rglob("*")):
        if path.is_file():
            assert path.read_bytes() == (second / path.relative_to(first)).read_bytes()


def test_generation_needs_no_network(tmp_path, generator, monkeypatch):
    """No hosted service, account, telemetry or upload in the example path."""

    def refuse(*args, **kwargs):
        raise AssertionError("the example path must not open a socket")

    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    generator.generate(tmp_path / "offline", tmp_path / "offline-work")


# --- generation never destroys what is already there -----------------------

# Every path the generator writes inside the work directory. Pinned here so the
# refusal is proven per destination, not only for the database.
WORK_DIR_DESTINATIONS = (
    "example-evidence.sqlite",
    "corrupted-copy.sqlite",
    "rejected-run.md",
)
PRE_EXISTING = b"pre-existing bytes that are not the generator's to remove"


def test_the_refused_destinations_are_the_ones_the_generator_writes(generator):
    assert set(generator.WORK_DIR_ARTIFACTS) == set(WORK_DIR_DESTINATIONS)


def test_generation_refuses_a_work_dir_holding_an_evidence_database(tmp_path, generator):
    """A database in the work directory may be someone's real evidence.

    The generator cannot tell a leftover fixture from evidence that has to
    survive, so it refuses rather than deleting or overwriting either. What
    matters is that the pre-existing run is still there, byte-identical, and
    still passes the verifying loader afterwards.
    """
    import evidence_store

    work = tmp_path / "work"
    work.mkdir()
    database = work / "example-evidence.sqlite"
    context, findings = generator._build_verified("pre-existing-run")
    evidence_store.store_scan_run(
        database, scan_id="pre-existing-run", context=context, findings=findings
    )
    before = database.read_bytes()
    output = tmp_path / "output"

    with pytest.raises(FileExistsError):
        generator.generate(output, work)

    assert database.read_bytes() == before
    stored = evidence_store.load_scan_run(database, "pre-existing-run")
    assert stored.scan_id == "pre-existing-run"
    # A refused run writes nothing anywhere: no second database, no samples.
    assert [path.name for path in work.iterdir()] == ["example-evidence.sqlite"]
    assert not output.exists()


@pytest.mark.parametrize("name", WORK_DIR_DESTINATIONS)
def test_generation_refuses_every_occupied_work_dir_destination(tmp_path, generator, name):
    work = tmp_path / "work"
    work.mkdir()
    occupied = work / name
    occupied.write_bytes(PRE_EXISTING)

    with pytest.raises(FileExistsError):
        generator.generate(tmp_path / "output", work)

    assert occupied.read_bytes() == PRE_EXISTING


# --- required coverage and recorded provenance -----------------------------


def test_every_required_outcome_is_covered(manifest):
    covered = {item for scenario in manifest["scenarios"] for item in scenario["covers"]}
    assert set(REQUIRED_COVERAGE) <= covered


def test_manifest_records_the_required_provenance(manifest):
    versions = manifest["versions"]
    for field in (
        "producing_harvestguard_version",
        "exporting_harvestguard_version",
        "executive_schema_version",
        "executive_policy_version",
        "finding_schema_version",
        "evidence_store_schema_version",
    ):
        assert versions[field], f"{field} is not recorded"
    assert manifest["regeneration"]["explicit_export_time"]

    for scenario in manifest["scenarios"]:
        assert scenario["evidence_label"].startswith("synthetic")
        assert scenario["commands"], f"{scenario['slug']} records no command"
        for artifact in scenario["artifacts"]:
            path = COLLECTION / artifact["path"]
            assert path.is_file()
            assert path.stat().st_size == artifact["bytes"]
            import hashlib

            assert hashlib.sha256(path.read_bytes()).hexdigest() == artifact["sha256"]
        if scenario["slug"] == "failed-integrity-corruption":
            continue
        scope = scenario["scope"]
        assert scope["target_path"] and scope["scanners"] and scope["scanner_versions"]
        assert scenario["recorded_scan_time"]
        assert scenario["export_time"] == manifest["regeneration"]["explicit_export_time"]
        assert scenario["collection_provenance"] is not None
        assert scenario["evidence_digest"]


def test_versions_recorded_match_the_installed_release(manifest):
    from executive_evidence import EXECUTIVE_POLICY_VERSION, EXECUTIVE_SCHEMA_VERSION
    from findings import SCHEMA_VERSION as FINDING_SCHEMA_VERSION
    from harvestguard_version import __version__

    versions = manifest["versions"]
    assert versions["producing_harvestguard_version"] == __version__
    assert versions["exporting_harvestguard_version"] == __version__
    assert versions["executive_schema_version"] == EXECUTIVE_SCHEMA_VERSION
    assert versions["executive_policy_version"] == EXECUTIVE_POLICY_VERSION
    assert versions["finding_schema_version"] == FINDING_SCHEMA_VERSION


# --- what the samples say ---------------------------------------------------


@pytest.mark.parametrize("sample", _json_samples(), ids=lambda path: path.stem)
def test_sample_status_agrees_with_the_manifest_and_the_markdown(sample, manifest):
    document = json.loads(sample.read_text(encoding="utf-8"))
    recorded = next(
        scenario for scenario in manifest["scenarios"] if scenario["slug"] == sample.stem
    )
    assert document["status"] == recorded["evidence_evaluation"]
    markdown = _markdown_for(sample).read_text(encoding="utf-8")
    assert f"**Evidence evaluation: {document['status']}**" in markdown
    # Status is never cherry-picked from passes: every reason names what it
    # rests on, and an empty required-check set could not produce one.
    assert document["status_reasons"]
    for reason in document["status_reasons"]:
        assert reason["check_ids"] or reason["exception_ids"]


# Semantic parity is checked record by record. The Markdown is parsed back into
# its records -- each check, exception, observation, conclusion, status reason
# and evidence occurrence, with every labelled line under it -- and each record
# is compared, in order, with the complete values of the corresponding JSON
# record. Finding an ID or a state word *somewhere* in the Markdown is not
# enough: a state, method or reference attached to the wrong record, or a
# missing statement, has to fail. This parser is written against the published
# Markdown layout, independently of the serializer's own helpers.

_HEADING_OBSERVED = "What HarvestGuard observed"
_HEADING_CHECKS = "Evidence checks and limitations"
_HEADING_EXCEPTIONS = "Defined exceptions"
_HEADING_CONCLUSIONS = "Supported conclusions and limits"
_HEADING_TECHNICAL = "Technical evidence detail"
_OBSERVED_FIXED = ("Record counts", "Declared scope", "Recorded scanner errors")
_CONCLUSIONS_FIXED = ("What this view could not establish", "Standing limits")
_EVIDENCE_LINK = re.compile(
    r"^\[(?P<scan>.+?) ordinal (?P<ordinal>\d+) \(finding ID (?P<finding>.*)\)\]"
    r"\(#(?P<anchor>[^)\s]+)\)$"
)
_ANCHOR = re.compile(r'^<a id="(?P<anchor>[^"]+)"></a>$')


def _unescape(text: str) -> str:
    """Undo the Markdown backslash escapes, leaving the stored text."""
    return re.sub(r"\\(.)", r"\1", text)


def _flat(value) -> str:
    """A stored text value as it has to read on one Markdown line."""
    text = "" if value is None else str(value)
    return text.replace("\r\n", " ").replace("\r", " ").replace("\n", " ").replace("\t", " ")


def _cell(value) -> str:
    """One stored value as its table cell has to read."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float, str)):
        return _flat(value)
    return json.dumps(value, sort_keys=False)


def _yes_no(value: bool) -> str:
    return "yes" if value else "no"


def _parse_markdown(markdown: str) -> dict[str, list[dict]]:
    """Split the Markdown into `##` sections, each a list of `###` records.

    Each record keeps its heading, its labelled `- Key: value` lines in order,
    its table rows, its plain bullets, and the anchor placed directly before it.
    Lines before the first `###` of a section form an unnamed leading record.
    """
    sections: dict[str, list[dict]] = {}
    current: list[dict] | None = None
    record: dict | None = None
    pending_anchor = None

    def new_record(heading):
        nonlocal pending_anchor
        item = {"heading": heading, "lines": [], "anchor": pending_anchor}
        pending_anchor = None
        return item

    for line in markdown.splitlines():
        if line.startswith("## "):
            current = sections.setdefault(_unescape(line[3:]), [])
            record = new_record(None)
            current.append(record)
            continue
        if current is None:
            continue
        if line.startswith("### "):
            record = new_record(_unescape(line[4:]))
            current.append(record)
            continue
        anchor = _ANCHOR.match(line)
        if anchor:
            pending_anchor = anchor.group("anchor")
            continue
        record["lines"].append(line)
    return sections


def _labelled(record: dict) -> list[tuple[str, object]]:
    """Every `- Key: value` line of a record, in order; evidence links parsed."""
    found: list[tuple[str, object]] = []
    for line in record["lines"]:
        if not line.startswith("- ") or ": " not in line:
            continue
        key, _, value = line[2:].partition(": ")
        if key == "Evidence":
            link = _EVIDENCE_LINK.match(value)
            assert link is not None, f"unparseable evidence link: {line}"
            found.append((
                "Evidence",
                (
                    _unescape(link.group("scan")),
                    int(link.group("ordinal")),
                    _unescape(link.group("finding")),
                    link.group("anchor"),
                ),
            ))
        else:
            found.append((_unescape(key), _unescape(value)))
    return found


def _bullets(record: dict) -> list[str]:
    return [_unescape(line[2:]) for line in record["lines"] if line.startswith("- ")]


def _table(record: dict) -> list[list[str]]:
    """Table body rows of a record, split on unescaped pipes, header dropped."""
    rows = []
    for line in record["lines"]:
        if not line.startswith("|"):
            continue
        cells = [_unescape(cell.strip()) for cell in re.split(r"(?<!\\)\|", line)[1:-1]]
        rows.append(cells)
    return rows[2:]


def _expected_references(references: list[dict], anchors: dict[int, str]) -> list:
    return [
        (
            "Evidence",
            (
                reference["scan_id"],
                reference["ordinal"],
                reference["finding_id"] or "not recorded",
                anchors[reference["ordinal"]],
            ),
        )
        for reference in references
    ]


def _expected_explanation(record: dict, anchors: dict[int, str]) -> tuple[str, list]:
    labelled = [("Statement", _flat(record["statement"])), ("Method", _flat(record["method"]))]
    labelled += [("Identified check", check_id) for check_id in record["check_ids"]]
    labelled += [("Limitation", _flat(item)) for item in record["limitations"]]
    labelled += _expected_references(record["references"], anchors)
    return f"{record['explanation_id']} ({record['nature']})", labelled


def _records(section: list[dict], fixed: tuple[str, ...] = ()) -> list[dict]:
    return [record for record in section if record["heading"] and record["heading"] not in fixed]


def _named(section: list[dict], heading: str) -> dict:
    matches = [record for record in section if record["heading"] == heading]
    assert len(matches) == 1, f"expected exactly one '{heading}' subsection"
    return matches[0]


def _assert_markdown_parallels_json(document: dict, markdown: str) -> None:
    """Every JSON record appears in the Markdown with its complete values, in place."""
    sections = _parse_markdown(markdown)
    assert list(sections) == [
        "Overview",
        _HEADING_OBSERVED,
        _HEADING_CHECKS,
        _HEADING_EXCEPTIONS,
        _HEADING_CONCLUSIONS,
        _HEADING_TECHNICAL,
    ]
    scope = document["scope"]

    # Occurrences first: every reference elsewhere must point at one of these.
    occurrences = _records(sections[_HEADING_TECHNICAL])
    assert [record["heading"] for record in occurrences] == [
        f"Occurrence {occurrence['ordinal']}" for occurrence in document["evidence"]
    ]
    anchors: dict[int, str] = {}
    for occurrence, record in zip(document["evidence"], occurrences):
        assert record["anchor"], f"Occurrence {occurrence['ordinal']} has no anchor"
        anchors[occurrence["ordinal"]] = record["anchor"]
        assert _labelled(record)[0] == (
            "Complete reference",
            f"scan {document['scan_id']}, ordinal {occurrence['ordinal']}, finding ID "
            f"{occurrence['finding_id'] or 'not recorded'}",
        )
        expected_rows = []
        for name, value in occurrence["snapshot"].items():
            if name == "provenance" and isinstance(value, dict):
                expected_rows += [[f"provenance.{key}", _cell(item)] for key, item in value.items()]
            else:
                expected_rows.append([name, _cell(value)])
        assert _table(record) == expected_rows, f"Occurrence {occurrence['ordinal']} fields"
        withheld = [line for line in record["lines"] if "Unrecognized stored field name" in line]
        assert len(withheld) == 1
        if occurrence["unrecognized_field_names"]:
            assert re.findall(r"`([^`]*)`", withheld[0]) == occurrence["unrecognized_field_names"]
        else:
            assert "none" in withheld[0]
    if not document["evidence"]:
        assert "This run retained no snapshot occurrence" in markdown

    # Overview: identity, status, statement, reasons and exception summaries.
    overview = sections["Overview"][0]
    assert _table(overview) == [
        ["Scan ID", document["scan_id"]],
        ["Scan time", document["scan_time"] or "not established"],
        ["Scan-time basis", document["scan_time_basis"]],
        ["Export time", document["export_time"]],
        ["Scan type", scope["scan_type"] or "not recorded"],
        ["Target", scope["target_path"]],
        ["Produced by", f"HarvestGuard {document['producing_harvestguard_version']}"],
        ["Exported by", f"HarvestGuard {document['exporting_harvestguard_version']}"],
        ["Executive schema", document["executive_schema_version"]],
        ["Executive policy", document["executive_policy_version"]],
        ["Normalized finding schema", document["finding_schema_version"]],
        ["Evidence digest", document["evidence_digest"] or "not recorded"],
        ["Retained snapshot occurrences", str(len(document["evidence"]))],
    ]
    overview_text = [_unescape(line) for line in overview["lines"]]
    assert f"**Evidence evaluation: {document['status']}**" in overview_text
    assert f"> {_flat(document['status_statement'])}" in overview_text
    overview_bullets = _bullets(overview)
    assert [item for item in overview_bullets if item.startswith("EV-RSN-")] == [
        f"{reason['reason_id']}: {_flat(reason['statement'])}"
        for reason in document["status_reasons"]
    ]
    summarized = [item for item in overview_bullets if item.startswith("EV-EXC-")]
    if summarized:
        assert summarized == [
            f"{record['exception_id']}: {_flat(record['statement'])}"
            for record in document["exceptions"]
        ]

    # Observations, then the fixed observation subsections.
    observed = sections[_HEADING_OBSERVED]
    assert [
        (record["heading"], _labelled(record)) for record in _records(observed, _OBSERVED_FIXED)
    ] == [_expected_explanation(record, anchors) for record in document["observations"]]
    assert _table(_named(observed, "Record counts")) == [
        [name, str(value)] for name, value in document["counts"].items()
    ]
    assert _table(_named(observed, "Declared scope")) == [
        ["Target path", scope["target_path"]],
        ["Scan type", scope["scan_type"] or "not recorded"],
        ["Scanners", "; ".join(scope["scanners"]) or "none recorded"],
        [
            "Scanner versions",
            "; ".join(f"{name} {version}" for name, version in scope["scanner_versions"].items())
            or "none recorded",
        ],
        ["Excluded paths", "; ".join(scope["excluded_paths"]) or "none"],
        ["Scope constraints", "; ".join(scope["scope_constraints"]) or "none recorded"],
        [
            "Crypto files inspected",
            "not recorded"
            if scope["crypto_files_inspected"] is None
            else str(scope["crypto_files_inspected"]),
        ],
    ]
    errors = _bullets(_named(observed, "Recorded scanner errors"))
    if document["scanner_errors"]:
        assert errors == [_flat(error) for error in document["scanner_errors"]]
    else:
        assert len(errors) == 1 and errors[0].startswith("None recorded.")

    # Checks: the summary table row and the detail record, each complete.
    checks = sections[_HEADING_CHECKS]
    assert _table(checks[0]) == [
        [
            check["check_id"],
            check["name"],
            _yes_no(check["required"]),
            _yes_no(check["applicable"]),
            check["state"],
        ]
        for check in document["checks"]
    ]
    expected_checks = []
    for check in document["checks"]:
        labelled = [
            ("State", check["state"]),
            ("Result", _flat(check["statement"])),
            ("Method", _flat(check["method"])),
        ]
        if check["state"] == "not_applicable" or check["not_applicable_reason"]:
            assert check["not_applicable_reason"], f"{check['check_id']} gives no reason"
            labelled.append(("Not applicable because", _flat(check["not_applicable_reason"])))
        labelled += [("Limitation", _flat(item)) for item in check["limitations"]]
        labelled += [("Source", _flat(item)) for item in check["source_references"]]
        labelled += _expected_references(check["references"], anchors)
        expected_checks.append((f"{check['check_id']} {check['title']}", labelled))
    assert [
        (record["heading"], _labelled(record)) for record in _records(checks)
    ] == expected_checks

    # Defined exceptions.
    exceptions = sections[_HEADING_EXCEPTIONS]
    assert [(record["heading"], _labelled(record)) for record in _records(exceptions)] == [
        (
            f"{record['exception_id']} {record['name']}",
            [
                ("Statement", _flat(record["statement"])),
                ("Outcome-affecting", _yes_no(record["outcome_affecting"])),
                *[("Detail", _flat(detail)) for detail in record["details"]],
                *_expected_references(record["references"], anchors),
            ],
        )
        for record in document["exceptions"]
    ]
    if not document["exceptions"]:
        assert "No defined exception was raised for this run." in exceptions[0]["lines"]

    # Conclusions, unknowns and standing limits.
    conclusions = sections[_HEADING_CONCLUSIONS]
    assert [
        (record["heading"], _labelled(record))
        for record in _records(conclusions, _CONCLUSIONS_FIXED)
    ] == [_expected_explanation(record, anchors) for record in document["conclusions"]]
    assert _bullets(_named(conclusions, "What this view could not establish")) == [
        _flat(item) for item in document["unknowns"]
    ]
    assert _bullets(_named(conclusions, "Standing limits")) == [
        _flat(item) for item in document["limits"]
    ]


@pytest.mark.parametrize("sample", _json_samples(), ids=lambda path: path.stem)
def test_json_and_markdown_stay_semantically_parallel(sample):
    document = json.loads(sample.read_text(encoding="utf-8"))
    markdown = _markdown_for(sample).read_text(encoding="utf-8")
    _assert_markdown_parallels_json(document, markdown)


def _swap_lines(markdown: str, first: str, second: str) -> str:
    """Exchange the first line starting with `first` and the first with `second`."""
    lines = markdown.split("\n")
    a = next(index for index, line in enumerate(lines) if line.startswith(first))
    b = next(index for index, line in enumerate(lines) if line.startswith(second))
    lines[a], lines[b] = lines[b], lines[a]
    return "\n".join(lines)


def _drop_section(markdown: str, heading: str) -> str:
    """Remove one `###` record, up to the next heading."""
    return re.sub(rf"(?ms)^### {re.escape(heading)}\n.*?(?=^#)", "", markdown, count=1)


def _drop_line_after(markdown: str, heading: str, prefix: str) -> str:
    """Remove the first line starting with `prefix` that follows `heading`."""
    lines = markdown.split("\n")
    start = lines.index(heading)
    index = next(i for i in range(start, len(lines)) if lines[i].startswith(prefix))
    del lines[index]
    return "\n".join(lines)


# Each corruption keeps every ID, state word and value somewhere in the
# document, so a search-anywhere comparison would accept all of them.
PARITY_CORRUPTIONS = {
    "one check's state is wrong": (
        "verified",
        lambda text: text.replace(
            "- State: passed\n", "- State: not\\_applicable\n", 1
        ),
    ),
    "two checks' results are exchanged": (
        "verified",
        lambda text: _swap_lines(
            text,
            "- Result: The stored run's recomputed digest",
            "- Result: Every retained record uses",
        ),
    ),
    "the summary table attaches the failure to the wrong check": (
        "failed-reference-consistency",
        lambda text: text.replace(
            "| evidence\\_integrity | yes | yes | passed |",
            "| evidence\\_integrity | yes | yes | failed |",
            1,
        ).replace(
            "| reference\\_consistency | yes | yes | failed |",
            "| reference\\_consistency | yes | yes | passed |",
            1,
        ),
    ),
    "a conclusion's method is missing": (
        "verified",
        lambda text: _drop_line_after(text, "### EV\\-CON\\-001 (check\\_result)", "- Method:"),
    ),
    "a whole conclusion is missing": (
        "verified",
        lambda text: _drop_section(text, "EV\\-CON\\-002 (check\\_result)"),
    ),
    "an evidence reference points at the other duplicate occurrence": (
        "duplicate-finding-ids",
        lambda text: text.replace(
            "ordinal 0 (finding ID synthetic\\-shared\\-finding\\-id)]"
            "(#evidence-synthetic-duplicate-ids-001-0)",
            "ordinal 1 (finding ID synthetic\\-shared\\-finding\\-id)]"
            "(#evidence-synthetic-duplicate-ids-001-1)",
            1,
        ),
    ),
    "two occurrences' locations are exchanged": (
        "verified",
        lambda text: _swap_lines(
            text,
            "| location | /synthetic/example\\-target/app/crypto\\_utils.py:14 |",
            "| location | /synthetic/example\\-target/app/legacy\\_digest.py:31 |",
        ),
    ),
    "an exception detail is attached to the wrong exception field": (
        "warning-unrecognized-fields",
        lambda text: _swap_lines(
            text, "- Detail: experimental\\_attribution", "- Outcome-affecting: yes"
        ),
    ),
}


@pytest.mark.parametrize("corruption", sorted(PARITY_CORRUPTIONS))
def test_semantic_parity_detects_values_on_the_wrong_record(corruption):
    """The parity check itself fails on each record-level mismatch."""
    slug, corrupt = PARITY_CORRUPTIONS[corruption]
    document = json.loads((SAMPLES / f"{slug}.json").read_text(encoding="utf-8"))
    markdown = (SAMPLES / f"{slug}.md").read_text(encoding="utf-8")
    corrupted = corrupt(markdown)
    assert corrupted != markdown, "the corruption did not apply"
    with pytest.raises(AssertionError):
        _assert_markdown_parallels_json(document, corrupted)


@pytest.mark.parametrize("sample", _json_samples(), ids=lambda path: path.stem)
def test_every_reference_resolves_to_exactly_one_occurrence(sample):
    document = json.loads(sample.read_text(encoding="utf-8"))
    occurrences = {
        (occurrence["ordinal"], occurrence["finding_id"]) for occurrence in document["evidence"]
    }
    markdown = _markdown_for(sample).read_text(encoding="utf-8")
    for reference in _references(document):
        assert reference["scan_id"] == document["scan_id"]
        matches = [
            occurrence
            for occurrence in document["evidence"]
            if occurrence["ordinal"] == reference["ordinal"]
        ]
        assert len(matches) == 1, f"reference {reference} does not resolve to one occurrence"
        if reference["finding_id"] is not None:
            assert (reference["ordinal"], reference["finding_id"]) in occurrences
        anchor = f'id="evidence-{document["scan_id"]}-{reference["ordinal"]}"'
        assert anchor in markdown, f"Markdown has no navigable target for {reference}"


def test_duplicate_finding_ids_stay_separate_occurrences():
    document = json.loads(
        (SAMPLES / "duplicate-finding-ids.json").read_text(encoding="utf-8")
    )
    occurrences = document["evidence"]
    assert len(occurrences) == 2
    assert len({occurrence["finding_id"] for occurrence in occurrences}) == 1
    assert {occurrence["ordinal"] for occurrence in occurrences} == {0, 1}
    assert (
        occurrences[0]["snapshot"]["location"] != occurrences[1]["snapshot"]["location"]
    )


def test_unrecognized_fields_disclose_names_and_withhold_values():
    document = json.loads(
        (SAMPLES / "warning-unrecognized-fields.json").read_text(encoding="utf-8")
    )
    markdown = (SAMPLES / "warning-unrecognized-fields.md").read_text(encoding="utf-8")
    occurrence = document["evidence"][0]
    assert occurrence["unrecognized_field_names"] == [
        "experimental_attribution",
        "provenance.experimental_collector_note",
    ]
    assert "experimental_attribution" not in occurrence["snapshot"]
    # The local-retention disclosure travels with the withheld names, in both
    # formats, so a withheld value is never silent data loss.
    from executive_evidence import UNRECOGNIZED_FIELD_VALUE_DISCLOSURE

    serialized = json.dumps(document)
    assert UNRECOGNIZED_FIELD_VALUE_DISCLOSURE in serialized
    assert UNRECOGNIZED_FIELD_VALUE_DISCLOSURE in markdown.replace("\\", "")


def test_unknown_historical_time_invents_nothing():
    document = json.loads(
        (SAMPLES / "incomplete-unknown-scan-time.json").read_text(encoding="utf-8")
    )
    assert document["scan_time"] is None
    assert "unknown" in document["scan_time_basis"]
    assert document["status"] == "INCOMPLETE"
    # The exporting clock is never substituted for the missing historical one.
    assert document["export_time"] not in json.dumps(document["conclusions"])


def test_corruption_sample_is_a_bounded_failure_with_no_report():
    transcript = (SAMPLES / "failed-integrity-corruption.stderr.txt").read_text(
        encoding="utf-8"
    )
    assert transcript.count("exit status: 1") == 2
    assert transcript.count("stdout bytes: 0") == 2
    assert transcript.count("output file written: no") == 2
    assert transcript.count("failed integrity verification") == 2
    # A rejected run yields a diagnostic, never an evidence-bearing document.
    assert "Evidence evaluation" not in transcript
    assert "Technical evidence detail" not in transcript
    assert "executive_schema_version" not in transcript


# --- published artifacts stay safe -----------------------------------------


@pytest.mark.parametrize(
    "path",
    sorted(
        path
        for path in COLLECTION.rglob("*")
        if path.is_file() and path.suffix in {".md", ".json", ".txt", ".py"}
    ),
    ids=lambda path: path.relative_to(COLLECTION).as_posix(),
)
def test_published_artifacts_carry_no_secret_or_identifying_values(path):
    text = path.read_text(encoding="utf-8")
    if path.name == "generate_examples.py":
        # The generator necessarily contains the canary literal it stores in an
        # unrecognized field; it must appear in no generated artifact.
        text = text.replace("SYNTHETIC-CANARY-VALUE-0000-NOT-A-REAL-SECRET", "")
    for pattern in FORBIDDEN_PATTERNS:
        assert not pattern.search(text), f"{pattern.pattern} matched in {path.name}"


def test_no_evidence_database_is_committed():
    assert not list(COLLECTION.rglob("*.sqlite"))
    assert not list(COLLECTION.rglob("*.db"))


def test_readme_relative_links_resolve():
    text = README.read_text(encoding="utf-8")
    for target in re.findall(r"\]\((?!https?:)([^)#]+)", text):
        assert (COLLECTION / target).exists(), f"broken link: {target}"


# --- the real CLI, from outside the checkout -------------------------------


def _cli_environment() -> dict[str, str]:
    environment = dict(os.environ)
    existing = environment.get("PYTHONPATH")
    environment["PYTHONPATH"] = f"{ROOT}{os.pathsep}{existing}" if existing else str(ROOT)
    return environment


def _run_cli(argv: list[str], cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "harvestguard", *argv],
        capture_output=True,
        text=True,
        cwd=str(cwd),
        env=_cli_environment(),
        check=False,
    )


def _assert_live_json_matches_committed(stdout: str, slug: str, fixed: str) -> None:
    """A live JSON export equals the sample once its export time is normalized."""
    live = json.loads(stdout)
    committed = json.loads((SAMPLES / f"{slug}.json").read_text(encoding="utf-8"))
    assert live["export_time"] != ""
    live["export_time"] = fixed
    assert live == committed


def _assert_live_markdown_matches_committed(stdout: str, slug: str, fixed: str) -> None:
    """The same for Markdown, whose export time appears in the identity table."""
    committed = (SAMPLES / f"{slug}.md").read_text(encoding="utf-8")
    export_row = re.search(r"\| Export time \| (.+) \|", stdout)
    assert export_row is not None
    normalized = stdout.replace(
        export_row.group(1), fixed.replace("-", "\\-").replace("+", "\\+")
    )
    assert normalized.strip() == committed.strip()


@pytest.mark.parametrize(
    "slug", ["verified", "incomplete-partial-execution", "warning-unrecognized-fields"]
)
def test_cli_reproduces_each_sample_apart_from_its_export_time(slug, regenerated, manifest):
    """CLI -> store -> verified load -> projection -> both exports, for real.

    This is the repository's entry point (`python -m harvestguard` with the
    checkout importable), run from a directory that is not the checkout: it
    covers the documented no-install path, not what an installed release does
    -- that is the last section's job. The CLI owns its export time and has no
    public override, so the committed sample and a live export are compared
    with that one value normalized away; nothing else may differ. Three
    representative scenarios keep the subprocess cost bounded; every
    scenario's byte-for-byte content is already covered above.
    """
    _output, work, _result = regenerated
    scenario = next(item for item in manifest["scenarios"] if item["slug"] == slug)
    database = work / "example-evidence.sqlite"
    fixed = manifest["regeneration"]["explicit_export_time"]

    for option, check in (
        ("--executive-json", _assert_live_json_matches_committed),
        ("--executive-markdown", _assert_live_markdown_matches_committed),
    ):
        completed = _run_cli(
            [
                "evidence",
                "export",
                scenario["scan_id"],
                "--evidence-db",
                str(database),
                option,
                "-",
            ],
            cwd=work,
        )
        assert completed.returncode == 0, completed.stderr
        check(completed.stdout, slug, fixed)


def test_generation_never_runs_a_harvestguard_found_on_path(tmp_path, generator, monkeypatch):
    """An older CLI earlier on `PATH` cannot answer for the code under review.

    A decoy `harvestguard` that would record being run, and would print a
    passing export, is put first on `PATH`. Generation must not invoke it, and
    the corruption diagnostic it produces must still be the committed one.
    """
    decoy_dir = tmp_path / "decoy-bin"
    decoy_dir.mkdir()
    marker = tmp_path / "decoy-was-run"
    decoy = decoy_dir / ("harvestguard.exe" if os.name == "nt" else "harvestguard")
    decoy.write_text(f"#!/bin/sh\ntouch {marker}\necho decoy\nexit 0\n", encoding="utf-8")
    decoy.chmod(0o755)
    monkeypatch.setenv("PATH", f"{decoy_dir}{os.pathsep}{os.environ.get('PATH', '')}")

    output = tmp_path / "output"
    generator.generate(output, tmp_path / "work")

    assert not marker.exists()
    name = "samples/failed-integrity-corruption.stderr.txt"
    assert (output / name).read_bytes() == (COLLECTION / name).read_bytes()


def test_generation_refuses_a_cli_that_would_import_other_modules(tmp_path, generator):
    """A CLI subprocess resolving a different implementation fails explicitly."""
    shadow = tmp_path / "shadow"
    shadow.mkdir()
    (shadow / "executive_reports.py").write_text("# not the reviewed module\n", encoding="utf-8")
    environment = dict(os.environ)
    environment["PYTHONPATH"] = f"{shadow}{os.pathsep}{ROOT}"

    with pytest.raises(generator.CliMismatchError, match="executive_reports"):
        generator._verify_cli_imports(sys.executable, environment, tmp_path)


def test_checkout_generation_runs_the_checkout_entry_point(tmp_path, generator):
    """From the checkout, the CLI is this interpreter running this checkout's module."""
    import evidence_store

    assert Path(evidence_store.__file__).resolve().parent == ROOT.resolve()
    command, environment = generator._cli_invocation(tmp_path)
    assert command == [sys.executable, "-m", "harvestguard"]
    assert environment["PYTHONPATH"].split(os.pathsep)[0] == str(ROOT.resolve())


def test_documented_export_commands_use_options_the_cli_accepts(manifest):
    help_text = _run_cli(["evidence", "export", "--help"], cwd=ROOT).stdout
    for scenario in manifest["scenarios"]:
        for command in scenario["commands"]:
            for option in re.findall(r"--[a-z-]+", command):
                assert option in help_text, f"{option} is not a shipped CLI option"
    # #153 explicitly does not add a public export-time override.
    assert "--export-time" not in help_text


def test_the_documented_relative_work_dir_command_generates_the_collection(tmp_path):
    """The README's `--work-dir ./eev-work`, run exactly as documented.

    Relative paths, from a directory that is not the checkout. The corruption
    example runs the real CLI with its `cwd` set to the work directory, so a
    relative work directory that is not pinned absolute first gets resolved a
    second time against that cwd: the CLI then reports a missing database, and
    the bounded *integrity* failure the sample exists to show never happens.
    Every other generation test passes an absolute temporary path, so none of
    them can see that.
    """
    completed = subprocess.run(
        [
            sys.executable,
            str(GENERATOR),
            "--output-dir",
            "./eev-output",
            "--work-dir",
            "./eev-work",
        ],
        capture_output=True,
        text=True,
        cwd=str(tmp_path),
        env=_cli_environment(),
        check=False,
    )
    assert completed.returncode == 0, completed.stderr

    # Kept where the documented follow-up CLI commands go looking for it.
    assert (tmp_path / "eev-work" / "example-evidence.sqlite").is_file()
    # The disposable copy is removed; nothing else is left behind.
    assert [path.name for path in (tmp_path / "eev-work").iterdir()] == [
        "example-evidence.sqlite"
    ]

    samples = tmp_path / "eev-output" / "samples"
    transcript = (samples / "failed-integrity-corruption.stderr.txt").read_text(
        encoding="utf-8"
    )
    # The real rejection, not a missing-database error that merely also exits 1.
    assert transcript.count("failed integrity verification") == 2
    assert transcript.count("exit status: 1") == 2
    assert transcript.count("stdout bytes: 0") == 2
    assert (samples / "verified.json").is_file()


# --- acceptance records claim nothing that has not happened ----------------


@pytest.mark.parametrize(
    "name, marker",
    [
        ("comprehension-protocol.md", "DRAFT"),
        ("comprehension-results.md", "NO PARTICIPANT HAS BEEN TESTED"),
        ("independent-use-record.md", "NO PRACTITIONER HAS COMPLETED THE EXERCISE"),
    ],
)
def test_outstanding_human_acceptance_is_recorded_as_incomplete(name, marker):
    text = (COLLECTION / name).read_text(encoding="utf-8")
    assert marker in text
    assert "INCOMPLETE" in text or "NOT FROZEN" in text


# --- participant material is separate from facilitator material -------------

PARTICIPANT = COLLECTION / "participant"
PACKET = PARTICIPANT / "reader-packet.md"
PROTOCOL = COLLECTION / "comprehension-protocol.md"
QUESTIONS = (
    "What did HarvestGuard observe?",
    "What evidence supports those observations?",
    "What can and cannot be concluded from that evidence?",
    'What does "Evidence evaluation: VERIFIED" mean?',
)


def test_async_packet_identity_questions_and_isolation():
    assert sorted(p.name for p in PARTICIPANT.iterdir()) == [PACKET.name]
    packet = PACKET.read_bytes()
    intro, rest = packet.split(b"<!-- BEGIN EVALUATED ARTIFACT -->\n")
    artifact, answers = rest.split(b"<!-- END EVALUATED ARTIFACT -->")
    assert artifact == (COLLECTION / "samples/verified.md").read_bytes()
    assert hashlib.sha256(artifact).hexdigest() == (
        "69b173bacfdc6dc04a9b2daf9223851d20529d376bce6eff64116b49ba15ba94"
    )
    added = (intro + answers).decode("utf-8")
    assert re.findall(r"^\*\*\d\. (.+)\*\*$", added, re.MULTILINE) == list(QUESTIONS)
    assert added.count("Your answer:") == 4
    assert not re.search(
        r"(?i)answer key|rubric|threshold|correct answer|prohibited|technical.review|"
        r"facilitator|30.second|stopwatch|https?:|\]\(",
        added,
    )
    # The unchanged artifact may have internal navigation, never repository links.
    assert all(t.startswith("#") for t in re.findall(r"\]\(([^)]+)\)", artifact.decode()))
    protocol = PROTOCOL.read_text(encoding="utf-8")
    questions = protocol[protocol.index("## 4.") : protocol.index("## 5.")]
    assert re.findall(r"^\d\. (.+)$", questions, re.MULTILINE)[:4] == list(QUESTIONS)


def test_async_active_reader_materials_have_no_timing_or_split_reveal_contract():
    for name in (
        "comprehension-protocol.md",
        "comprehension-results.md",
        "facilitator-record-sheet.md",
        "participant/reader-packet.md",
    ):
        text = (COLLECTION / name).read_text(encoding="utf-8")
        assert not re.search(r"(?i)30[ -]second|30 s\b|stopwatch|Part [12]|screen.share", text)
    protocol = PROTOCOL.read_text(encoding="utf-8")
    for rule in (
        "no pass/fail completion-time requirement",
        "four of five",
        "Dispatch to an eligible reader",
        "Missing answers",
        "Withdrawals and closed nonresponses may be replaced",
        "Tim decides",
        "original returned files",
        "not establish",
    ):
        assert rule in protocol
    for boundary in (
        "organizational security",
        "regulatory compliance",
        "business safety",
        "complete environmental coverage",
        "source authenticity",
        "proof that no relevant cryptographic asset exists",
    ):
        assert boundary in " ".join(protocol.split())


def test_async_revision_preserves_semantic_key_rubric_and_practitioner():
    protocol = PROTOCOL.read_bytes()
    key = protocol[protocol.index(b"## 6. Answer key") : protocol.index(b"## 8. Pass threshold")]
    assert (
        hashlib.sha256(key).hexdigest()
        == "0f3b982a2daac91a8ba84af3a8b7f3164ff1bd6899639e3f0a76526a165270ab"
    )
    practitioner = (COLLECTION / "independent-use-record.md").read_bytes()
    assert (
        hashlib.sha256(practitioner).hexdigest()
        == "847d76541551b9b7129fd2d95ca0dd1cfec22c2dea0c57477bfc26a13505539c"
    )
    for path in COLLECTION.rglob("*.md"):
        assert "participant-response-form" not in path.read_text(encoding="utf-8")


def test_facilitator_sheet_is_marked_facilitator_only():
    text = (COLLECTION / "facilitator-record-sheet.md").read_text(encoding="utf-8")
    assert "FACILITATOR AND SCORER ONLY" in text.splitlines()[2]


def test_acceptance_summary_separates_the_evidence_categories():
    text = (COLLECTION / "acceptance-summary.md").read_text(encoding="utf-8")
    for category in (
        "Automated and AI-produced evidence",
        "Independent technical-review evidence",
        "Real human-comprehension evidence",
        "Maintainer decisions",
    ):
        assert category in text
    assert "INCOMPLETE" in text


# --- the installed package, from outside the checkout ----------------------

# A regeneration that imports this checkout says nothing about the release a
# reader installs, so the collection is regenerated once more from a
# non-editable install: outside the checkout, with no `PYTHONPATH` and no
# repository import override, driving the shipped console script. The committed
# bytes have to come out either way.
#
# The target environment is provisioned the way a reader's would be, and then
# checked, rather than borrowed from the host. It is created *without*
# `--system-site-packages` -- which would inherit the base interpreter's global
# packages, not the test runner's virtual environment -- and HarvestGuard is
# installed *with* its declared dependencies, through pip's normal build
# isolation. Nothing is decided from what the parent interpreter happens to
# have. Before anything is generated, the fixture confirms inside the target
# environment that system site-packages are off, `pip check` is clean, and every
# declared dependency of the installed distribution resolves from that
# environment itself.
#
# Installing declared dependencies needs a package index (network access, or a
# pip cache or configured index that can supply them), exactly like
# `tests/test_clean_install.py`, and honours the same opt-out:
# `HARVESTGUARD_SKIP_CLEAN_INSTALL_TESTS=1` skips these tests when working
# offline, and they are then reported as skipped. An install failure when they
# do run is a real failure.

CLEAN_INSTALL_SKIP_VAR = "HARVESTGUARD_SKIP_CLEAN_INSTALL_TESTS"

requires_clean_install = pytest.mark.skipif(
    os.environ.get(CLEAN_INSTALL_SKIP_VAR, "") == "1",
    reason=f"{CLEAN_INSTALL_SKIP_VAR}=1: installing declared dependencies needs a package index",
)


def _venv_bin(venv_dir: Path, name: str) -> Path:
    if sys.platform == "win32":
        return venv_dir / "Scripts" / f"{name}.exe"
    return venv_dir / "bin" / name


def _installed_environment(venv_dir: Path) -> dict[str, str]:
    """No repository import path, no user site, the environment's own tools first."""
    environment = {
        key: value
        for key, value in os.environ.items()
        if key not in {"PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV"}
    }
    environment["PYTHONNOUSERSITE"] = "1"
    bin_dir = _venv_bin(venv_dir, "python").parent
    environment["PATH"] = f"{bin_dir}{os.pathsep}{environment.get('PATH', '')}"
    return environment


# Run inside the target environment: where every declared requirement of the
# installed distribution resolves from, and what the interpreter searches.
_DEPENDENCY_PROBE = """
import json, re, site, sys
from importlib import metadata

names = []
for requirement in metadata.requires("harvestguard") or []:
    if "extra ==" in requirement:
        continue
    names.append(re.match(r"[A-Za-z0-9._-]+", requirement).group(0))
located = {}
for name in names:
    distribution = metadata.distribution(name)
    located[name] = str(distribution.locate_file(""))
print(json.dumps({
    "prefix": sys.prefix,
    "base_prefix": sys.base_prefix,
    "user_site_enabled": bool(site.ENABLE_USER_SITE),
    "site_packages": site.getsitepackages(),
    "harvestguard": str(metadata.distribution("harvestguard").locate_file("")),
    "requirements": located,
}))
"""


def _assert_target_environment_is_self_contained(venv_dir: Path, environment: dict) -> None:
    """The dependencies are provisioned in, and answered by, the target environment.

    Run from outside the checkout: `-c` puts the working directory on the import
    path, and a checkout can hold build metadata that would answer instead.
    """
    outside = venv_dir.parent
    python = str(_venv_bin(venv_dir, "python"))
    configuration = (venv_dir / "pyvenv.cfg").read_text(encoding="utf-8")
    assert re.search(r"(?m)^include-system-site-packages\s*=\s*false\s*$", configuration), (
        "the target environment must not inherit system site-packages"
    )

    checked = subprocess.run(
        [python, "-m", "pip", "check"],
        cwd=str(outside),
        capture_output=True,
        text=True,
        timeout=300,
        env=environment,
        check=False,
    )
    assert checked.returncode == 0, checked.stdout + checked.stderr

    probed = subprocess.run(
        [python, "-c", _DEPENDENCY_PROBE],
        cwd=str(outside),
        capture_output=True,
        text=True,
        timeout=300,
        env=environment,
        check=False,
    )
    assert probed.returncode == 0, probed.stderr[-2000:]
    report = json.loads(probed.stdout)
    venv = venv_dir.resolve()
    assert Path(report["prefix"]).resolve() == venv
    assert Path(report["base_prefix"]).resolve() != venv
    assert report["user_site_enabled"] is False
    for entry in report["site_packages"]:
        assert venv in Path(entry).resolve().parents, f"searches {entry} outside the target"
    assert venv in Path(report["harvestguard"]).resolve().parents
    assert report["requirements"], "the installed distribution declares no dependencies"
    for name, location in report["requirements"].items():
        assert venv in Path(location).resolve().parents, (
            f"{name} resolves from {location}, outside the target environment"
        )


@pytest.fixture(scope="module")
def installed_generation(tmp_path_factory):
    """The whole collection, regenerated by a non-editable install.

    Returns the environment directory, the outside-the-checkout run directory
    (whose `work/` keeps the generated evidence database), the regenerated
    collection, and the clean environment used to produce it.
    """
    venv_dir = tmp_path_factory.mktemp("eev-installed") / "venv"
    subprocess.run(
        [sys.executable, "-m", "venv", str(venv_dir)],
        capture_output=True,
        text=True,
        timeout=300,
        check=True,
    )
    environment = _installed_environment(venv_dir)
    installed = subprocess.run(
        [str(_venv_bin(venv_dir, "python")), "-m", "pip", "install", str(ROOT)],
        cwd=str(venv_dir.parent),
        capture_output=True,
        text=True,
        timeout=1800,
        env=environment,
        check=False,
    )
    assert installed.returncode == 0, (installed.stdout + installed.stderr)[-4000:]
    _assert_target_environment_is_self_contained(venv_dir, environment)

    outside = tmp_path_factory.mktemp("eev-installed-run")
    assert ROOT not in outside.parents and outside != ROOT
    output = outside / "collection"
    completed = subprocess.run(
        [
            str(_venv_bin(venv_dir, "python")),
            str(GENERATOR),
            "--output-dir",
            str(output),
            "--work-dir",
            str(outside / "work"),
        ],
        cwd=str(outside),
        capture_output=True,
        text=True,
        timeout=600,
        env=environment,
        check=False,
    )
    assert completed.returncode == 0, (completed.stdout + completed.stderr)[-3000:]
    return venv_dir, outside, output, environment


@requires_clean_install
def test_the_installed_generator_imports_the_install_not_the_checkout(installed_generation):
    """Every module the generator drives, and the CLI it runs, is the install's."""
    venv_dir, outside, _output, environment = installed_generation
    probe = (
        "import importlib.util, pathlib, sys\n"
        f"spec = importlib.util.spec_from_file_location('eev_probe', {str(GENERATOR)!r})\n"
        "module = importlib.util.module_from_spec(spec)\n"
        "sys.modules['eev_probe'] = module\n"
        "spec.loader.exec_module(module)\n"
        "for name in ('evidence_store', 'executive_evidence', 'executive_reports'):\n"
        "    print(sys.modules[name].__file__)\n"
        "print(str(module._REPO_ROOT) in sys.path)\n"
        "print(module._cli_invocation(pathlib.Path.cwd())[0][0])\n"
    )
    completed = subprocess.run(
        [str(_venv_bin(venv_dir, "python")), "-c", probe],
        cwd=str(outside),
        capture_output=True,
        text=True,
        timeout=300,
        env=environment,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr[-2000:]
    *origins, repo_root_on_path, cli = completed.stdout.split()
    # The checkout is never put on the import path when an install answers.
    assert repo_root_on_path == "False"
    for origin in (Path(item) for item in origins):
        assert venv_dir in origin.parents, origin
        assert ROOT not in origin.parents, origin
    # The CLI the corruption example runs is this install's own console script.
    assert Path(cli) == _venv_bin(venv_dir, "harvestguard")


@requires_clean_install
def test_the_installed_generator_refuses_a_console_script_from_elsewhere(
    installed_generation, tmp_path
):
    """A `harvestguard` the imported distribution did not install is refused."""
    venv_dir, outside, _output, environment = installed_generation
    elsewhere = tmp_path / "elsewhere" / "bin"
    elsewhere.mkdir(parents=True)
    impostor = elsewhere / _venv_bin(venv_dir, "harvestguard").name
    impostor.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    probe = (
        "import importlib.util, sys\n"
        f"spec = importlib.util.spec_from_file_location('eev_probe', {str(GENERATOR)!r})\n"
        "module = importlib.util.module_from_spec(spec)\n"
        "sys.modules['eev_probe'] = module\n"
        "spec.loader.exec_module(module)\n"
        f"sys.executable = {str(elsewhere / 'python')!r}\n"
        "try:\n"
        "    module._installed_console_script()\n"
        "except module.CliMismatchError as refusal:\n"
        "    print('refused:', refusal)\n"
        "else:\n"
        "    print('accepted')\n"
    )
    completed = subprocess.run(
        [str(_venv_bin(venv_dir, "python")), "-c", probe],
        cwd=str(outside),
        capture_output=True,
        text=True,
        timeout=300,
        env=environment,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr[-2000:]
    assert completed.stdout.startswith("refused:"), completed.stdout


@requires_clean_install
def test_a_non_editable_install_regenerates_the_committed_collection(installed_generation):
    """The published bytes are reproducible from an installed release."""
    _venv_dir, _outside, output, _environment = installed_generation
    generated = {
        path.relative_to(output).as_posix(): path.read_bytes()
        for path in sorted(output.rglob("*"))
        if path.is_file()
    }
    committed = {
        path.relative_to(COLLECTION).as_posix(): path.read_bytes()
        for path in [MANIFEST, *sorted(SAMPLES.iterdir())]
    }

    assert set(generated) == set(committed)
    for name, content in committed.items():
        assert generated[name] == content, (
            f"{name} differs when generated from a non-editable install"
        )


@requires_clean_install
@pytest.mark.parametrize("slug", ["verified", "warning-unrecognized-fields"])
def test_installed_cli_reproduces_each_sample_apart_from_its_export_time(
    slug, installed_generation, manifest
):
    """The shipped console script, outside the checkout, against the kept store."""
    venv_dir, outside, _output, environment = installed_generation
    scenario = next(item for item in manifest["scenarios"] if item["slug"] == slug)
    database = outside / "work" / "example-evidence.sqlite"
    fixed = manifest["regeneration"]["explicit_export_time"]

    for option, check in (
        ("--executive-json", _assert_live_json_matches_committed),
        ("--executive-markdown", _assert_live_markdown_matches_committed),
    ):
        completed = subprocess.run(
            [
                str(_venv_bin(venv_dir, "harvestguard")),
                "evidence",
                "export",
                scenario["scan_id"],
                "--evidence-db",
                str(database),
                option,
                "-",
            ],
            cwd=str(outside),
            capture_output=True,
            text=True,
            timeout=300,
            env=environment,
            check=False,
        )
        assert completed.returncode == 0, completed.stderr[-2000:]
        check(completed.stdout, slug, fixed)
