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
or against the real CLI run as a subprocess from outside the checkout.
"""

from __future__ import annotations

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


@pytest.mark.parametrize("sample", _json_samples(), ids=lambda path: path.stem)
def test_json_and_markdown_stay_semantically_parallel(sample):
    document = json.loads(sample.read_text(encoding="utf-8"))
    markdown = _markdown_for(sample).read_text(encoding="utf-8")
    # Markdown escapes punctuation for presentation safety, so compare on
    # identifiers and unescaped text rather than whole sentences.
    plain = markdown.replace("\\", "")
    for check in document["checks"]:
        assert check["check_id"] in plain
        assert check["state"] in plain
    for exception in document["exceptions"]:
        assert exception["exception_id"] in plain
    for reason in document["status_reasons"]:
        assert reason["reason_id"] in plain
    for occurrence in document["evidence"]:
        for name in occurrence["unrecognized_field_names"]:
            assert name in plain, f"{name} is disclosed in JSON but not in Markdown"
    for limit in document["limits"]:
        assert limit.split(".")[0] in plain


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


@pytest.mark.parametrize(
    "slug", ["verified", "incomplete-partial-execution", "warning-unrecognized-fields"]
)
def test_cli_reproduces_each_sample_apart_from_its_export_time(slug, regenerated, manifest):
    """CLI -> store -> verified load -> projection -> both exports, for real.

    Run from a directory that is not the checkout. The CLI owns its export
    time and has no public override, so the committed sample and a live export
    are compared with that one value normalized away -- nothing else may
    differ. Three representative scenarios keep the subprocess cost bounded;
    every scenario's byte-for-byte content is already covered above.
    """
    _output, work, _result = regenerated
    scenario = next(item for item in manifest["scenarios"] if item["slug"] == slug)
    database = work / "example-evidence.sqlite"
    fixed = manifest["regeneration"]["explicit_export_time"]

    json_run = _run_cli(
        [
            "evidence",
            "export",
            scenario["scan_id"],
            "--evidence-db",
            str(database),
            "--executive-json",
            "-",
        ],
        cwd=work,
    )
    assert json_run.returncode == 0, json_run.stderr
    live = json.loads(json_run.stdout)
    committed = json.loads((SAMPLES / f"{slug}.json").read_text(encoding="utf-8"))
    assert live["export_time"] != ""
    live["export_time"] = fixed
    assert live == committed

    markdown_run = _run_cli(
        [
            "evidence",
            "export",
            scenario["scan_id"],
            "--evidence-db",
            str(database),
            "--executive-markdown",
            "-",
        ],
        cwd=work,
    )
    assert markdown_run.returncode == 0, markdown_run.stderr
    committed_markdown = (SAMPLES / f"{slug}.md").read_text(encoding="utf-8")
    live_markdown = markdown_run.stdout
    export_row = re.search(r"\| Export time \| (.+) \|", live_markdown)
    assert export_row is not None
    normalized = live_markdown.replace(export_row.group(1), fixed.replace("-", "\\-").replace(
        "+", "\\+"
    ))
    assert normalized.strip() == committed_markdown.strip()


def test_documented_export_commands_use_options_the_cli_accepts(manifest):
    help_text = _run_cli(["evidence", "export", "--help"], cwd=ROOT).stdout
    for scenario in manifest["scenarios"]:
        for command in scenario["commands"]:
            for option in re.findall(r"--[a-z-]+", command):
                assert option in help_text, f"{option} is not a shipped CLI option"
    # #153 explicitly does not add a public export-time override.
    assert "--export-time" not in help_text


# --- acceptance records claim nothing that has not happened ----------------


@pytest.mark.parametrize(
    "name, marker",
    [
        ("comprehension-protocol.md", "DRAFT"),
        ("comprehension-results.md", "NO PARTICIPANT HAS BEEN TESTED"),
        ("independent-use-record.md", "NO PRACTITIONER HAS COMPLETED THE EXERCISE"),
        ("technical-traceability-review.md", "NOT PERFORMED"),
    ],
)
def test_outstanding_human_acceptance_is_recorded_as_incomplete(name, marker):
    text = (COLLECTION / name).read_text(encoding="utf-8")
    assert marker in text
    assert "INCOMPLETE" in text or "NOT FROZEN" in text


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
