"""Regenerate the committed first-run sample output (GitHub issue #116).

The samples in this directory are produced by the supported CLI against the
repository's synthetic demo corpus (`demo/sample_target/`). Nothing in them is
hand-authored: this script runs the two documented commands and then replaces a
short, fixed list of *volatile* values -- a per-run scan id, collection
timestamps, a wall-clock duration, and checkout-specific absolute paths -- with
stable placeholders so the committed files do not churn on every run and carry
no user-specific path. Findings themselves are never rewritten, reordered, or
filtered.

Run it from anywhere:

    python docs/examples/first-run/generate_samples.py

`tests/test_first_run_samples.py` re-runs the same generation and compares the
host-independent portions against the committed files.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

EXAMPLES_DIR = Path(__file__).resolve().parent
REPO_ROOT = EXAMPLES_DIR.parents[2]

# The scan the samples come from, exactly as documented in docs/CLI.md's demo
# walkthrough. `--json` and `--markdown` are mutually exclusive on the CLI, so
# the two samples come from two runs of the same command.
DEMO_TARGET = "demo/sample_target"
SCAN_ARGV = ["scan", DEMO_TARGET, "--type", "all", "--quiet"]

JSON_SAMPLE = EXAMPLES_DIR / "sample-findings.json"
MARKDOWN_SAMPLE = EXAMPLES_DIR / "sample-report.md"

# Placeholders for the volatile values. Each is obviously a placeholder rather
# than a plausible real value, so nobody mistakes a committed sample for the
# record of an actual scan.
PLACEHOLDER_SCAN_ID = "00000000-0000-0000-0000-000000000000"
PLACEHOLDER_TIMESTAMP = "1970-01-01T00:00:00+00:00"
PLACEHOLDER_DURATION = "0.00 seconds"
PLACEHOLDER_CHECKOUT = "<checkout>"

# Finding fields whose value is a collection timestamp, not evidence about the
# scanned asset. A certificate's parsed `Expiration` is evidence and is left
# exactly as the scanner reported it.
_TIMESTAMP_FIELDS = ("observed_at",)
_PROVENANCE_TIMESTAMP_FIELDS = ("collected_at",)
# File modification time of a scanned demo file: a property of the checkout
# (git does not preserve mtimes), not of the fixture's content.
_TIMESTAMP_METADATA_FIELDS = ("Modified",)

_MARKDOWN_SCAN_TIME_ROW = re.compile(r"^\| Scan Time \| (?P<value>.+) \|$", re.MULTILINE)
_MARKDOWN_SCAN_ID_ROW = re.compile(r"^\| Scan ID \| (?P<value>.+) \|$", re.MULTILINE)
_MARKDOWN_DURATION_ROW = re.compile(r"^\| Duration \| (?P<value>.+) \|$", re.MULTILINE)
_ISO_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$")
_OBSERVED_AT_HEADER = "Observed At"


def run_scan(output_flag: str, output_path: Path) -> str:
    """Run the documented demo scan and return the artifact it wrote."""
    subprocess.run(
        [sys.executable, "-m", "harvestguard", *SCAN_ARGV, output_flag, str(output_path)],
        cwd=REPO_ROOT,
        check=True,
    )
    return output_path.read_text(encoding="utf-8")


def _strip_checkout_path(text: str) -> str:
    """Replace this checkout's absolute path with a stable placeholder."""
    return text.replace(str(REPO_ROOT), PLACEHOLDER_CHECKOUT)


def normalize_json(raw: str) -> str:
    """Normalize volatile values in a `--json` artifact; keep the contract intact."""
    findings = json.loads(_strip_checkout_path(raw))
    for finding in findings:
        if "scan_id" in finding:
            finding["scan_id"] = PLACEHOLDER_SCAN_ID
        for field in _TIMESTAMP_FIELDS:
            if finding.get(field) is not None:
                finding[field] = PLACEHOLDER_TIMESTAMP
        provenance = finding.get("provenance") or {}
        for field in _PROVENANCE_TIMESTAMP_FIELDS:
            if provenance.get(field) is not None:
                provenance[field] = PLACEHOLDER_TIMESTAMP
        metadata = finding.get("technical_metadata") or {}
        for field in _TIMESTAMP_METADATA_FIELDS:
            if metadata.get(field) is not None:
                metadata[field] = PLACEHOLDER_TIMESTAMP
    return json.dumps(findings, indent=2) + "\n"


def _normalize_observed_at_cells(text: str) -> str:
    """Replace the `Observed At` cell of every Detailed Findings table row.

    Column-addressed rather than value-addressed on purpose: a finding's
    collection timestamp and the report's own `Scan Time` can land on either
    side of a second boundary, so matching the scan-time literal would leave
    some cells unnormalized. A parsed certificate `Expiration` lives in a
    different column and is never touched.
    """
    observed_index: int | None = None
    lines = text.split("\n")
    for position, line in enumerate(lines):
        if not line.startswith("|"):
            continue
        cells = line.split("|")
        labels = [cell.strip() for cell in cells]
        if _OBSERVED_AT_HEADER in labels:
            observed_index = labels.index(_OBSERVED_AT_HEADER)
        elif observed_index is not None and observed_index < len(cells):
            if _ISO_TIMESTAMP.match(cells[observed_index].strip()):
                cells[observed_index] = f" {PLACEHOLDER_TIMESTAMP} "
                lines[position] = "|".join(cells)
    return "\n".join(lines)


def normalize_markdown(raw: str) -> str:
    """Normalize volatile values in a `--markdown` artifact."""
    text = _strip_checkout_path(raw)
    text = _MARKDOWN_SCAN_TIME_ROW.sub(f"| Scan Time | {PLACEHOLDER_TIMESTAMP} |", text)
    text = _MARKDOWN_SCAN_ID_ROW.sub(f"| Scan ID | {PLACEHOLDER_SCAN_ID} |", text)
    text = _MARKDOWN_DURATION_ROW.sub(f"| Duration | {PLACEHOLDER_DURATION} |", text)
    return _normalize_observed_at_cells(text)


def generate() -> tuple[str, str]:
    """Run both documented commands and return the normalized (JSON, Markdown)."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp_dir = Path(tmp)
        raw_json = run_scan("--json", tmp_dir / "findings.json")
        raw_markdown = run_scan("--markdown", tmp_dir / "report.md")
    return normalize_json(raw_json), normalize_markdown(raw_markdown)


def main() -> int:
    json_text, markdown_text = generate()
    JSON_SAMPLE.write_text(json_text, encoding="utf-8")
    MARKDOWN_SAMPLE.write_text(markdown_text, encoding="utf-8")
    print(f"wrote {JSON_SAMPLE.relative_to(REPO_ROOT)}")
    print(f"wrote {MARKDOWN_SAMPLE.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
