"""Tests for demo/sample_target/ (HG-006, GitHub issue #18).

These exist specifically because earlier versions of
demo/sample_target/sensitive/leaked_config.env contained, in turn, a
syntactically valid-looking Slack token and then a valid-looking AWS access
key, and GitHub push protection correctly rejected the push both times. The
fix was to make every fixture value unmistakably fake rather than to weaken
push protection, HarvestGuard's classifiers, or any other security control
-- these tests guard against that regressing.
"""

from __future__ import annotations

from pathlib import Path

from classifier.patterns import AWS_ACCESS_KEY_RE, GITHUB_TOKEN_RE, SLACK_TOKEN_RE
from classifier.scanner import (
    classify_text,
    scan_filesystem_for_sensitive_data,
    scan_filesystem_for_sensitive_data_findings,
)
from reports import findings_json, format_markdown_report, make_report_context

DEMO_TARGET = Path(__file__).parent.parent / "demo" / "sample_target"
LEAKED_CONFIG = DEMO_TARGET / "sensitive" / "leaked_config.env"

# The exact fake values written into the fixture. Used below to prove they
# never appear in classifier/report output, which must report categories
# and counts only -- never the matched values themselves.
FIXTURE_SECRET_VALUES = ("FAKE-DEMO-PASSWORD-VALUE-0000000000",)


def test_demo_target_exists_and_is_reachable():
    assert DEMO_TARGET.is_dir()
    assert LEAKED_CONFIG.is_file()


def test_demo_target_produces_expected_sensitive_data_categories():
    df = scan_filesystem_for_sensitive_data(str(DEMO_TARGET))

    assert len(df) == 1
    row = df.iloc[0]
    assert row["Location"].endswith("leaked_config.env")

    categories = {c.strip() for c in row["Categories"].split(",")}
    assert categories == {"Email", "Private Key", "Generic Secret"}
    # Deliberately absent -- see the fixture's header comment. Each of these
    # three is a real, service-specific credential shape that a value
    # matching it would also trip GitHub push protection on, same as the
    # Slack token and AWS access key incidents this fixture's design
    # addresses.
    assert "Slack Token" not in categories
    assert "GitHub Token" not in categories
    assert "AWS Access Key" not in categories


def test_demo_fixture_values_do_not_match_service_specific_credential_shapes():
    text = LEAKED_CONFIG.read_text()

    assert SLACK_TOKEN_RE.search(text) is None
    assert GITHUB_TOKEN_RE.search(text) is None
    assert AWS_ACCESS_KEY_RE.search(text) is None

    # classify_text() must agree with the raw regex checks above.
    counts = classify_text(text)
    assert "Slack Token" not in counts
    assert "GitHub Token" not in counts
    assert "AWS Access Key" not in counts


def test_demo_fixture_is_clearly_marked_as_fake():
    text = LEAKED_CONFIG.read_text()
    lowered = text.lower()

    assert "fake" in lowered
    assert "do not" in lowered  # "do not use" / "do not copy" guidance present
    # The specific incident this fixture's design addresses should be
    # documented in the file itself, not just in a commit message.
    assert "push protection" in lowered


def test_demo_findings_do_not_expose_raw_secret_values():
    findings = scan_filesystem_for_sensitive_data_findings(str(DEMO_TARGET))
    assert len(findings) == 1

    payload = findings[0].to_dict()
    serialized = str(payload)

    for secret_value in FIXTURE_SECRET_VALUES:
        assert secret_value not in serialized
    # Categories/counts are fine to expose; the underlying matched text
    # (e.g. the literal PEM body marker) must not appear.
    assert "NOT-A-REAL-KEY-THIS-IS-FAKE-DEMO-CONTENT-ONLY-DO-NOT-USE" not in serialized


def test_demo_json_report_does_not_expose_raw_secret_values():
    findings = scan_filesystem_for_sensitive_data_findings(str(DEMO_TARGET))

    report = findings_json(findings)

    for secret_value in FIXTURE_SECRET_VALUES:
        assert secret_value not in report


def test_demo_markdown_report_does_not_expose_raw_secret_values():
    findings = scan_filesystem_for_sensitive_data_findings(str(DEMO_TARGET))
    context = make_report_context(target_path=str(DEMO_TARGET))

    report = format_markdown_report(findings, context)

    for secret_value in FIXTURE_SECRET_VALUES:
        assert secret_value not in report
    assert "Email" in report
    assert "Generic Secret" in report
