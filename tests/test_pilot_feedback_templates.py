"""Tests for the pilot feedback issue forms (GitHub issue #135).

The four forms under `.github/ISSUE_TEMPLATE/` that first external pilot users
are pointed at -- install problems, scan/output problems, validation harness
feedback, and documentation confusion -- have to stay safe and lightweight:
they solicit commands, logs, and paths, so every one of them must tell the
reporter to sanitize first, route suspected vulnerabilities to the private
process in SECURITY.md instead of a public issue, and avoid turning a feedback
request into a product claim or a support commitment.

These tests read the YAML only; they open no network connection and run no
subprocess.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).parent.parent
TEMPLATE_DIR = ROOT / ".github" / "ISSUE_TEMPLATE"

PILOT_FORMS = (
    "install-problem.yml",
    "scan-output-problem.yml",
    "validation-feedback.yml",
    "documentation-confusion.yml",
)

# Every field type GitHub issue forms accept.
FORM_FIELD_TYPES = {"markdown", "input", "textarea", "dropdown", "checkboxes"}

SECURITY_URL = "https://github.com/serewicz/HarvestGuard/blob/main/SECURITY.md"

# The material the forms must warn against, per the issue's safety list.
PROHIBITED_MATERIAL = (
    "real secrets",
    "private keys",
    "reconstructable key material",
    "production certificates",
    "proprietary source trees",
    "confidential scan output",
    "passphrases",
    "plaintext sensitive data",
    "decrypted material",
    "raw secret values",
    "credentials or tokens",
    "sensitive internal hostnames or paths",
)

# Labels a feedback category may carry. None of these imply severity,
# exploitability, business risk, or a response commitment.
ALLOWED_LABELS = {
    "pilot-feedback",
    "install",
    "scan-output",
    "validation",
    "documentation",
}


def _load(name: str) -> dict:
    return yaml.safe_load((TEMPLATE_DIR / name).read_text())


def _text(name: str) -> str:
    return (TEMPLATE_DIR / name).read_text()


def _markdown_blocks(form: dict) -> str:
    return "\n".join(
        element["attributes"]["value"]
        for element in form["body"]
        if element["type"] == "markdown"
    )


@pytest.mark.parametrize("name", PILOT_FORMS)
def test_pilot_form_exists(name: str) -> None:
    assert (TEMPLATE_DIR / name).is_file(), f"missing pilot feedback form {name}"


@pytest.mark.parametrize("name", sorted(p.name for p in TEMPLATE_DIR.glob("*.yml")))
def test_issue_form_structure_is_valid(name: str) -> None:
    """Every issue form parses and uses the documented issue-form schema."""
    form = _load(name)
    assert isinstance(form, dict), f"{name} is not a YAML mapping"
    assert form.get("name"), f"{name} has no form name"
    assert form.get("description"), f"{name} has no description"
    assert isinstance(form.get("body"), list) and form["body"], f"{name} has no body"

    seen_ids: set[str] = set()
    for element in form["body"]:
        kind = element.get("type")
        assert kind in FORM_FIELD_TYPES, f"{name} uses unknown field type {kind!r}"
        attributes = element.get("attributes")
        assert isinstance(attributes, dict), f"{name} has a field with no attributes"

        if kind == "markdown":
            assert attributes.get("value"), f"{name} has an empty markdown block"
            continue

        assert attributes.get("label"), f"{name} has an unlabelled {kind} field"
        field_id = element.get("id")
        assert field_id, f"{name} has a {kind} field with no id"
        assert field_id not in seen_ids, f"{name} reuses field id {field_id!r}"
        seen_ids.add(field_id)

        if kind == "dropdown":
            options = attributes.get("options")
            assert options, f"{name}:{field_id} is a dropdown with no options"
            assert all(
                isinstance(option, str) and option for option in options
            ), f"{name}:{field_id} has a non-string dropdown option"
        elif kind == "checkboxes":
            options = attributes.get("options")
            assert options, f"{name}:{field_id} is a checkboxes field with no options"
            assert all(
                option.get("label") for option in options
            ), f"{name}:{field_id} has an unlabelled checkbox"


@pytest.mark.parametrize("name", PILOT_FORMS)
def test_form_warns_against_sensitive_material(name: str) -> None:
    """The safety warning is in a markdown block, so it renders before any field."""
    intro = _markdown_blocks(_load(name)).lower()
    assert "sanitize" in intro, f"{name} does not tell the reporter to sanitize"
    for phrase in PROHIBITED_MATERIAL:
        assert phrase in intro, f"{name} omits {phrase!r} from its safety warning"


@pytest.mark.parametrize("name", PILOT_FORMS)
def test_form_asks_for_a_sanitization_confirmation(name: str) -> None:
    form = _load(name)
    checkboxes = [
        option["label"].lower()
        for element in form["body"]
        if element["type"] == "checkboxes"
        for option in element["attributes"]["options"]
    ]
    assert any(
        "no secrets" in label for label in checkboxes
    ), f"{name} has no sanitization confirmation checkbox"


@pytest.mark.parametrize("name", PILOT_FORMS)
def test_form_routes_vulnerabilities_to_the_private_process(name: str) -> None:
    intro = _markdown_blocks(_load(name))
    assert SECURITY_URL in intro, f"{name} does not link SECURITY.md"
    lowered = intro.lower()
    assert (
        "security vulnerability" in lowered
    ), f"{name} does not mention security vulnerabilities"
    assert (
        "public issue" in lowered
    ), f"{name} does not say to keep a vulnerability out of a public issue"


@pytest.mark.parametrize("name", PILOT_FORMS)
def test_form_points_at_the_synthetic_demo_corpus(name: str) -> None:
    assert (
        "demo/sample_target/" in _markdown_blocks(_load(name))
    ), f"{name} does not encourage reproducing against the demo corpus"


@pytest.mark.parametrize("name", PILOT_FORMS)
def test_form_does_not_block_useful_reports(name: str) -> None:
    """At most one free-text field and the sanitization checkbox are required."""
    form = _load(name)
    required_text_fields = [
        element["id"]
        for element in form["body"]
        if element["type"] in {"input", "textarea", "dropdown"}
        and element.get("validations", {}).get("required")
    ]
    optional_fields = [
        element["id"]
        for element in form["body"]
        if element["type"] in {"input", "textarea", "dropdown"}
        and not element.get("validations", {}).get("required")
    ]
    assert len(required_text_fields) <= 1, (
        f"{name} requires too many fields to file a useful report: "
        f"{required_text_fields}"
    )
    assert optional_fields, f"{name} has no optional fields"


@pytest.mark.parametrize("name", PILOT_FORMS)
def test_form_labels_stay_neutral(name: str) -> None:
    labels = set(_load(name).get("labels", []))
    assert labels, f"{name} carries no label"
    assert labels <= ALLOWED_LABELS, (
        f"{name} carries labels outside the neutral feedback categories: "
        f"{sorted(labels - ALLOWED_LABELS)}"
    )


@pytest.mark.parametrize("name", PILOT_FORMS)
def test_form_makes_no_support_promise(name: str) -> None:
    text = _text(name).lower()
    forbidden = (
        r"\bsla\b",
        r"service[- ]level agreement",
        r"paid support",
        r"support tier",
        r"we (will|aim to) (respond|reply|fix|acknowledge)",
        r"within \d+ (business )?(hour|day|week)",
        r"guaranteed response",
        r"response time",
    )
    for pattern in forbidden:
        assert not re.search(pattern, text), f"{name} implies a support commitment: {pattern}"


@pytest.mark.parametrize("name", PILOT_FORMS)
def test_form_makes_no_expanded_product_claim(name: str) -> None:
    text = _text(name).lower()
    forbidden = (
        r"production[- ]ready",
        r"enterprise[- ]ready",
        r"complete inventory",
        r"full inventory",
        r"comprehensive inventory",
        r"complete (format )?(support|coverage)",
        r"all (supported )?formats",
        r"exploitab",
        r"runtime exposure",
        r"business risk",
        r"remediation priority",
        r"quantum[- ](ready|readiness|safe)",
        r"\bcompliance\b",
        r"\bwindows\b",
        r"\bwsl\b",
    )
    for pattern in forbidden:
        assert not re.search(
            pattern, text
        ), f"{name} makes a claim outside the product boundary: {pattern}"
