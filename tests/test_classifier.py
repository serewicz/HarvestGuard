import os

from classifier.patterns import is_valid_credit_card
from classifier.scanner import classify_text, scan_filesystem_for_sensitive_data


def test_classify_text_detects_email():
    counts = classify_text("Contact us at jane.doe@example.com for details.")
    assert counts == {"Email": 1}


def test_classify_text_detects_ssn():
    counts = classify_text("SSN on file: 123-45-6789")
    assert counts.get("SSN") == 1


def test_classify_text_detects_private_key():
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAK...\n-----END RSA PRIVATE KEY-----"
    counts = classify_text(text)
    assert counts.get("Private Key") == 1


def test_classify_text_detects_aws_access_key():
    counts = classify_text("aws_access_key_id = AKIAABCDEFGHIJKLMNOP")
    assert counts.get("AWS Access Key") == 1


def test_classify_text_detects_generic_secret_assignment():
    counts = classify_text('api_key = "not-a-real-secret-value-0123456789"')
    assert counts.get("Generic Secret") == 1


def test_classify_text_ignores_plain_prose():
    counts = classify_text("The quick brown fox jumps over the lazy dog.")
    assert counts == {}


def _fake_slack_token() -> str:
    """A Slack-token-shaped value (matches SLACK_TOKEN_RE) built from
    separate pieces at import/call time, not as one matchable literal.

    GitHub push protection (and most secret scanners) scan the raw text of
    committed files for exactly this shape -- xox[baprs]-... -- regardless
    of whether the value is real. Concatenating clearly-fake, non-random
    segments means no single string in this file's source ever matches the
    pattern, so this test proves the production regex still works without
    committing anything a scanner would flag. See
    demo/sample_target/sensitive/leaked_config.env's header comment for the
    incident this addresses.
    """
    return "-".join(["xoxb", "FAKE0000000000", "TESTONLYNOTREAL"])


def _fake_github_token() -> str:
    """Same technique as _fake_slack_token(), for GitHub's gh[pousr]_... shape."""
    return "ghp_" + "FAKE0000000000TESTONLYNOTREALVALUE00"


def _fake_aws_access_key() -> str:
    """Same technique as _fake_slack_token(), for AWS's AKIA/ASIA + 16 chars shape."""
    return "AKIA" + "FAKE0000FAKE0000"


def test_classify_text_detects_slack_token_shape_without_a_literal_in_source():
    token = _fake_slack_token()
    assert token.startswith("xoxb-")  # sanity check the helper built the expected shape
    counts = classify_text(f"SLACK_TOKEN={token}")
    assert counts.get("Slack Token") == 1


def test_classify_text_detects_github_token_shape_without_a_literal_in_source():
    token = _fake_github_token()
    assert token.startswith("ghp_")
    counts = classify_text(f"GITHUB_TOKEN={token}")
    assert counts.get("GitHub Token") == 1


def test_classify_text_detects_aws_access_key_shape_without_a_literal_in_source():
    key = _fake_aws_access_key()
    assert key.startswith("AKIA")
    assert len(key) == 20  # AKIA + 16 chars, matching AWS_ACCESS_KEY_RE exactly
    counts = classify_text(f"aws_access_key_id = {key}")
    assert counts.get("AWS Access Key") == 1


def test_credit_card_luhn_validates_real_number_not_arbitrary_digits():
    assert is_valid_credit_card("4111 1111 1111 1111") is True  # known-valid test Visa number
    assert is_valid_credit_card("1234 5678 9012 3456") is False  # fails Luhn


def test_scan_filesystem_for_sensitive_data_flags_matching_file(tmp_path):
    (tmp_path / "customers.csv").write_text("name,email\nJane Doe,jane@example.com\n")
    (tmp_path / "readme.txt").write_text("nothing sensitive here")

    df = scan_filesystem_for_sensitive_data(str(tmp_path))

    assert len(df) == 1
    assert df.iloc[0]["Location"].endswith("customers.csv")
    assert "Email" in df.iloc[0]["Categories"]


def test_scan_filesystem_for_sensitive_data_empty_when_nothing_found(tmp_path):
    (tmp_path / "readme.txt").write_text("nothing sensitive here")
    df = scan_filesystem_for_sensitive_data(str(tmp_path))
    assert df.empty


def test_scan_filesystem_for_sensitive_data_risk_severity(tmp_path):
    (tmp_path / "secret.env").write_text('password = "supersecretvalue123"')
    (tmp_path / "contact.txt").write_text("reach me at jane@example.com")

    df = scan_filesystem_for_sensitive_data(str(tmp_path))
    by_name = df.set_index(df["Location"].apply(os.path.basename))

    assert by_name.loc["secret.env", "Risk"] == "High"
    assert by_name.loc["contact.txt", "Risk"] == "Medium"


def test_scan_filesystem_for_sensitive_data_respects_max_depth(tmp_path):
    deep = tmp_path / "l1" / "l2" / "l3" / "l4"
    deep.mkdir(parents=True)
    (deep / "buried.txt").write_text("jane@example.com")

    df = scan_filesystem_for_sensitive_data(str(tmp_path), max_depth=1)

    assert df.empty
