"""Tests for scanner/errors.py's sanitize_provider_error, which caps and
single-lines provider/SDK exception text before it reaches CLI stderr,
scanner_errors, or Markdown reports (HG-005, GitHub issue #17).

Provider exception messages are service-controlled text that can carry
response fragments, signed URLs, or token material -- these tests exist so
that risk is bounded (length-capped, single-line) without hiding the
information a reviewer actually needs (exception type, leading message text).
"""

from __future__ import annotations

from scanner.errors import CloudScanError, sanitize_provider_error


def test_sanitize_provider_error_includes_exception_type_and_message():
    result = sanitize_provider_error(ValueError("bucket not found"))

    assert result == "ValueError: bucket not found"


def test_sanitize_provider_error_falls_back_to_type_name_for_empty_message():
    result = sanitize_provider_error(RuntimeError())

    assert result == "RuntimeError"


def test_sanitize_provider_error_collapses_multiline_messages_to_one_line():
    exc = RuntimeError("line one\nline two\r\nline three\ttabbed")

    result = sanitize_provider_error(exc)

    assert "\n" not in result
    assert "\r" not in result
    assert "\t" not in result
    assert "line one line two line three tabbed" in result


def test_sanitize_provider_error_truncates_long_messages():
    # A large SDK error body (which can carry response fragments, signed
    # URLs, or token material) must not be dumped wholesale into evidence
    # output -- only the leading part, where providers put the error code
    # and failing operation, survives.
    long_message = "A" * 1000
    exc = RuntimeError(long_message)

    result = sanitize_provider_error(exc)

    assert len(result) < len(long_message)
    assert result.endswith("... [truncated]")
    assert "A" * 1000 not in result


def test_sanitize_provider_error_respects_a_custom_limit():
    exc = RuntimeError("A" * 50)

    result = sanitize_provider_error(exc, limit=10)

    assert result == "RuntimeError: AAAAAAAAAA... [truncated]"


def test_sanitize_provider_error_does_not_truncate_short_messages():
    exc = RuntimeError("short")

    result = sanitize_provider_error(exc)

    assert result == "RuntimeError: short"
    assert "truncated" not in result


def test_sanitize_provider_error_bounds_a_long_signed_url_via_truncation_and_redaction():
    # A signed URL's query string (SigV4 credentials, expiry, signature) is
    # exactly the kind of token material this function must not leak
    # wholesale. With a short limit, truncation is the backstop even before
    # considering explicit redaction -- verified here by confirming a long
    # embedded signed URL does not survive intact.
    fake_signed_url = (
        "https://bucket.s3.amazonaws.com/key?X-Amz-Algorithm=AWS4-HMAC-SHA256"
        "&X-Amz-Credential=" + "FAKE0000FAKE0000FAKE0000FAKE0000" * 10
        + "&X-Amz-Signature=" + "deadbeef" * 20
    )
    exc = RuntimeError(f"PUT request failed: {fake_signed_url}")

    result = sanitize_provider_error(exc, limit=80)

    assert fake_signed_url not in result
    assert result.endswith("... [truncated]")


# --- Explicit credential-value redaction (independent of truncation) -------
#
# These use a generous limit (well above _MAX_PROVIDER_MESSAGE_CHARS'
# default and any value used below) so the credential value's absence is
# proven by redaction, not merely because truncation happened to cut it off.
# All synthetic values are built by concatenating literal fragments at
# runtime, not as a single matchable literal, so committed test source does
# not itself contain a production-shaped secret (same technique as
# tests/test_classifier.py's _fake_aws_key() and friends).


def _fake_bearer_token() -> str:
    return "ey" + "J" + "FAKE0000BEARERTOKEN0000FAKE" + ".signature-part"


def _fake_amz_credential() -> str:
    return "AKIA" + "FAKE0000FAKE0000" + "/20260101/us-east-1/s3/aws4_request"


def _fake_amz_signature() -> str:
    return "deadbeef" * 8


def _fake_amz_security_token() -> str:
    return "FAKESECURITYTOKEN" + "0000FAKE0000FAKE0000EXTRA"


def test_sanitize_provider_error_redacts_bearer_token():
    token = _fake_bearer_token()
    exc = RuntimeError(f"Authorization: Bearer {token}")

    result = sanitize_provider_error(exc)

    assert token not in result
    assert "Bearer [REDACTED]" in result
    assert "Authorization:" in result  # surrounding context still useful


def test_sanitize_provider_error_redacts_x_amz_credential():
    value = _fake_amz_credential()
    exc = RuntimeError(
        f"SignatureDoesNotMatch: X-Amz-Credential={value}&X-Amz-Date=20260101T000000Z"
    )

    result = sanitize_provider_error(exc)

    assert value not in result
    assert "X-Amz-Credential=[REDACTED]" in result
    # Adjacent, non-credential query params remain visible.
    assert "X-Amz-Date=20260101T000000Z" in result
    assert "SignatureDoesNotMatch" in result


def test_sanitize_provider_error_redacts_x_amz_signature():
    value = _fake_amz_signature()
    exc = RuntimeError(f"RequestTimeTooSkewed: X-Amz-Signature={value}")

    result = sanitize_provider_error(exc)

    assert value not in result
    assert "X-Amz-Signature=[REDACTED]" in result
    assert "RequestTimeTooSkewed" in result


def test_sanitize_provider_error_redacts_x_amz_security_token():
    value = _fake_amz_security_token()
    exc = RuntimeError(f"ExpiredToken: X-Amz-Security-Token={value} has expired")

    result = sanitize_provider_error(exc)

    assert value not in result
    assert "X-Amz-Security-Token=[REDACTED]" in result
    assert "ExpiredToken" in result
    assert "has expired" in result


def test_sanitize_provider_error_redacts_combined_aws_signed_url():
    # A realistic SigV4 signed-URL error carries all three credential
    # parameters together -- none may survive, and the non-credential
    # parameters and error code must still be legible.
    credential = _fake_amz_credential()
    signature = _fake_amz_signature()
    security_token = _fake_amz_security_token()
    signed_url = (
        "https://bucket.s3.amazonaws.com/key?X-Amz-Algorithm=AWS4-HMAC-SHA256"
        f"&X-Amz-Credential={credential}"
        "&X-Amz-Date=20260101T000000Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host"
        f"&X-Amz-Security-Token={security_token}"
        f"&X-Amz-Signature={signature}"
    )
    exc = RuntimeError(f"ExpiredToken: request expired, url: {signed_url}")

    result = sanitize_provider_error(exc)

    assert credential not in result
    assert signature not in result
    assert security_token not in result
    assert "X-Amz-Credential=[REDACTED]" in result
    assert "X-Amz-Signature=[REDACTED]" in result
    assert "X-Amz-Security-Token=[REDACTED]" in result
    # Non-credential context remains readable.
    assert "X-Amz-Algorithm=AWS4-HMAC-SHA256" in result
    assert "X-Amz-Expires=3600" in result
    assert "ExpiredToken" in result


def test_sanitize_provider_error_leaves_normal_non_secret_errors_readable():
    exc = RuntimeError("AccessDenied: User is not authorized to perform s3:GetObject")

    result = sanitize_provider_error(exc)

    assert result == (
        "RuntimeError: AccessDenied: User is not authorized to perform s3:GetObject"
    )
    assert "[REDACTED]" not in result


def test_cloud_scan_error_carries_sanitized_messages_not_raw_exception_objects():
    # CloudScanError's own message is built by the scanner wrappers by
    # joining already-sanitized strings -- it never stores or exposes the
    # original exception object.
    message = sanitize_provider_error(RuntimeError("ExpiredToken: signature expired"))
    error = CloudScanError(message)

    assert str(error) == "RuntimeError: ExpiredToken: signature expired"
    assert not hasattr(error, "__cause__") or error.__cause__ is None
