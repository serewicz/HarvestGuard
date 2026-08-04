from __future__ import annotations

import re

# Provider exception messages are attacker- and service-controlled text that
# ends up in CLI stderr, scanner_errors, and Markdown reports. Cap and
# single-line them so a large SDK error body (which can carry response
# fragments, signed URLs, or token material) cannot be dumped wholesale into
# evidence output. The head of the message is where providers put the useful
# part -- the error code and failing operation.
_MAX_PROVIDER_MESSAGE_CHARS = 300

# Credential-bearing substrings known to appear in cloud provider/SDK
# exception text, redacted before the message is truncated -- truncating
# first could leave the credential value intact while cutting off
# everything after it, so redaction must run first. Each pattern captures
# the label/prefix in group 1 and replaces only the value, so useful
# context ("Bearer", "X-Amz-Credential=", the error code/operation around
# it) survives.
#
# This is intentionally NOT a general secret detector -- that is
# classifier.scanner's job (classifier/patterns.py), which this function
# does not touch or duplicate. It targets only the small set of shapes
# explicitly named for HG-005 (bearer tokens; AWS SigV4 signed-URL
# Credential/Signature/Security-Token parameters, in either query-string
# `Key=value` or header `Key: value` form) that are common enough in cloud
# SDK exception text to be worth redacting specifically. It does not claim
# to catch every possible credential shape a provider might ever emit.
_CREDENTIAL_VALUE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)(\bBearer\s+)\S+"),
    re.compile(r"(?i)(\bX-Amz-Credential[:=]\s*)[^\s&;\"']+"),
    re.compile(r"(?i)(\bX-Amz-Signature[:=]\s*)[^\s&;\"']+"),
    re.compile(r"(?i)(\bX-Amz-Security-Token[:=]\s*)[^\s&;\"']+"),
)


def _redact_credential_material(message: str) -> str:
    for pattern in _CREDENTIAL_VALUE_PATTERNS:
        message = pattern.sub(r"\g<1>[REDACTED]", message)
    return message


def sanitize_provider_error(exc: BaseException, limit: int = _MAX_PROVIDER_MESSAGE_CHARS) -> str:
    """Render a provider/SDK exception as a single-line, length-capped,
    credential-redacted string.

    Keeps what a reviewer needs to understand a coverage gap -- the exception
    type and the leading part of the provider's message (error code, failing
    operation) -- without serializing the exception object wholesale, and
    without letting an embedded bearer token or AWS signed-URL credential
    parameter survive into CLI JSON, Markdown reports, or scanner_errors.
    Redaction runs on the raw message, before whitespace normalization and
    truncation, so a credential value cannot survive by sitting past the
    truncation point of an unredacted message.
    """
    message = _redact_credential_material(str(exc))
    message = " ".join(message.split())
    if len(message) > limit:
        message = message[:limit].rstrip() + "... [truncated]"
    if not message:
        return type(exc).__name__
    return f"{type(exc).__name__}: {message}"


class CloudScanError(RuntimeError):
    """Raised when a cloud scanner could not complete a scan.

    The DataFrame-producing cloud scan functions (``scan_s3_bucket``,
    ``scan_gcs_bucket``, ``scan_azure_container``) intentionally swallow
    provider and authentication errors and return an empty DataFrame so the
    Streamlit dashboard degrades gracefully instead of crashing. That empty
    result is indistinguishable from a genuinely empty bucket/container, which
    is wrong for the CLI: a failed scan must not look like a clean, empty
    result and must not exit 0.

    The ``*_findings`` wrappers therefore collect any swallowed scan-level
    error and raise this exception so callers (the CLI) can surface the
    failure via a nonzero exit code while keeping structured output valid.

    ``partial_findings`` carries whatever findings were successfully
    collected before the failure. A failure partway through a scan (a later
    page, a later object) must not discard the evidence already gathered:
    callers surface the error AND keep these findings -- the failure stays
    a failure (nonzero exit), but valid partial results still appear in the
    output rather than silently vanishing.
    """

    def __init__(self, message: str, partial_findings=()):
        super().__init__(message)
        self.partial_findings = tuple(partial_findings)


class LocalScanError(RuntimeError):
    """Raised when a local scanner's directory traversal could not fully
    complete -- a subdirectory it could not list (permission denied,
    unreadable, or another OSError partway through the walk).

    Mirrors CloudScanError's shape for the same reason: the walk itself is
    not aborted by the failure (a permission failure in one subtree must not
    discard evidence gathered everywhere else in the target, including a
    root-level finding whose own markers were already fully validated before
    traversal continued past it), but the result must not silently look like
    a clean, fully-covered scan either. ``partial_findings`` carries every
    finding collected during the scan; callers surface the failure via
    scanner_errors while still keeping those findings.
    """

    def __init__(self, message: str, partial_findings=()):
        super().__init__(message)
        self.partial_findings = tuple(partial_findings)
