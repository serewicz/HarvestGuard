from __future__ import annotations


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
    """
