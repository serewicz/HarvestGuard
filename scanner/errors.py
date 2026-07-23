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
