from __future__ import annotations

from datetime import datetime, timezone

import pandas as pd
from google.api_core.exceptions import GoogleAPIError
from google.auth.exceptions import DefaultCredentialsError
from google.cloud import storage

from finding_adapters import normalize_gcs_df
from findings import NormalizedFinding
from scanner.errors import CloudScanError


def _encryption_status(blob) -> str:
    return "CMEK" if blob.kms_key_name else "Google-managed"


def _risk_for_encryption(encryption: str) -> str:
    return "Low" if encryption == "CMEK" else "Medium"


def scan_gcs_bucket(
    bucket_name: str, prefix: str = "", errors: list[str] | None = None
) -> pd.DataFrame:
    """Scan a GCS bucket for encryption status.

    GCS encrypts every object at rest by default (Google-managed keys), so
    unlike S3 there's no "unencrypted" state to detect. The meaningful
    signal for a due-diligence scan is whether the org has taken on
    customer-managed key (CMEK) control or is relying on the platform
    default.

    A scan-level failure (auth/provider error) is swallowed so the Streamlit
    dashboard degrades to an empty result. When ``errors`` is provided, the
    failure is recorded there instead of printed, so a caller (the CLI) can
    distinguish a failed scan from an empty bucket and report it explicitly.
    """
    results = []

    try:
        client = storage.Client()
        for blob in client.list_blobs(bucket_name, prefix=prefix):
            encryption = _encryption_status(blob)
            results.append({
                "Location": f"gs://{bucket_name}/{blob.name}",
                "Size": blob.size,
                "Modified": blob.updated,
                "Encryption": encryption,
                "Risk": _risk_for_encryption(encryption),
            })
    except (GoogleAPIError, DefaultCredentialsError) as e:
        # DefaultCredentialsError comes from google.auth, not google.api_core --
        # storage.Client() resolves credentials eagerly at construction time,
        # so an auth failure surfaces here rather than from a list_blobs() call.
        message = f"Error scanning GCS: {e}"
        if errors is None:
            print(message)
        else:
            errors.append(message)

    return pd.DataFrame(results)


def scan_gcs_bucket_findings(
    bucket_name: str, prefix: str = "", scan_id: str | None = None
) -> list[NormalizedFinding]:
    errors: list[str] = []
    # Collection time for the scan (observed_at), not the blob's own update time.
    collected_at = datetime.now(timezone.utc)
    df = scan_gcs_bucket(bucket_name, prefix=prefix, errors=errors)
    if errors:
        # Still a failure (the caller exits nonzero), but the findings
        # gathered before the failure ride along on the exception instead
        # of being discarded -- a later blob/page failing must not erase
        # the evidence already collected.
        raise CloudScanError(
            "; ".join(errors),
            partial_findings=normalize_gcs_df(df, scan_id=scan_id, observed_at=collected_at),
        )
    return normalize_gcs_df(df, scan_id=scan_id, observed_at=collected_at)
