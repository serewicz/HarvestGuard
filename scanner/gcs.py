from __future__ import annotations

import pandas as pd
from google.api_core.exceptions import GoogleAPIError
from google.auth.exceptions import DefaultCredentialsError
from google.cloud import storage

from finding_adapters import normalize_gcs_df
from findings import NormalizedFinding


def _encryption_status(blob) -> str:
    return "CMEK" if blob.kms_key_name else "Google-managed"


def _risk_for_encryption(encryption: str) -> str:
    return "Low" if encryption == "CMEK" else "Medium"


def scan_gcs_bucket(bucket_name: str, prefix: str = "") -> pd.DataFrame:
    """Scan a GCS bucket for encryption status.

    GCS encrypts every object at rest by default (Google-managed keys), so
    unlike S3 there's no "unencrypted" state to detect. The meaningful
    signal for a due-diligence scan is whether the org has taken on
    customer-managed key (CMEK) control or is relying on the platform
    default.
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
        print(f"Error scanning GCS: {e}")

    return pd.DataFrame(results)


def scan_gcs_bucket_findings(
    bucket_name: str, prefix: str = "", scan_id: str | None = None
) -> list[NormalizedFinding]:
    return normalize_gcs_df(scan_gcs_bucket(bucket_name, prefix=prefix), scan_id=scan_id)
