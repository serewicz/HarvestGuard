from __future__ import annotations

from datetime import datetime, timezone

import pandas as pd
from azure.core.exceptions import AzureError
from azure.identity import DefaultAzureCredential
from azure.storage.blob import BlobServiceClient

from finding_adapters import normalize_azure_blob_df
from findings import NormalizedFinding
from scanner.errors import CloudScanError


def _encryption_status(blob) -> str:
    scope = getattr(blob, "encryption_scope", None)
    return f"Customer-managed (scope: {scope})" if scope else "Microsoft-managed"


def _risk_for_encryption(encryption: str) -> str:
    return "Low" if encryption.startswith("Customer-managed") else "Medium"


def scan_azure_container(
    account_url: str,
    container_name: str,
    prefix: str = "",
    errors: list[str] | None = None,
) -> pd.DataFrame:
    """Scan an Azure Blob container for encryption status.

    Azure Storage Service Encryption is mandatory and always on, so -- like
    GCS -- there's no "unencrypted" state. The signal worth surfacing is
    whether blobs use a customer-managed encryption scope or the
    Microsoft-managed default.

    A scan-level failure (auth/provider error) is swallowed so the Streamlit
    dashboard degrades to an empty result. When ``errors`` is provided, the
    failure is recorded there instead of printed, so a caller (the CLI) can
    distinguish a failed scan from an empty container and report it explicitly.
    """
    results = []

    try:
        service_client = BlobServiceClient(
            account_url=account_url, credential=DefaultAzureCredential()
        )
        container_client = service_client.get_container_client(container_name)
        for blob in container_client.list_blobs(name_starts_with=prefix):
            encryption = _encryption_status(blob)
            results.append({
                "Location": f"{account_url.rstrip('/')}/{container_name}/{blob.name}",
                "Size": blob.size,
                "Modified": blob.last_modified,
                "Encryption": encryption,
                "Risk": _risk_for_encryption(encryption),
            })
    except AzureError as e:
        message = f"Error scanning Azure Blob: {e}"
        if errors is None:
            print(message)
        else:
            errors.append(message)

    return pd.DataFrame(results)


def scan_azure_container_findings(
    account_url: str,
    container_name: str,
    prefix: str = "",
    scan_id: str | None = None,
) -> list[NormalizedFinding]:
    errors: list[str] = []
    # Collection time for the scan (observed_at), not the blob's own last-modified time.
    collected_at = datetime.now(timezone.utc)
    df = scan_azure_container(account_url, container_name, prefix=prefix, errors=errors)
    if errors:
        raise CloudScanError("; ".join(errors))
    return normalize_azure_blob_df(df, scan_id=scan_id, observed_at=collected_at)
