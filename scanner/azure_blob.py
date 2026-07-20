from __future__ import annotations

import pandas as pd
from azure.core.exceptions import AzureError
from azure.identity import DefaultAzureCredential
from azure.storage.blob import BlobServiceClient


def _encryption_status(blob) -> str:
    scope = getattr(blob, "encryption_scope", None)
    return f"Customer-managed (scope: {scope})" if scope else "Microsoft-managed"


def _risk_for_encryption(encryption: str) -> str:
    return "Low" if encryption.startswith("Customer-managed") else "Medium"


def scan_azure_container(account_url: str, container_name: str, prefix: str = "") -> pd.DataFrame:
    """Scan an Azure Blob container for encryption status.

    Azure Storage Service Encryption is mandatory and always on, so -- like
    GCS -- there's no "unencrypted" state. The signal worth surfacing is
    whether blobs use a customer-managed encryption scope or the
    Microsoft-managed default.
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
        print(f"Error scanning Azure Blob: {e}")

    return pd.DataFrame(results)
