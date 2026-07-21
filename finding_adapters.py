from __future__ import annotations

from typing import Any

import pandas as pd

from findings import NormalizedFinding


def normalize_filesystem_df(
    df: pd.DataFrame, scan_id: str | None = None
) -> list[NormalizedFinding]:
    return [
        NormalizedFinding(
            scan_id=scan_id,
            source_type="local_filesystem",
            asset_type="file",
            location=row["Location"],
            scanner_name="filesystem",
            scanner_version="0.1.0",
            observed_at=row.get("Modified"),
            evidence=f"Encryption status observed: {row.get('Encryption')}",
            confidence=_confidence_for_encryption(row.get("Encryption")),
            technical_metadata=_metadata(row, ["Size", "Modified", "Encryption", "Owner"]),
        )
        for row in _records(df)
    ]


def normalize_s3_df(df: pd.DataFrame, scan_id: str | None = None) -> list[NormalizedFinding]:
    return [
        NormalizedFinding(
            scan_id=scan_id,
            source_type="aws_s3",
            asset_type="object",
            location=row["Location"],
            scanner_name="s3",
            scanner_version="0.1.0",
            observed_at=row.get("Modified"),
            evidence=f"S3 ServerSideEncryption metadata: {row.get('Encryption')}",
            confidence="High",
            technical_metadata=_metadata(row, ["Size", "Modified", "Encryption"]),
        )
        for row in _records(df)
    ]


def normalize_gcs_df(df: pd.DataFrame, scan_id: str | None = None) -> list[NormalizedFinding]:
    return [
        NormalizedFinding(
            scan_id=scan_id,
            source_type="gcs",
            asset_type="object",
            location=row["Location"],
            scanner_name="gcs",
            scanner_version="0.1.0",
            observed_at=row.get("Modified"),
            evidence=f"GCS encryption metadata: {row.get('Encryption')}",
            confidence="High",
            technical_metadata=_metadata(row, ["Size", "Modified", "Encryption"]),
        )
        for row in _records(df)
    ]


def normalize_azure_blob_df(
    df: pd.DataFrame, scan_id: str | None = None
) -> list[NormalizedFinding]:
    return [
        NormalizedFinding(
            scan_id=scan_id,
            source_type="azure_blob",
            asset_type="blob",
            location=row["Location"],
            scanner_name="azure_blob",
            scanner_version="0.1.0",
            observed_at=row.get("Modified"),
            evidence=f"Azure Blob encryption metadata: {row.get('Encryption')}",
            confidence="High",
            technical_metadata=_metadata(row, ["Size", "Modified", "Encryption"]),
        )
        for row in _records(df)
    ]


def normalize_sensitive_data_df(
    df: pd.DataFrame, scan_id: str | None = None
) -> list[NormalizedFinding]:
    return [
        NormalizedFinding(
            scan_id=scan_id,
            source_type="local_sensitive_data",
            asset_type="file",
            location=row["Location"],
            scanner_name="sensitive_data_classifier",
            scanner_version="0.1.0",
            observed_at=row.get("Modified"),
            evidence=(
                f"Sensitive data categories detected: {row.get('Categories')}; "
                f"total matches: {row.get('Total Matches')}"
            ),
            confidence="Medium",
            technical_metadata=_metadata(
                row, ["Size", "Modified", "Categories", "Total Matches"]
            ),
        )
        for row in _records(df)
    ]


def normalize_code_analysis_df(
    df: pd.DataFrame, scan_id: str | None = None
) -> list[NormalizedFinding]:
    return [
        NormalizedFinding(
            scan_id=scan_id,
            source_type="code_analysis",
            asset_type="source_code",
            location=row["Location"],
            scanner_name="semgrep_crypto_rules",
            scanner_version="0.1.0",
            evidence=f"Semgrep rule matched: {row.get('Rule')}",
            confidence="High",
            technical_metadata=_metadata(row, ["Rule", "Message"]),
        )
        for row in _records(df)
    ]


def normalize_crypto_inventory_df(
    df: pd.DataFrame, scan_id: str | None = None
) -> list[NormalizedFinding]:
    return [
        NormalizedFinding(
            finding_id=row.get("Finding ID"),
            scan_id=scan_id,
            source_type="crypto_inventory",
            asset_type=row["Asset Type"],
            location=row["Location"],
            scanner_name=row.get("Scanner", "crypto_inventory"),
            scanner_version=row.get("Scanner Version", "0.1.0"),
            observed_at=row.get("Observed At"),
            evidence=row.get("Evidence", ""),
            confidence=row.get("Confidence", "Low"),
            errors=_errors(row.get("Errors")),
            technical_metadata=_metadata(
                row,
                [
                    "Algorithm",
                    "Key Size",
                    "Signature Algorithm",
                    "Expiration",
                    "Issuer",
                    "Subject",
                    "Fingerprint",
                ],
            ),
        )
        for row in _records(df)
    ]


def _records(df: pd.DataFrame) -> list[dict[str, Any]]:
    return df.to_dict(orient="records")


def _metadata(row: dict[str, Any], keys: list[str]) -> dict[str, Any]:
    return {key: row.get(key) for key in keys if key in row}


def _errors(value: Any) -> list[str]:
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return []
    if isinstance(value, list):
        return [str(item) for item in value if str(item)]
    return [part.strip() for part in str(value).split(";") if part.strip()]


def _confidence_for_encryption(encryption: Any) -> str:
    if encryption is None:
        return "Low"
    encryption_text = str(encryption)
    if encryption_text == "Unknown":
        return "Low"
    if encryption_text.startswith("File-level"):
        return "High"
    return "Medium"
