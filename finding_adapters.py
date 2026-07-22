from __future__ import annotations

from typing import Any

import pandas as pd

from findings import NormalizedFinding


def normalize_filesystem_df(
    df: pd.DataFrame, scan_id: str | None = None
) -> list[NormalizedFinding]:
    return [_filesystem_finding_from_row(row, scan_id) for row in _records(df)]


def _filesystem_finding_from_row(
    row: dict[str, Any], scan_id: str | None
) -> NormalizedFinding:
    # "directory" rows are coverage-limitation findings (unreadable
    # directory, or a directory beyond the configured max_depth boundary)
    # -- they never have file-level metadata to report, unlike "file" rows.
    asset_type = row.get("Asset Type", "file")
    is_file = asset_type == "file"
    return NormalizedFinding(
        scan_id=scan_id,
        source_type="local_filesystem",
        asset_type=asset_type,
        location=row["Location"],
        scanner_name="filesystem",
        scanner_version="0.1.0",
        observed_at=row.get("Collected At"),
        evidence=row.get("Evidence"),
        confidence=row.get("Confidence"),
        confidence_rationale=row.get("Confidence Rationale"),
        collection_method=row.get("Collection Method"),
        collection_source=row.get("Collection Source"),
        rule_id=row.get("Rule ID"),
        verification_rationale=row.get("Verification Rationale"),
        repeatable=row.get("Repeatable"),
        ownership_signals=_filesystem_ownership_signals(row) if is_file else {},
        unknowns=row.get("Unknowns") or [],
        limitations=row.get("Limitations") or [],
        technical_metadata=(
            _metadata(row, ["Size", "Modified", "Encryption"]) if is_file else {}
        ),
    )


def _filesystem_ownership_signals(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "uid": row.get("UID"),
        "owner_name": row.get("Owner Name"),
        "gid": row.get("GID"),
        "group_name": row.get("Group Name"),
        "mode_octal": row.get("Mode Octal"),
        "permissions": row.get("Permissions"),
        "acl_present": row.get("ACL Present"),
    }


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
            # Location alone (file:line) is not always a unique identity: two
            # independent semgrep rules can legitimately match the same line
            # (e.g. `DES.new(key, DES.MODE_ECB)` matches both weak-cipher-des
            # and weak-cipher-ecb-mode). rule_id -- already computed by the
            # scanner as the semgrep check id -- disambiguates them.
            rule_id=row.get("Rule"),
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
            # location alone doesn't distinguish two certificates/keys parsed
            # from the same PKCS#12 or PEM file -- both share source_type,
            # asset_type, location, scanner_name, and rule_id (unset).
            # Fingerprint is already computed by the scanner for every
            # successfully-parsed certificate/key and is a stable, content-
            # derived value, so it's a natural identity_key. Left unset (None)
            # for findings without one (e.g. malformed/undecryptable blocks),
            # matching identity_key's "when present" contract rather than
            # fabricating a discriminator that isn't there.
            identity_key=row.get("Fingerprint") or None,
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
