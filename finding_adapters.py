from __future__ import annotations

from datetime import datetime
from typing import Any, NamedTuple

import pandas as pd

from findings import NormalizedFinding


class ScannerIdentity(NamedTuple):
    """The scanner name and version an adapter stamps onto its findings."""

    name: str
    version: str


# Declared here rather than only inline below so a caller can name a scanner it
# invoked without having a finding to read the identity off: a scanner that
# produced nothing, or failed before producing anything, still has to appear in
# the report's Scanner Versions table with its version.
FILESYSTEM_SCANNER = ScannerIdentity("filesystem", "0.1.0")
S3_SCANNER = ScannerIdentity("s3", "0.1.0")
GCS_SCANNER = ScannerIdentity("gcs", "0.1.0")
AZURE_BLOB_SCANNER = ScannerIdentity("azure_blob", "0.1.0")
SENSITIVE_DATA_SCANNER = ScannerIdentity("sensitive_data_classifier", "0.1.0")
CODE_ANALYSIS_SCANNER = ScannerIdentity("semgrep_crypto_rules", "0.1.0")
# Aggregate filesystem context findings: one record per mount, standing in for
# the volume/filesystem/platform context shared by every ordinary regular file
# inspected on that mount, instead of repeating that context once per file.
# Declared here (rather than in scanner/filesystem.py) because both the scanner
# that emits these findings and the report layer that classifies and counts
# them need the same identifiers, and both already depend on this module.
FILESYSTEM_CONTEXT_ASSET_TYPE = "volume"
FILESYSTEM_FILES_INSPECTED_KEY = "Regular Files Inspected"
FILESYSTEM_FILES_REPRESENTED_KEY = "Files Represented By This Context"
FILESYSTEM_FILES_WITH_FINDINGS_KEY = "Files With Individual Findings"
# technical_metadata keys carried by an aggregate context finding. "Encryption"
# is reused from the per-file records so a consumer reads volume status from
# the same key; Size/Modified are deliberately absent, since a mount has
# neither.
FILESYSTEM_CONTEXT_METADATA_KEYS = [
    "Encryption",
    "Mount Point",
    "Platform",
    FILESYSTEM_FILES_INSPECTED_KEY,
    FILESYSTEM_FILES_REPRESENTED_KEY,
    FILESYSTEM_FILES_WITH_FINDINGS_KEY,
]

# scanner/crypto_inventory.py stamps its own SCANNER_NAME/SCANNER_VERSION onto
# each row; these are the fallbacks used when a row omits them. They are
# duplicated as literals because scanner.crypto_inventory imports this module.
CRYPTO_INVENTORY_SCANNER = ScannerIdentity("crypto_inventory", "0.1.0")


def normalize_filesystem_df(
    df: pd.DataFrame, scan_id: str | None = None
) -> list[NormalizedFinding]:
    return [_filesystem_finding_from_row(row, scan_id) for row in _records(df)]


def _filesystem_finding_from_row(
    row: dict[str, Any], scan_id: str | None
) -> NormalizedFinding:
    # "directory" and "special_file" rows are coverage-limitation findings
    # (an unreadable directory, a directory beyond the configured max_depth
    # boundary, or a symlink/FIFO/socket/device entry skipped for safety) --
    # they never have file-level metadata to report, unlike "file" rows, and
    # must not carry encryption metadata that was never observed.
    #
    # A "volume" row is an aggregate mount/volume/platform context record: it
    # has its own metadata (volume status, mount point, platform, how many
    # regular files it represents) but no per-file ownership signals, since it
    # describes a mount rather than any single file on it.
    asset_type = row.get("Asset Type", "file")
    is_file = asset_type == "file"
    is_context = asset_type == FILESYSTEM_CONTEXT_ASSET_TYPE
    return NormalizedFinding(
        scan_id=scan_id,
        source_type="local_filesystem",
        asset_type=asset_type,
        location=row["Location"],
        scanner_name=FILESYSTEM_SCANNER.name,
        scanner_version=FILESYSTEM_SCANNER.version,
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
        # Stable technical identity of the mount an aggregate context record
        # describes; unset for every other filesystem row, whose location
        # already identifies it.
        identity_key=_optional_str(row.get("Identity Key")),
        technical_metadata=_filesystem_metadata(row, is_file=is_file, is_context=is_context),
    )


def _filesystem_metadata(
    row: dict[str, Any], is_file: bool, is_context: bool
) -> dict[str, Any]:
    if is_file:
        return _metadata(row, ["Size", "Modified", "Encryption"])
    if is_context:
        return _metadata(row, FILESYSTEM_CONTEXT_METADATA_KEYS)
    return {}


def _optional_str(value: Any) -> str | None:
    """Row values arrive via a DataFrame, so a column another row type supplies
    reads back as NaN here rather than as None -- and NaN is truthy, so it would
    otherwise be passed through as a real value."""
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return None
    return str(value) or None


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


def normalize_s3_df(
    df: pd.DataFrame,
    scan_id: str | None = None,
    observed_at: str | datetime | None = None,
) -> list[NormalizedFinding]:
    # observed_at is the scan's collection time (passed in by the scan
    # wrapper), never the object's own LastModified time -- the latter is a
    # property of the asset, not of the observation, and is preserved in
    # technical_metadata["Modified"]. See ASSET_INVENTORY.md / NORMALIZED_FINDINGS.md.
    return [
        NormalizedFinding(
            scan_id=scan_id,
            source_type="aws_s3",
            asset_type="object",
            location=row["Location"],
            scanner_name=S3_SCANNER.name,
            scanner_version=S3_SCANNER.version,
            observed_at=observed_at,
            evidence=f"S3 ServerSideEncryption metadata: {row.get('Encryption')}",
            confidence="High",
            technical_metadata=_metadata(row, ["Size", "Modified", "Encryption"]),
        )
        for row in _records(df)
    ]


def normalize_gcs_df(
    df: pd.DataFrame,
    scan_id: str | None = None,
    observed_at: str | datetime | None = None,
) -> list[NormalizedFinding]:
    return [
        NormalizedFinding(
            scan_id=scan_id,
            source_type="gcs",
            asset_type="object",
            location=row["Location"],
            scanner_name=GCS_SCANNER.name,
            scanner_version=GCS_SCANNER.version,
            observed_at=observed_at,
            evidence=f"GCS encryption metadata: {row.get('Encryption')}",
            confidence="High",
            technical_metadata=_metadata(row, ["Size", "Modified", "Encryption"]),
        )
        for row in _records(df)
    ]


def normalize_azure_blob_df(
    df: pd.DataFrame,
    scan_id: str | None = None,
    observed_at: str | datetime | None = None,
) -> list[NormalizedFinding]:
    return [
        NormalizedFinding(
            scan_id=scan_id,
            source_type="azure_blob",
            asset_type="blob",
            location=row["Location"],
            scanner_name=AZURE_BLOB_SCANNER.name,
            scanner_version=AZURE_BLOB_SCANNER.version,
            observed_at=observed_at,
            evidence=f"Azure Blob encryption metadata: {row.get('Encryption')}",
            confidence="High",
            technical_metadata=_metadata(row, ["Size", "Modified", "Encryption"]),
        )
        for row in _records(df)
    ]


def normalize_sensitive_data_df(
    df: pd.DataFrame,
    scan_id: str | None = None,
    observed_at: str | datetime | None = None,
) -> list[NormalizedFinding]:
    # observed_at is the scan's collection time (passed in by the scan
    # wrapper), never the file's own "Modified" mtime -- the latter is a
    # property of the asset, not of the observation, and is preserved in
    # technical_metadata["Modified"]. See ASSET_INVENTORY.md / NORMALIZED_FINDINGS.md.
    return [
        NormalizedFinding(
            scan_id=scan_id,
            source_type="local_sensitive_data",
            asset_type="file",
            location=row["Location"],
            scanner_name=SENSITIVE_DATA_SCANNER.name,
            scanner_version=SENSITIVE_DATA_SCANNER.version,
            observed_at=observed_at,
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
    df: pd.DataFrame,
    scan_id: str | None = None,
    observed_at: str | datetime | None = None,
) -> list[NormalizedFinding]:
    # observed_at is the scan's collection time (passed in by the scan
    # wrapper). Source findings have no asset "modification time" to confuse
    # it with; this makes scan time explicit rather than leaving it unset.
    return [
        NormalizedFinding(
            scan_id=scan_id,
            source_type="code_analysis",
            asset_type="source_code",
            location=row["Location"],
            scanner_name=CODE_ANALYSIS_SCANNER.name,
            scanner_version=CODE_ANALYSIS_SCANNER.version,
            observed_at=observed_at,
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
            scanner_name=row.get("Scanner", CRYPTO_INVENTORY_SCANNER.name),
            scanner_version=row.get("Scanner Version", CRYPTO_INVENTORY_SCANNER.version),
            observed_at=row.get("Observed At"),
            evidence=row.get("Evidence", ""),
            confidence=row.get("Confidence", "Low"),
            # Unset for most crypto-inventory asset types (parsed certs/keys
            # have no named detection rule); the OpenSSL Salted__ finding
            # (HG-030) is the one asset type that sets it, via "Rule ID".
            rule_id=row.get("Rule ID"),
            errors=_errors(row.get("Errors")),
            # location alone doesn't distinguish two certificates/keys parsed
            # from the same PKCS#12 or PEM file -- both share source_type,
            # asset_type, location, and scanner_name.
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
