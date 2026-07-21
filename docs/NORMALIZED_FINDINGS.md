# Normalized Finding Schema

HarvestGuard's normalized finding schema is the internal evidence contract
between scanner adapters and later workflow layers. It is versioned for current
repository use, but it is not a long-term public API guarantee.

Current schema version: `1.0.0`

## Purpose

Scanners observe evidence. They do not decide business impact, remediation
cost, owner, executive priority, or quantum risk. Those assessment concepts
belong to later layers and must not be mixed into normalized findings.

## Required Fields

- `finding_id`: deterministic SHA-256 identifier for the normalized finding.
- `source_type`: scanner source family, such as `local_filesystem`, `aws_s3`,
  `gcs`, `azure_blob`, `local_sensitive_data`, `code_analysis`, or
  `crypto_inventory`.
- `asset_type`: type of asset observed by the scanner, such as `file`,
  `object`, `blob`, `source_code`, or a crypto asset type.
- `location`: local path, cloud URI, URL, or source location.
- `asset_name`: derived asset name when available.
- `scanner_name`: scanner or adapter that produced the finding.
- `scanner_version`: scanner contract version.
- `observed_at`: ISO-8601 timestamp for the observation.
- `evidence`: concise statement of the observed evidence.
- `confidence`: scanner confidence in the observation.
- `errors`: list of parsing or partial-finding errors.
- `technical_metadata`: scanner-specific observed values.
- `schema_version`: normalized schema version.

## Optional Fields

- `scan_id`: caller-supplied scan identifier. HG-003 does not add persistence,
  so this is optional until a later scan history layer exists.

## Technical Metadata

Scanner-specific values that do not belong in common fields are preserved in
`technical_metadata`.

Examples:

- Filesystem scanner: size, modified time, owner, and encryption status.
- Cloud scanners: size, modified time, and provider encryption metadata.
- Sensitive-data classifier: category names and total match count. Matched
  sensitive values are not stored.
- Semgrep code analysis: rule id and message.
- Crypto inventory: algorithm, key size, signature algorithm, expiration,
  issuer, subject, and fingerprint.

Legacy DataFrame columns that represent assessment, such as `Risk`, are not
copied into normalized findings. Existing scanner DataFrame behavior is
preserved for compatibility, but the normalized model remains evidence-only.

## Serialization

`NormalizedFinding.to_dict()` returns a JSON-compatible dictionary. Datetimes
are serialized as ISO-8601 strings, pandas timestamps are normalized, and
missing/NaN values become `null`.

## Versioning

The model uses `schema_version = "1.0.0"`. Future changes should increment the
schema version when they change field meaning or required structure.
