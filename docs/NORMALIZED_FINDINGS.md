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
  Its input is deliberately narrow -- a small canonical identity, not "most of
  the object" -- so the id survives re-scanning the same unchanged asset even
  when volatile facts differ between runs:
  - **Included**: `schema_version`, `source_type`, `asset_type`, `location`
    (the stable asset identifier), `scanner_name`, `rule_id` (which detection
    path fired), and `evidence` (the canonical observed claim -- "what was
    found").
  - **Excluded**: `scan_id`, `scanner_version`, `observed_at` (collection
    timestamp), `collection_source` (collection environment), `confidence`
    and `confidence_rationale`, `ownership_signals`, `unknowns`,
    `limitations`, `errors`, and `technical_metadata` (size, mtime, mode, and
    other scanner-observed detail). A touched mtime, a `chmod`, scanning from
    a different machine, or a resolved-vs-unresolved owner name must not
    change a finding's identity.
  - See `NormalizedFinding._generate_id()` in `findings.py` for the exact
    payload.
- `source_type`: scanner source family, such as `local_filesystem`, `aws_s3`,
  `gcs`, `azure_blob`, `local_sensitive_data`, `code_analysis`, or
  `crypto_inventory`.
- `asset_type`: type of asset observed by the scanner, such as `file`,
  `object`, `blob`, `source_code`, `directory` (a coverage-limitation finding,
  see below), or a crypto asset type.
- `location`: local path, cloud URI, URL, or source location.
- `asset_name`: derived asset name when available.
- `scanner_name`: scanner or adapter that produced the finding.
- `scanner_version`: scanner contract version.
- `observed_at`: ISO-8601 timestamp for when the scanner collected this
  observation (collection time), not necessarily when the underlying fact
  originated. A file's own modification time is a property of the asset, not
  of the observation, and is preserved separately (e.g. `Modified` in
  `technical_metadata`).
- `evidence`: concise statement of the observed evidence.
- `confidence`: scanner confidence in the observation itself -- never
  severity, priority, business impact, or remediation urgency.
- `confidence_rationale`: what evidence quality produced that confidence
  level (optional; populated by the filesystem scanner as the reference
  implementation).
- `errors`: list of parsing or partial-finding errors.
- `technical_metadata`: scanner-specific observed values.
- `schema_version`: normalized schema version.

## Optional Fields

- `scan_id`: caller-supplied scan identifier. HG-003 does not add persistence,
  so this is optional until a later scan history layer exists.
- `collection_method`, `collection_source`, `rule_id`, `repeatable`,
  `verification_rationale`: provenance for how a specific observation was
  collected, so it can be independently verified. `rule_id` identifies which
  detection path produced the evidence (e.g. `file_signature:openssl`,
  `volume_status:unencrypted`). `repeatable` indicates whether re-running the
  same collection method against the same asset should reproduce the same
  observation. `collection_source` describes the **scanned target**, not the
  machine running the scan -- for the filesystem scanner this is the
  normalized absolute scan root path, not a hostname. It must never leak
  workstation identity, and the same target scanned from two different
  machines must be recognizable as the same source (and, since it's excluded
  from `finding_id`'s input, produce the same id).
  - `finding.provenance` (Python-level only, not a new field in `to_dict()`'s
    flat keys) is a small typed `Provenance` view over these same fields plus
    `scanner_name`/`scanner_version`/`observed_at`, for callers that want
    structured access. `to_dict()` additionally nests this as a `provenance`
    key alongside the existing flat keys -- additive, so new provenance
    fields can grow there without perturbing the flat keys existing callers
    depend on. The flat fields remain the source of truth; every scanner
    adapter keeps constructing `NormalizedFinding` with them exactly as
    before.
- `ownership_signals`: technical ownership signals the operating system
  exposes (uid, owner name, gid, group name, numeric mode, human-readable
  permissions, ACL presence). Never business ownership, department, data
  steward, or accountable executive -- those cannot be derived from
  filesystem metadata and belong in `unknowns` instead.
- `unknowns`: things HarvestGuard cannot establish at all, independent of any
  specific failure (e.g. "business ownership cannot be established from
  filesystem metadata"). Distinct from `limitations`.
- `limitations`: conditions that constrained a specific observation (e.g.
  permission denied, volume-level fallback used because file-level status
  could not be determined, ACL presence not portably determinable on this
  platform). A limitation must not cause a finding to silently disappear --
  the finding is still produced, with the limitation recorded.

These optional fields are currently populated richly only by the filesystem
scanner, which serves as the reference implementation of the model. Other
scanners default them to `None`/empty and can adopt them incrementally.

## Coverage Limitations

Incomplete scan coverage must never be silently indistinguishable from "no
findings." When the filesystem scanner cannot inspect part of a scan
(a directory it can't list, or one beyond the configured `max_depth`
boundary), it emits an explicit `NormalizedFinding` with `asset_type =
"directory"` rather than fabricating file-level findings for whatever might
be underneath -- there is no separate scan-summary framework for this, it is
the same Finding model used for everything else.

- `rule_id = "directory_traversal_error"`: `os.walk`'s `onerror` fired for
  this directory (e.g. permission denied). `limitations` preserves the
  exception type/message. Not repeatable (`repeatable = False`): the failure
  reflects current permission/filesystem state, not a deterministic
  detection.
- `rule_id = "max_depth_boundary"`: the directory exists and is readable, but
  sits beyond the configured `max_depth` and was intentionally not descended
  into. Repeatable (`repeatable = True`): re-running the same scan with the
  same `max_depth` deterministically produces the same boundary.

Both carry an `unknowns` entry stating that encryption status beneath that
directory cannot be established, and never claim anything about specific
files that were never visited.

## Technical Metadata

Scanner-specific values that do not belong in common fields are preserved in
`technical_metadata`.

Examples:

- Filesystem scanner: size, modified time (`Modified`), and observed
  encryption status. Ownership/permission data lives in `ownership_signals`,
  not here.
- Cloud scanners: size, modified time, and provider encryption metadata.
- Sensitive-data classifier: category names and total match count. Matched
  sensitive values are not stored.
- Semgrep code analysis: rule id and message.
- Crypto inventory: algorithm, key size, signature algorithm, expiration,
  issuer, subject, and fingerprint.

Legacy DataFrame columns that represent assessment, such as `Risk`, are not
copied into normalized findings. Existing scanner DataFrame behavior is
preserved for compatibility, but the normalized model remains evidence-only.

## Immutability

`NormalizedFinding` is a frozen dataclass, but `frozen=True` alone only stops
reassigning a field (`finding.confidence = "Low"` raises) -- it does nothing
to stop mutating a nested dict/list in place (`finding.technical_metadata["x"]
= "y"` would otherwise succeed silently). `technical_metadata`,
`ownership_signals`, `unknowns`, `limitations`, and `errors` are therefore
recursively frozen after construction: dicts become `types.MappingProxyType`,
lists/tuples become `tuple`, sets become `frozenset`, applied recursively
through any nesting. No new dependency -- all three are standard library.

## Serialization

`NormalizedFinding.to_dict()` returns a JSON-compatible dictionary, converting
the frozen structures above back into plain `dict`/`list`. Datetimes are
serialized as ISO-8601 strings, pandas timestamps are normalized, and
missing/NaN values become `null`.

## Versioning

The model uses `schema_version = "1.0.0"`. Future changes should increment the
schema version when they change field meaning or required structure.
