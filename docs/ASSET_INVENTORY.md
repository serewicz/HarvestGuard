# Cryptographic Asset Inventory

This document defines HarvestGuard's **cryptographic asset inventory** concept:
the evidence-only inventory of where cryptographic protection is *observed*,
*missing*, or *uncertain* across supported scan targets. It is the conceptual
layer named by roadmap item HG-001, and it is realized by the normalized
finding model documented in [NORMALIZED_FINDINGS.md](NORMALIZED_FINDINGS.md).

> This is the cross-scanner inventory concept. It is distinct from the local
> certificate-and-key scanner documented in
> [CRYPTO_INVENTORY.md](CRYPTO_INVENTORY.md), which is one contributing adapter
> among several (see the mapping table below).

## What the inventory is

Each supported scan adapter observes evidence about a single asset — a file, an
object, a blob, a source location, or a piece of cryptographic material — and
emits one inventory record per observation. Collected together, those records
are the cryptographic asset inventory for a scan.

The inventory answers, per asset and with attributed evidence: *what was
observed, where, which scanner produced it, when it was collected, and how
confident that scanner is in the observation.* It does not assign business
impact, exposure, remediation priority, or executive scoring — those are
assessment-layer concerns kept separate per
[ADR-005: Evidence versus inference](DECISIONS/ADR-005-evidence-versus-inference.md).

## Minimum inventory record

Every inventory record carries at least the following fields. Each maps
directly onto a field of `NormalizedFinding` (see
[NORMALIZED_FINDINGS.md](NORMALIZED_FINDINGS.md) for the full schema and
`findings.py` for the implementation), so the inventory concept and the
normalized schema stay in agreement rather than describing two different
shapes.

| Inventory field | Normalized finding field(s) | Meaning |
| --- | --- | --- |
| Source | `source_type` | Which scan-source family produced the record (e.g. `local_filesystem`, `aws_s3`, `gcs`, `azure_blob`, `code_analysis`). |
| Location | `location` | Local path, cloud URI, or source location of the asset. |
| Observed encryption evidence | `evidence` (plus provider/status detail in `technical_metadata`) | The concise, source-attributed statement of what was observed about cryptographic protection. |
| Scanner identity | `scanner_name`, `scanner_version` | Which scanner/adapter and contract version produced the record. |
| Scan time | `observed_at` | ISO-8601 timestamp for when the observation was collected (collection time, not the asset's own modification time). |
| Confidence | `confidence` (with optional `confidence_rationale`) | The scanner's confidence in the observation itself — never severity, exposure, or priority. |

The terms *observed evidence*, *confidence*, *unknown*, *coverage*, and
*partial scan* used here are defined in [TERMINOLOGY.md](TERMINOLOGY.md).

## Per-adapter mapping

The five scan surfaces named in HG-001 map to inventory records as follows.
The sensitive-data classifier and the local certificate/key inventory scanner
contribute additional evidence records to the same inventory and are included
for completeness. All mappings are implemented today in `finding_adapters.py`
without changing existing scanner behavior.

| Adapter (`scanner_name`) | `source_type` | Observed encryption evidence |
| --- | --- | --- |
| `filesystem` | `local_filesystem` | Per-file encrypted-format signature (OpenSSL, PGP/GPG, age, LUKS, encrypted ZIP), falling back to volume-level status (FileVault / LUKS / BitLocker). Encryption status is also kept in `technical_metadata["Encryption"]`. |
| `s3` | `aws_s3` | Object `ServerSideEncryption` metadata reported by the S3 API. |
| `gcs` | `gcs` | Per-blob CMEK vs. Google-managed encryption metadata. |
| `azure_blob` | `azure_blob` | Per-blob customer-managed encryption scope vs. Microsoft-managed default. |
| `semgrep_crypto_rules` | `code_analysis` | Weak/legacy crypto usage matched in source by a vendored Semgrep rule (`rule_id` records which check fired). |
| `sensitive_data_classifier` | `local_sensitive_data` | Sensitive-data category names and total match count only. Matched values are never stored (see below). |
| `crypto_inventory` | `crypto_inventory` | Local certificate/key material (algorithm, key size, issuer, subject, expiration, fingerprint). See [CRYPTO_INVENTORY.md](CRYPTO_INVENTORY.md). |

Cloud provider encryption metadata is captured as observed evidence in
`evidence` and preserved in `technical_metadata`, so the record states what the
provider reported rather than inferring a protection outcome.

## Uncertain and inaccessible observations stay visible

Incomplete coverage must never be silently indistinguishable from "no
findings," and an observation must never be quietly reclassified into a cleaner
answer than the evidence supports. The inventory represents uncertainty
explicitly rather than dropping it:

- **Inaccessible or un-descended scope** — when the filesystem scanner cannot
  inspect part of a target, it still emits an explicit inventory record (an
  `asset_type = "directory"` finding with `rule_id` of
  `directory_traversal_error` or `max_depth_boundary`) carrying `limitations`
  and `unknowns`, rather than fabricating file-level records or silently
  omitting the region. See "Coverage Limitations" in
  [NORMALIZED_FINDINGS.md](NORMALIZED_FINDINGS.md).
- **Constrained observations** — conditions that limited a specific
  observation (permission denied, volume-level fallback used because file-level
  status could not be determined, platform limits) are recorded in
  `limitations` on the record that is still produced.
- **Things that cannot be established at all** — e.g. business ownership from
  filesystem metadata — are recorded in `unknowns`, distinct from
  `limitations`.
- **Parsing and API errors** — partial or malformed assets and scanner/API
  failures are surfaced in `errors` rather than collapsing the record.
- **Confidence** — records whose evidence is indirect or incomplete carry a
  lower `confidence` (and, for the filesystem reference adapter, a
  `confidence_rationale`) rather than being presented as certain.

## Privacy

Inventory records never persist file contents or raw sensitive matched values.
The sensitive-data classifier contributes category names and counts only, by
design, so an inventory record cannot itself leak the sensitive data it
observed. Findings are held locally and are not sent to external services.

## Scope boundary

This inventory is evidence-only. It deliberately excludes exposure labels, risk
scores, HNDL buckets, remediation priority, executive scoring, and any
recommendation — see [ADR-006: Product boundary](DECISIONS/ADR-006-product-boundary.md)
and [PRODUCT_PRINCIPLES.md](PRODUCT_PRINCIPLES.md). Those inferences, where they
exist at all, live in a separate assessment layer that must stay traceable back
to these records.
