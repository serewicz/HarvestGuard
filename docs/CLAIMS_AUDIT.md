# Claims Audit

This is HarvestGuard's canonical claims-inventory record (roadmap item
HG-010): the product, CLI, report, dashboard, architecture, and
documentation claims that were reviewed for this audit, how each is
classified, the evidence behind the classification, and the correction made
where one was needed. It consumes [HG-008](DETECTION_CHARACTERIZATION.md)'s
end-to-end validation and [HG-009](DETECTION_CHARACTERIZATION.md)'s
per-scanner detection characterization as audit inputs rather than
rediscovering them.

**Classifications used, exactly as defined by the issue this audit
satisfies:**

- **Implemented and tested** — the claim matches current behavior and is
  covered by tests.
- **Implemented with known limitations** — the claim is true but has
  documented boundaries a reader needs to know.
- **Experimental / Needs Validation** — heuristic or inferred, not yet
  validated as reliable.
- **Planned** — not implemented yet.
- **Explicitly out of scope** — deliberately not part of the product.

This document narrows or corrects claims to match reality. It does not add
product capability to make a claim true — where a claim was broader than
current behavior, the claim was narrowed, marked planned, or declared out of
scope instead.

## Product identity

| Claim | Classification | Evidence |
| --- | --- | --- |
| Cryptographic asset inventory tool | Implemented and tested | `scanner/crypto_inventory.py`, `scanner/filesystem.py`, cloud scanners; [ASSET_INVENTORY.md](ASSET_INVENTORY.md) |
| Evidence-collection tool for technology diligence | Implemented and tested | `NormalizedFinding` schema, evidence-only CLI reports (`reports.py`) |
| "Quantum risk scanner" (old README/dashboard/`pyproject.toml` framing) | Corrected | No quantum-readiness determination is implemented anywhere in the codebase — confirmed by grep across `harvestguard.py`, `reports.py`, `finding_adapters.py`, `findings.py`. Reworded to "cryptographic asset inventory and evidence-collection tool" in README, `main.py`'s dashboard tagline, and `pyproject.toml`'s package description. |
| Quantum-readiness determination | Explicitly out of scope | [PRODUCT_PRINCIPLES.md](PRODUCT_PRINCIPLES.md) already states HarvestGuard "should not... determine whether an organization is quantum-ready"; unchanged, already accurate |
| HNDL (Harvest Now, Decrypt Later) exposure framing | Experimental / Needs Validation | Heuristic High/Medium/Low bucket from `analyzer/risk.py`, dashboard-only (see "Evidence and inference boundary" below); [TERMINOLOGY.md](TERMINOLOGY.md) already marks it `Needs Validation` |

## Scanner coverage

| Claim | Classification | Evidence |
| --- | --- | --- |
| Local filesystem encryption evidence | Implemented with known limitations | Signature table + host-dependent volume fallback; see [DETECTION_CHARACTERIZATION.md](DETECTION_CHARACTERIZATION.md#local-filesystem-encryption-evidence) |
| AWS S3 encryption evidence | Implemented and tested | `scanner/cloud.py`; `tests/test_cloud.py` (14 tests) |
| GCS encryption evidence | Implemented and tested | `scanner/gcs.py`; `tests/test_gcs.py` (12 tests) |
| Azure Blob encryption evidence | Implemented and tested | `scanner/azure_blob.py`; `tests/test_azure_blob.py` (11 tests) |
| Sensitive-data classification | Implemented with known limitations | Regex/pattern-based, category/count only; 2 MB size cap, binary/undecodable content skipped silently; see [DETECTION_CHARACTERIZATION.md](DETECTION_CHARACTERIZATION.md#sensitive-data-classifier) |
| Source-code crypto analysis | Implemented with known limitations | Verified directly: a directory with equivalent weak-crypto usage in `.py`, `.js`, and `.java` files produces exactly one finding (the Python one) — every rule in `code_analysis/rules/crypto.yaml` declares `languages: [python]`. Source-text matching only, not binary/bytecode/runtime. |
| Crypto asset inventory (certs/keys/PKCS#12/JKS) | Implemented with known limitations | Candidate-file gate can silently produce zero findings for unrecognized formats; JKS is header-evidence only; see [DETECTION_CHARACTERIZATION.md](DETECTION_CHARACTERIZATION.md#local-cryptographic-asset-inventory) |
| Network/TLS discovery | Planned | Not implemented; listed under future scan surfaces in [ROADMAP.md](ROADMAP.md) |
| Binary/runtime crypto analysis | Planned | Not implemented; explicitly named as future in [ROADMAP.md](ROADMAP.md) and [DETECTION_CHARACTERIZATION.md](DETECTION_CHARACTERIZATION.md) |
| Broader keystore/container coverage (beyond JKS header, PKCS#12 without a password) | Planned | Named as a future scan surface in [ROADMAP.md](ROADMAP.md)'s Preserved Product Notes |

## Completeness and coverage language

| Claim | Classification | Evidence |
| --- | --- | --- |
| Default local scan depth | Implemented and tested | `DEFAULT_MAX_DEPTH = 3` in `harvestguard.py`; a scan with no explicit `--max-depth` is bounded configured scope, not unlimited recursion. README and `docs/CLI.md` now state this explicitly. |
| `Coverage: No limits recorded` | Implemented with known limitations | Means no traversal/scope limitation was recorded — it does not mean every asset was successfully inspected, and finding-level `errors` can still be present; carried forward from HG-008, already documented in `docs/CLI.md` |
| "Scan succeeded" / "no findings" | Implemented with known limitations | Absence of a finding is never proof of absence; this is the load-bearing caveat threaded through [SCAN_COVERAGE.md](SCAN_COVERAGE.md), [DETECTION_CHARACTERIZATION.md](DETECTION_CHARACTERIZATION.md), and now `reports.py`'s Known Limitations section |
| Dashboard empty-result messages ("No sensitive data patterns detected...", "No weak/legacy crypto library usage detected.") | Corrected | Prior wording (`st.success`) read as a positive, definitive absence claim. Changed to `st.info` + a `st.caption` distinguishing "no match in the inspected scope" from "condition absent," matching the detection boundaries above, without turning the dashboard into documentation prose (one line of caveat, not a re-statement of the full characterization doc) |
| "Comprehensive" / "complete" inventory or discovery | Explicitly out of scope (as a claim) | No such language exists in reviewed docs; confirmed by grep across README, CLI.md, ROADMAP.md, TERMINOLOGY.md, PRODUCT_PRINCIPLES.md, ARCHITECTURE.md, ASSET_INVENTORY.md, NORMALIZED_FINDINGS.md, SCAN_COVERAGE.md, DETECTION_CHARACTERIZATION.md, EXECUTIVE_DELIVERABLES.md — nothing to correct |

## Quantum / PQC positioning

| Claim | Classification | Evidence |
| --- | --- | --- |
| Quantum readiness / PQC migration readiness determination | Explicitly out of scope | [PRODUCT_PRINCIPLES.md](PRODUCT_PRINCIPLES.md), unchanged; already correctly excluded |
| HNDL exposure scoring | Experimental / Needs Validation | `analyzer/risk.py` heuristic; [TERMINOLOGY.md](TERMINOLOGY.md) already marks it `Needs Validation`; dashboard now labels the chart itself `HNDL Exposure (inferred — Needs Validation)` |
| Migration readiness / crypto-agility assessment | Planned | Roadmap items HG-025 (Milestone 5); not implemented |
| Exposure/risk scoring (0–100 Risk Score) | Experimental / Needs Validation | Same `analyzer/risk.py` heuristic; dashboard-only, never in CLI JSON/Markdown (confirmed by grep: no `risk`/`HNDL` reference exists in `harvestguard.py`, `reports.py`, `finding_adapters.py`, or `findings.py`) |

## Security / privacy

| Claim | Classification | Evidence |
| --- | --- | --- |
| Local-first, no default outbound network calls for local scans | Implemented and tested | `code_analysis/scanner.py` explicitly disables Semgrep's metrics/version-check network calls; documented in its own docstring and `SECURITY.md` |
| Credentials — HarvestGuard does not manage or provision cloud credentials | Implemented and tested | S3/GCS/Azure scanners all construct SDK clients with no HarvestGuard-supplied credential material (`boto3.client('s3')`, `storage.Client()`, `DefaultAzureCredential()`) — provider SDK default chains only |
| Sensitive-data raw values are never emitted | Implemented and tested | `classifier/scanner.py` returns category/count only; regression-tested in `tests/test_detection_characterization.py::test_sensitive_data_finding_never_carries_the_matched_value` |
| Reports can contain sensitive identifiers (paths, object/bucket names, ownership signals) | Implemented with known limitations | Already stated in README; unchanged, accurate |
| Container image signing/SBOM (keyless Sigstore/cosign + CycloneDX SBOM attestation) | Implemented with known limitations | `.github/workflows/container-build.yml` is configured to do this; the sign/attest mechanics were tested end-to-end against a local registry, but the keyless OIDC step can only be exercised for real inside GitHub Actions and had not yet produced a real published, verifiable image as of the commit that documents this (see [SECURITY.md](../SECURITY.md#verifying-the-container-image)). Release identity/provenance validation is HG-011's scope, not re-litigated here. |

## Assessment-layer claims

| Claim | Classification | Evidence |
| --- | --- | --- |
| Risk Score | Experimental / Needs Validation, dashboard-only | Never appears in CLI JSON/Markdown output; [TERMINOLOGY.md](TERMINOLOGY.md) |
| HNDL Exposure | Experimental / Needs Validation, dashboard-only | Same as above |
| Business impact conclusions | Explicitly out of scope | Not implemented anywhere; [PRODUCT_PRINCIPLES.md](PRODUCT_PRINCIPLES.md) |
| Remediation recommendations | Explicitly out of scope | Not implemented; `reports.py`'s Known Limitations section states this directly |
| Compliance conclusions | Explicitly out of scope | Not implemented |
| Executive Priority Index | Planned | Roadmap item HG-027 (Milestone 5); not implemented |
| `NormalizedFinding` fields | Implemented and tested | Evidence/provenance only — confirmed no risk/exposure/priority field exists in `findings.py`'s dataclass |

## Operating paths

| Claim | Classification | Evidence |
| --- | --- | --- |
| Installed `harvestguard` CLI is a distinct operating path from the Streamlit dashboard | Corrected (made explicit) | README previously implied a single unified product surface. Now states the dashboard runs via `streamlit run main.py` from the repository root and is deliberately not part of the installed `harvestguard` CLI package. |
| Detection logic is shared between the two paths | Implemented and tested | Both call the same `scanner.filesystem`, `classifier.scanner`, etc. functions |
| Evidence provenance is *not* shared between the two paths | Implemented with known limitations | The dashboard's `scan_filesystem`/`scan_filesystem_for_sensitive_data` calls do not produce `NormalizedFinding` provenance fields (`confidence_rationale`, `unknowns`, `limitations`, `errors`) the way the CLI's evidence path does; documented in [DETECTION_CHARACTERIZATION.md](DETECTION_CHARACTERIZATION.md#coverage-and-errors-interacting-with-detection-limits) |
| Dashboard local-scan depth | Implemented with known limitations (newly documented here) | `main.py` hardcodes `max_depth=2` for its local filesystem and sensitive-data scans, with no UI control to change it — distinct from the CLI's `--max-depth` default of `3`. No existing doc claimed a specific dashboard depth value, so this is recorded for completeness rather than as a correction to an overclaim. |

## Executive deliverables

| Claim | Classification | Evidence |
| --- | --- | --- |
| Technology Due Diligence Evidence Package | Planned (reporting target, not shipped output) | `reports.py`'s actual Markdown sections are Executive Summary, Scan Information, Scanner Versions, Findings Summary, Finding Breakdown by Type, Errors and Warnings, Known Limitations, and Appendix — none branded as the "Evidence Package." [EXECUTIVE_DELIVERABLES.md](EXECUTIVE_DELIVERABLES.md) now states plainly what exists today (console summary, `--json`, `--markdown`) versus what every named deliverable, including the Evidence Package itself, still is: a reporting target derived from that evidence. |
| Console summary / `--json` / `--markdown` evidence outputs | Implemented and tested | `reports.py`, `tests/test_reports.py` |
| HTML executive report | Planned | Roadmap item HG-017 (Milestone 3); not implemented |

## Correction made to the salvaged draft of this audit

**`reports.py`'s code-analysis execution-failure caveat was made
conditional.** An earlier draft of this audit's report change added an
unconditional Known Limitations bullet naming the code-analysis
stderr/empty-result asymmetry (see below). Three pre-existing tests
(`tests/test_reports.py::test_markdown_scope_lists_only_the_scanners_that_ran`
and two counterparts in `tests/test_cli.py`) already assert that a
single-scanner report must never mention a scanner it did not run — and an
unconditional bullet naming "code analysis" would itself have been exactly
the kind of misleading claim this audit exists to catch: a filesystem-only
or cloud-only report would have carried a caveat about a scanner it never
invoked. The bullet now appears only when `"code analysis"` is in the
report's `context.scanners`, matching how the *Scope* section already
conditions itself on which scanners actually ran. Regression-tested in
`tests/test_product_claims.py::test_code_analysis_asymmetry_caveat_only_appears_when_code_analysis_ran`.

## Identified for a separate issue

**Source-code analysis scanner-error propagation asymmetry.** When
`semgrep` is unavailable, times out, exits non-zero, or emits unparsable
output, `scan_source_for_crypto_usage` (`code_analysis/scanner.py`) returns
an empty result and writes its diagnostic to stderr. Unlike an equivalent
S3/GCS/Azure failure, this does not raise, does not populate
`scanner_errors`, and does not change the CLI exit code — so a code-analysis
execution failure is indistinguishable, from the JSON/Markdown artifact
alone, from a clean scan that found nothing. This is documented truthfully
in [DETECTION_CHARACTERIZATION.md](DETECTION_CHARACTERIZATION.md#source-code-crypto-analysis),
`docs/CLI.md`, `docs/ASSET_INVENTORY.md`, and `reports.py`'s Known
Limitations section, per this audit's explicit instruction not to change
scanner behavior to resolve it. If the asymmetry needs fixing, it should be
a narrowly scoped follow-up issue (propagate code-analysis execution
failures through the same `scanner_errors`/nonzero-exit path the cloud
scanners already use), not part of HG-010.

## Areas remaining `Needs Validation` for v0.1

- **Risk Score and HNDL Exposure** (`analyzer/risk.py`) — heuristic,
  dashboard-only, not validated against real-world outcomes.
- **Container image signing/SBOM attestation** — configured and locally
  tested end-to-end, but not yet exercised against a real published image;
  see [SECURITY.md](../SECURITY.md#verifying-the-container-image).
- **HG-010 itself** — this audit's roadmap status remains `Needs Validation`
  until an independent closure review confirms it after merge, consistent
  with how HG-009 was held at `Needs Validation` until its own closure
  review completed.

## Scope boundary

Consistent with [PRODUCT_PRINCIPLES.md](PRODUCT_PRINCIPLES.md) and
[ADR-006: Product boundary](DECISIONS/ADR-006-product-boundary.md), this
audit corrected wording only. No scanner, risk, remediation, dashboard,
storage, or release capability was added to make a claim true; every
overstated claim in the tables above was narrowed, marked `Planned`, or
declared out of scope instead.
