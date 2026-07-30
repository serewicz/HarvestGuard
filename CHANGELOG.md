# Changelog

Notable changes to HarvestGuard. Release identity, reproducibility
expectations, and the release procedure are documented in
[docs/RELEASE.md](docs/RELEASE.md).

HarvestGuard is pre-1.0: CLI flags, report sections, and documentation may
change between versions. The normalized finding schema is versioned separately
(`schema_version`, currently `1.0.0`).

## 0.1.0 — Controlled Diligence Pilot (candidate, not yet tagged)

v0.1.0 is prepared but **not tagged**: HG-010 (product claims and trust audit)
is still `Needs Validation` pending its closure review. See
[release readiness](docs/RELEASE.md#release-readiness-gate).

Release notes for controlled-pilot users.

### What v0.1 supports

- **Cryptographic asset inventory** — local certificate and key material
  (PEM/DER X.509, PEM and OpenSSH keys, PKCS#12, JKS header evidence only) with
  algorithm, key size, issuer, subject, expiration, fingerprint, confidence, and
  parsing errors.
- **Local filesystem encryption evidence** — per-file signature checks
  (OpenSSL, PGP/GPG, age, LUKS containers, encrypted ZIP) with a volume-level
  fallback (FileVault / LUKS / BitLocker).
- **Cloud object encryption status** — AWS S3, Google Cloud Storage, and Azure
  Blob Storage, as *reported by* each provider's API. Credentials come from each
  provider SDK's own default resolution; HarvestGuard never manages, prompts
  for, or stores them.
- **Sensitive-data classification** — email addresses, SSNs, phone numbers,
  Luhn-validated payment card numbers, and credentials/secrets, reported as
  category and count only, never the matched values.
- **Crypto code analysis** — weak/legacy crypto usage (MD5/SHA1, DES/3DES/RC4,
  ECB mode, sub-2048-bit RSA) via a small vendored Semgrep rule set, Python
  source text only.
- **Unified CLI** (`harvestguard scan`) with console summary, `--json`
  (a bare array of normalized findings), and `--markdown` evidence reports;
  bounded by `--max-depth` (default `3`), `--prefix`, and `--exclude`.
- **Version identity** — `harvestguard --version`, and a `HarvestGuard Version`
  row in every Markdown report's *Scan Information* table, so a shared evidence
  artifact names the release that produced it.
- **Streamlit dashboard** (`streamlit run main.py`) — a separate operating path
  from the installed CLI, and the only place the heuristic Risk Score and HNDL
  Exposure buckets appear.
- **Container image** — distroless, non-root, `--read-only`-compatible; runs the
  dashboard.

### Known limitations

- **Absence of a finding is not proof of absence.** Every scanner has a
  deliberately narrow detection surface; what each one can miss, its likely
  false positives and false negatives, and how to read its `confidence` value
  are documented per scanner in
  [docs/DETECTION_CHARACTERIZATION.md](docs/DETECTION_CHARACTERIZATION.md).
- Cloud results are **provider-reported metadata**, not independent proof of the
  underlying cryptographic implementation.
- Code analysis is **Python source text only** — no binary, bytecode, runtime,
  or network/TLS discovery. A code-analysis execution failure produces no
  findings and writes its diagnostic to stderr only, so from the artifact alone
  it is indistinguishable from a clean scan.
- Local scans are depth-bounded by default (`--max-depth 3`); a bounded or
  partial scan is reported in the artifact's *Coverage*, *Scope*, and
  *Errors and Warnings* sections rather than silently.
- Risk Score and HNDL Exposure are **heuristic inferences, not measured facts**,
  are labeled `Needs Validation`, and appear in the dashboard only — never in
  CLI JSON or Markdown output.
- Encrypted key containers may not expose algorithm or key-size metadata
  without a passphrase; JKS support is header evidence only.
- Reports carry no risk score, remediation advice, business impact, compliance
  conclusion, or quantum-readiness verdict, by product boundary
  ([docs/DECISIONS/ADR-006-product-boundary.md](docs/DECISIONS/ADR-006-product-boundary.md)).

### Privacy and security expectations

- HarvestGuard runs **locally**. Local filesystem, sensitive-data, and
  code-analysis scans make no outbound network calls; cloud scans reach only the
  provider API you point them at
  ([SECURITY.md](SECURITY.md#container-network-posture)).
- No telemetry, no update service, no hosted component, no evidence store:
  output goes to your terminal or to the file you name.
- **Generated reports can contain sensitive identifiers** — file paths, object
  and bucket names, ownership signals — so handle and share them accordingly.
  Sensitive-data findings themselves never include matched values.
- Scan only targets you are authorized to scan. Cloud scans need read-only
  access; least-privilege IAM templates are in [deploy/iam/](deploy/iam/).

### Deferred to a later release

CBOM (CycloneDX) and PDF export, network/TLS cipher discovery, an evidence
store, and the packaged Technology Due Diligence Evidence Package are not built;
see [docs/ROADMAP.md](docs/ROADMAP.md). Release-engineering gaps specifically —
dependency pinning, source SBOM, SLSA provenance, signed tags, published
packages — are listed in
[docs/RELEASE.md](docs/RELEASE.md#sbom-signing-and-provenance-status).
