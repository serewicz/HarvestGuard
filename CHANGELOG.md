# Changelog

Notable changes to HarvestGuard. Release identity, reproducibility
expectations, and the release procedure are documented in
[docs/RELEASE.md](docs/RELEASE.md).

HarvestGuard is pre-1.0: CLI flags, report sections, and documentation may
change between versions. The normalized finding schema is versioned separately
(`schema_version`, currently `1.0.0`).

## Unreleased

The `0.2.0` entry below is a **draft for a release that has not happened**. It
describes work already merged to `main`; it does not describe a published
version. Specifically, at the time of writing:

- the declared version is still `0.1.0` in both `pyproject.toml` and
  `harvestguard_version.py`, and `harvestguard --version` prints
  `harvestguard 0.1.0`;
- no `v0.2.0` tag has been created, and no GitHub Release has been published
  from any tag;
- no PyPI, wheel, or sdist publication has been made, and no version-tagged
  container image exists.

Drafting that entry closes open item B-3 of the
[v0.2 pre-1.0 release readiness audit](docs/RELEASE.md#v02-pre-10-release-readiness-audit).
The chosen release path, the disposition of every other open item, and the
maintainer actions still required are recorded in
[release and distribution decision](docs/RELEASE.md#release-and-distribution-decision-v02-preparation);
the draft GitHub Release notes are in
[docs/release-notes/v0.2.0-draft.md](docs/release-notes/v0.2.0-draft.md).

Nothing here bumps a version literal, creates a tag, or publishes anything;
each of those remains a separate, explicitly authorized maintainer action.

## 0.2.0 — Cryptographic Inventory and First Public Use (drafted, unreleased)

Covers the `v0.1.1 Stabilization` (HG-028…HG-032) and `v0.2` cryptographic
inventory (HG-033…HG-044) milestones in
[docs/ROADMAP.md](docs/ROADMAP.md), plus the first-public-use work from issues
#115 through #119. Every scanner addition below is **evidence only**: a
detection records what was structurally observed in a file, and establishes
nothing about runtime exposure, exploitability, remediation priority, business
risk, compliance, HNDL exposure, quantum readiness, or migration readiness.

### Added — cryptographic asset inventory

Bounded, format-specific detectors, each requiring structural evidence rather
than a filename extension or an entropy guess, and each characterized in
[docs/DETECTION_CHARACTERIZATION.md](docs/DETECTION_CHARACTERIZATION.md):

- **Encrypted-file and encrypted-container evidence** — OpenSSL `Salted__`
  files (HG-030), binary and ASCII-armored OpenPGP encrypted messages
  (HG-031), gocryptfs forward-mode cipher roots reported once per root without
  mounting or per-ciphertext-file findings (HG-032), and native age v1 files
  (HG-035).
- **Encrypted key and object structures** — encrypted PKCS#8 private keys
  (HG-038), CMS/PKCS#7 encrypted objects (HG-039), and legacy PEM encryption
  headers (HG-040).
- **Keystores and certificate stores** — BCFKS (HG-036) and JCEKS (HG-037)
  keystore evidence, Mozilla NSS database sets (HG-041), and Java
  trusted-certificate-only stores (HG-042).
- **Host and cluster identity material** — OpenSSH host identity through
  file-local private-key, public-key, and host-certificate findings, with no
  cross-file key/certificate pairing (HG-043), and Kubernetes TLS Secret
  manifests read from local JSON and YAML documents only, with no cluster,
  Kubernetes API, or kubeconfig access (HG-044).

### Changed

- **Shared crypto detector framework** (HG-033) — an explicit static detector
  registry with deterministic IDs and priorities, separate file and root
  detector concepts, scanner-owned traversal, cached shared scan context, and
  per-detector metadata allowlists. It adds no detection capability of its own.
- **Internal cryptographic relationship model** (HG-034) — immutable records
  for direct structural links between existing findings, with a fixed bounded
  vocabulary and High confidence only for direct structural proof. It is
  internal only: no relationship appears in the normalized finding schema,
  JSON output, or Markdown reports.
- **Filesystem finding and summary semantics** (HG-029) — ordinary files no
  longer produce repeated per-file filesystem context findings; shared
  filesystem context is represented once per mount or volume, and console and
  Markdown summaries separate material evidence, aggregate filesystem context,
  coverage limitations, skipped or inaccessible entries, finding-level errors,
  and scanner errors. Crypto scans additionally report *Crypto files
  inspected*.
- **Self-contained CLI installation** (HG-028) — `pip install .` and
  `pip install -e .` produce a usable `harvestguard` in a clean environment
  without a second dependency step; `pyproject.toml` is the authoritative
  runtime dependency declaration.

### Added — first public use experience (issues #115–#119)

- **Synthetic demo corpus** — [`demo/sample_target/`](demo/sample_target/README.md),
  four fake-pattern files with a per-file manifest of the finding each is
  expected to produce. It contains no real credentials.
- **Committed sample output** — [`docs/examples/first-run/`](docs/examples/first-run/README.md):
  JSON and Markdown artifacts from exactly that demo scan, their generating
  commands and version, and the normalization applied, so output can be read
  before installing anything.
- **README quickstart** — the canonical run/review/export sequence, including
  which demo results are host-dependent and why the demo's one expected
  finding-level error is not a failure.
- **Executive-readable evidence example** —
  [`docs/examples/executive-evidence-example.md`](docs/examples/executive-evidence-example.md),
  which keeps every executive-readable statement traceable back to a technical
  finding.
- **v0.2 pre-1.0 release readiness audit** — a go/no-go evidence record in
  [docs/RELEASE.md](docs/RELEASE.md#v02-pre-10-release-readiness-audit), and
  the release/distribution decision that followed it.
- **[SUPPORT.md](SUPPORT.md)** — where to ask, which version is supported, what
  to include in a bug report, and what support to expect.

### Known limitations

The v0.1 limitations below still apply in full, unchanged. In addition:

- **Broader format coverage is still not complete coverage.** Each detector
  above recognizes specific structures in specific formats; anything outside
  them is not detected, and absence of a finding remains not proof of absence.
  Per-detector misses, false positives, and false negatives are in
  [docs/DETECTION_CHARACTERIZATION.md](docs/DETECTION_CHARACTERIZATION.md).
- Keystore, NSS, and truststore findings are **structural evidence about the
  container**, not a decrypted enumeration of its contents; encrypted material
  may not expose algorithm or key-size metadata without a passphrase.
- Kubernetes TLS Secret evidence comes from **local manifest files only** — it
  says nothing about what a live cluster actually holds.
- OpenSSH findings are **file-local**: no key is paired with a certificate
  across files.
- Detection has been exercised against the repository's own fixtures and demo
  corpus. **Real-world validation depth remains outstanding work** (HG-045),
  and no claim in this entry depends on it.
- Still not built: CBOM (CycloneDX) and PDF export, network/TLS cipher
  discovery, and the packaged Technology Due Diligence Evidence Package. Risk
  Score and HNDL Exposure remain heuristic, `Needs Validation`, and
  dashboard-only.

### Release state

Drafting this entry published nothing. The declared version literal is
unchanged at `0.1.0`, no `v0.2.0` tag has been created, no GitHub Release
exists, HarvestGuard is not published to PyPI, and container images remain
tagged by commit SHA. Before this entry can describe an actual release, the
version literals must be bumped in step and the blocking items in
[docs/RELEASE.md](docs/RELEASE.md#open-items-for-the-v02-gono-go) resolved —
see [release and distribution decision](docs/RELEASE.md#release-and-distribution-decision-v02-preparation).

## 0.1.0 — Controlled Diligence Pilot (approved, tagged)

v0.1.0's implementation and closure review are complete: HG-008, HG-009,
HG-010, and HG-011 are all `Complete`, and Milestone 2 is fully delivered.
The annotated `v0.1.0` git tag exists. No GitHub Release has been published
for it. Whether to publish one from the existing tag is a separate,
deliberate maintainer decision — not a sign that any implementation work
remains open. See
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
