# Detection Characterization

This document characterizes what each HarvestGuard scanner actually detects
today, what it can miss, how to read its `confidence`, and when an absence of
findings must not be read as proof that no cryptographic asset, sensitive
data, weak crypto usage, or encryption gap exists (roadmap item HG-009). It
complements, and does not duplicate:

- [ASSET_INVENTORY.md](ASSET_INVENTORY.md) and
  [NORMALIZED_FINDINGS.md](NORMALIZED_FINDINGS.md), which define the evidence
  schema (`evidence`, `confidence`, `confidence_rationale`, `unknowns`,
  `limitations`, `errors`, `technical_metadata`) these characterizations are
  expressed through;
- [SCAN_COVERAGE.md](SCAN_COVERAGE.md), which defines *coverage* — whether the
  configured scope was processed;
- [TERMINOLOGY.md](TERMINOLOGY.md), which defines *confidence*, *false
  positive*, and *false negative* in general terms.

**Coverage and detection scope are different questions.** Coverage asks "was
the configured target processed?" Detection scope asks "of what was
processed, what can this scanner actually recognize?" A scan can have
complete coverage — every configured file, object, or blob was inspected —
and still miss real conditions, because every scanner below has a
deliberately narrow, non-exhaustive detector set. **Absence of a finding is
never proof that the underlying condition is absent**; it may mean the
scanner inspected the asset and found nothing it recognizes, or that the
asset's format, size, or content fell outside what the scanner looks for at
all.

This document is characterization of current behavior for evidence
interpretation. It is explicitly not a plan to expand detection surface: see
[ROADMAP.md](ROADMAP.md) for future scan surfaces (network/TLS, deeper
binary, broader keystore/container coverage), which are out of scope here.

## Confidence, in general

Every finding's `confidence` describes how directly and reliably *this
specific observation* was made — never business severity, exposure, or the
security effectiveness of what was observed. A `High`-confidence finding that
a file is unencrypted is a reliable observation that the file is unencrypted;
it says nothing about how much that matters. See
[TERMINOLOGY.md](TERMINOLOGY.md#evidence-layer-terms) for the full
definition.

Two scanners below assign a single fixed confidence to every finding they
produce (S3/GCS/Azure Blob: always `High`; the sensitive-data classifier:
always `Medium`) because their detection method itself does not vary in
reliability from one finding to the next — a provider-reported metadata field
is either present or absent, and a regex match is either found or not.
Filesystem and crypto-inventory findings carry per-observation confidence,
because those scanners use several detection methods of differing
reliability (a direct byte-signature match versus a volume-level fallback; a
successfully parsed certificate versus a magic-header-only match).

---

## Local filesystem encryption evidence

**Scanner:** `filesystem` (`scanner/filesystem.py`, `scan_filesystem_evidence`)
**Source type:** `local_filesystem`

### What it supports

Each regular file's leading bytes are checked against a fixed table of known
encrypted-format signatures (OpenSSL `Salted__`, PGP/GPG armor and binary
packet headers, `age`, LUKS containers, and the encrypted-ZIP general-purpose
bit flag). If no signature matches, the file inherits the encryption status
of the volume it lives on (FileVault on macOS, LUKS on Linux via `lsblk`,
BitLocker on Windows via `manage-bde`), computed once per scan root.
Symlinks, FIFOs, sockets, and device files are never followed or opened (see
[SCAN_COVERAGE.md](SCAN_COVERAGE.md)) and produce a `skipped_special_file`
finding instead of file-content evidence.

### Confidence semantics

- `High` — a file-level signature matched. The observation is a direct read
  of file content, independent of the volume.
- `Medium` — no file-level signature matched and the volume-level status is a
  known value (encrypted or not). The file itself was not independently
  verified; it inherits the volume's status.
- `Low` — either the file's header could not be read (permission denied, the
  file vanished mid-scan) and volume status was used as a fallback with no
  file-level verification at all, or neither file-level nor volume-level
  status could be determined.

`confidence_rationale` on every filesystem finding states which of these
applied. Host-dependent confidence is expected: the same file scanned on a
FileVault-enabled Mac versus an unrelated Linux host can legitimately produce
`Medium` in one case and `Low` in the other, because volume-level detection
depends on the host's own platform and tooling, not on the file itself.

### What this scanner can miss

- **Encrypted formats with no recognized signature.** The signature table is
  fixed and small. A proprietary or unlisted encrypted container, or an
  encrypted file with a non-standard header, is invisible to file-level
  detection and falls through to the (possibly `Unknown`) volume status.
- **Volume tooling unavailable or unsupported.** `_detect_volume_encryption`
  returns `"Unknown"` — never a guess of "unencrypted" — when the platform
  isn't Darwin/Linux/Windows, when `lsblk`/`manage-bde` aren't on `PATH`, or
  when the underlying command fails or times out. A `False`-shaped absence
  (no encrypted-format detected) on a host with `Unknown` volume status must
  not be read as "unencrypted."
- **False positive (documented, narrow, residual):** the OpenPGP `MESSAGE`
  armor header (`-----BEGIN PGP MESSAGE-----`) is also used by `gpg --armor
  --sign` output that is compressed and/or signed but *not* encrypted. This
  scanner cannot distinguish that case from a genuinely encrypted PGP message
  without parsing the packet body, so a small residual false-positive rate
  remains for `MESSAGE`-armored files specifically. Other PGP armor types —
  `SIGNED MESSAGE` (clearsign, plaintext body), `SIGNATURE` (detached
  signature only), `PUBLIC KEY BLOCK`, and `PRIVATE KEY BLOCK` — are *not*
  matched as encrypted data (see "Behavioral correction" below); a
  `PRIVATE KEY BLOCK` that is itself unprotected is correctly not reported as
  file-level encrypted, but is exactly the kind of asset
  [crypto_inventory](#local-cryptographic-asset-inventory) exists to flag —
  run both scanners for full local coverage.
- **False negative:** an encrypted file whose header happens to match none of
  the known signatures, or a proprietary encryption scheme, produces no
  file-level finding and falls back to volume status.
- **Ownership signals are metadata only.** `owner_name`/`group_name`
  resolution depends on the host's local passwd/group databases; a UID/GID
  with no local entry (common for files copied from another system, or in a
  container) resolves to `None` and is recorded as a `limitations` entry, not
  guessed.
- **Scope boundaries are reported, not silently applied.** `max_depth`
  boundaries and inaccessible directories produce explicit
  `max_depth_boundary` / `directory_traversal_error` findings rather than
  disappearing from the result; see [SCAN_COVERAGE.md](SCAN_COVERAGE.md) for
  the full semantics. **Default local scans use `--max-depth 3`**, so a
  normal `harvestguard scan <path>` run is bounded to that configured depth
  by default, not unbounded, unless `--max-depth` is changed.

### Behavioral correction: PGP armor prefix narrowed

Before this characterization, the file-signature table matched any header
starting with `-----BEGIN PGP`, which includes `MESSAGE`, `SIGNED MESSAGE`,
`SIGNATURE`, `PUBLIC KEY BLOCK`, and `PRIVATE KEY BLOCK` armor. Constructing
synthetic samples of each showed all five were classified identically as
`File-level (PGP/GPG)` with `High` confidence — including a clearsigned file
whose body is plaintext, and a public key block, neither of which is
encrypted data. That directly contradicted the confidence contract ("a
`High`-confidence observation is reliable"): reporting a readable plaintext
file as high-confidence encrypted evidence is a material misclassification,
not a defensible heuristic.

The signature was narrowed to match only `-----BEGIN PGP MESSAGE`, the armor
type OpenPGP uses for actual message content (encrypted, or — per the
residual ambiguity noted above — signed/compressed only). This is regression
tested in `tests/test_detection_characterization.py`. No other scanner
behavior changed.

---

## Local cryptographic asset inventory

**Scanner:** `crypto_inventory` (`scanner/crypto_inventory.py`)
**Source type:** `crypto_inventory`

### What it supports

Parses X.509 certificates (PEM and DER), PEM/OpenSSH private and public keys,
and PKCS#12 containers without a password, extracting algorithm, key size,
signature algorithm, expiration, issuer, subject, and a SHA-256 fingerprint
where parsing succeeds. Encrypted PEM private keys are identified (via the
`ENCRYPTED PRIVATE KEY` PEM label or a `Proc-Type: 4,ENCRYPTED` header) and
reported without decrypting them. See
[CRYPTO_INVENTORY.md](CRYPTO_INVENTORY.md) for the full supported-asset-type
list and usage.

### Confidence semantics

`confidence` varies per parse outcome, not per file:

- `High` — a certificate or key was fully parsed and its cryptographic
  properties extracted, or an encrypted PEM/OpenSSH private key block was
  positively identified by its header (algorithm/key-size may still be
  unavailable without a passphrase).
- `Medium` — a JKS magic header matched, or an OpenSSH private key's block
  was found but could not be loaded (an inconsistency with the PEM path,
  where an encrypted PEM key is `High`; both are documented, unvalidated
  differences in this MVP scanner, not a claim that Medium is more or less
  reliable in a measured sense).
- `Low` — a candidate block was found (PEM certificate, DER file extension,
  PKCS#12 extension, SSH public-key prefix) but parsing failed, reported as a
  `Malformed ...` asset type with the parser's error message in `errors`.

### What this scanner can miss

- **The candidate-file gate is a silent pre-filter.** Before any parsing is
  attempted, `_could_contain_crypto_asset` requires a file to either have a
  recognized extension (`.cer`, `.crt`, `.der`, `.jks`, `.p12`, `.pfx`), start
  with an SSH public-key prefix, match the JKS magic header, or contain the
  literal bytes `-----BEGIN ` somewhere in its first 5 MB. **A file that
  matches none of these produces no finding and no limitation record at
  all** — unlike the filesystem scanner, there is no explicit
  "not inspected" marker for gate-excluded files. An empty crypto-inventory
  result does not distinguish "no crypto assets present" from "assets present
  in a format or extension this gate does not recognize."
- **Password-protected PKCS#12 containers** are reported as
  `Malformed PKCS#12` (confidence `Low`) because the scanner does not attempt
  passphrases. This is a known, already-documented limitation (see
  [CRYPTO_INVENTORY.md](CRYPTO_INVENTORY.md#known-limitations)), not a
  distinct new finding — flagged here because the asset-type label
  (`Malformed`) can be misread as file corruption rather than "encrypted, and
  the scanner has no password to try."
- **JKS entries are not parsed.** Only the magic header is checked; no
  certificate or key inside a Java Keystore is extracted. This is stated
  directly in the finding's `errors` field, not left implicit.
- **Files above the 5 MB text-decode threshold** are not scanned for PEM/SSH
  content (binary-parse-extension and JKS-magic-header checks still apply
  regardless of size).
- **Symlinks are not followed by default**; `--follow-symlinks` changes that
  for a specific, intentional target.
- **False negative:** any crypto asset in an unrecognized container format,
  a renamed/unusual extension, or below the candidate gate's detection
  threshold is invisible to this scanner. Run alongside
  [filesystem](#local-filesystem-encryption-evidence) and
  [sensitive-data](#sensitive-data-classifier) scans for complementary
  evidence, not as a substitute for either.

---

## Sensitive-data classifier

**Scanner:** `sensitive_data_classifier` (`classifier/scanner.py`)
**Source type:** `local_sensitive_data`

### What it supports

Regex-based category matching against file text content (SSNs, credit card
numbers validated with a Luhn check, and similar PII/secret-shaped patterns
defined in `classifier/patterns.py`). Findings report **category names and a
total match count only**; matched values are read into memory transiently to
run the match and are never included in a finding, `technical_metadata`, a
report, or any persisted output.

### Confidence semantics

Every sensitive-data finding carries a fixed `confidence` of `Medium`. This
is deliberate, not an oversight: pattern-based classification over free text
always carries a nonzero false-positive and false-negative rate that does not
meaningfully vary from one match to the next the way filesystem or
crypto-inventory confidence does, so the scanner does not claim a precision
it cannot support.

### What this scanner can miss

- **Files above 2 MB are skipped entirely**, not partially read. A 2.1 MB
  file with sensitive data on line 1 produces no finding.
- **Binary files are skipped** via a crude null-byte heuristic on the first
  read chunk. A file with sensitive data embedded in a binary format (a
  database file, a compressed archive) is invisible to this scanner.
- **Undecodable text is skipped.** Content that fails both UTF-8 and
  Latin-1 decoding is treated as unreadable and produces no finding.
- **A file with zero matches produces no finding at all** — there is no
  explicit "inspected, nothing found" record, and no `technical_metadata`
  distinguishing "inspected and clean" from "skipped because binary/oversize/
  undecodable/inaccessible." An empty sensitive-data result for a target
  therefore does not by itself prove no sensitive data is present in it.
- **False positive:** the regex patterns match shape, not verified identity —
  a credit-card-shaped number that passes the Luhn check but belongs to no
  real account, or an SSN-shaped string in test/fixture data, is indistinguishable
  from a genuine instance.
- **False negative:** any sensitive-data format not covered by
  `CATEGORY_PATTERNS` (a category the classifier has no pattern for, or
  sensitive data that doesn't match the expected shape — reformatted,
  obfuscated, or embedded in structured data the regex doesn't anticipate) is
  not detected.
- **max_depth applies** the same way it does to the filesystem scanner, but
  this scanner does not emit `max_depth_boundary` findings for the
  directories it does not descend into — the boundary is recorded only as a
  configured scope constraint in the report, not per-directory (see
  [SCAN_COVERAGE.md](SCAN_COVERAGE.md)).

---

## Source-code crypto analysis

**Scanner:** `semgrep_crypto_rules` (`code_analysis/scanner.py`)
**Source type:** `code_analysis`

### What it supports

**This is source-code rule matching only, not binary analysis.** A vendored
Semgrep rule set (`code_analysis/rules/crypto.yaml`) runs against source text
to flag known weak/legacy cryptographic API usage (e.g. MD5 hashing, DES/ECB
cipher construction, undersized RSA key generation) with a line-level
location and the matched rule.

**Every rule in the current set declares `languages: [python]`**, so only
Python source is matched. Verified directly: a directory containing
`hashlib.md5` in a `.py` file, `crypto.createHash("md5")` in a `.js` file, and
`MessageDigest.getInstance("MD5")` in a `.java` file produces exactly one
finding — the Python one. A polyglot or non-Python repository can therefore
return an empty code-analysis result while containing the same weak-crypto
usage the rules describe.

### Confidence semantics

Every code-analysis finding carries a fixed `confidence` of `High`. A Semgrep
AST rule match on source code is a direct, deterministic observation of what
the code contains — there is no volume-fallback or partial-read style
uncertainty analogous to the filesystem scanner's confidence tiers. `High`
here describes certainty that the pattern matched, not a judgment that the
matched usage is necessarily exploitable in context.

### What this scanner can miss

- **Not binary analysis.** Compiled binaries, bytecode, and any crypto usage
  that does not appear as matchable source text (dynamically constructed API
  calls, crypto invoked through reflection or a wrapper the rules don't
  recognize) are entirely outside this scanner's reach.
- **Rule-set coverage is intentionally narrow.** Only the specific
  library/API patterns in `crypto.yaml` are matched. A weak-crypto call using
  a library or idiom not covered by an existing rule produces no finding.
- **Non-Python source is not matched at all.** See "What it supports" above:
  the rules are Python-only, so a Go, Java, JavaScript, C, or C# codebase
  yields no code-analysis findings regardless of what crypto it uses. Broader
  language coverage is future scan-surface work (see
  [ROADMAP.md](ROADMAP.md)), not a current capability.
- **Modern/strong crypto usage produces no finding**, by design — this is a
  targeted weak-usage scanner, not a full inventory of all cryptographic
  calls in the source tree.
- **Absence-of-finding semantics.** An empty result for a scanned repository
  means "no matched weak-usage pattern was found," not "this code contains no
  cryptography" or "this code is safe." See `code-analysis failure/absence
  semantics` below for the distinct case of the scanner not having run at
  all.
- **Scanner failure vs. clean scan.** If `semgrep` is not installed, times
  out, exits non-zero, or its output cannot be parsed as JSON, the scanner
  returns an empty result with no findings — indistinguishable, from the
  finding data alone, from "the code was scanned and nothing matched,"
  *unless* the caller checks `scanner_errors`/exit code. `harvestguard.py`
  raises no exception for this path today (`scan_source_for_crypto_usage`
  returns an empty DataFrame rather than raising), so a code-analysis
  environment failure currently does not appear as a nonzero-exit scanner
  error the way a cloud provider failure does. This is a known asymmetry
  with the cloud scanners' error-propagation behavior; documented here as a
  detection-characterization limitation rather than changed, since fixing it
  is a scanner-error-propagation change beyond this issue's narrow-correction
  scope.

### Behavioral correction: failure diagnostics moved to stderr

`docs/CLI.md` documents that `--json` stdout stays valid, machine-readable
JSON even when a scanner fails partway through, and that progress/failure
messages never mix into stdout. Before this fix, `scan_source_for_crypto_usage`
printed its "semgrep not installed" / timeout / non-zero-exit / JSON-decode
diagnostics with a bare `print(..., flush=True)`, which defaults to stdout.

Reproduced directly: running a scan with `--type code --json -` while
`semgrep` is unavailable produced literal stdout content of
`"Error running code analysis: semgrep is not installed\n[]\n"` — not valid
JSON, and at exit code `0`. Every diagnostic `print` in this function was
changed to `file=sys.stderr`, keeping the same message text and
`flush=True`. Confirmed the same scenario now emits exactly `[]\n` on stdout,
with the diagnostic on stderr, and this is regression tested in
`tests/test_detection_characterization.py`. No other code-analysis behavior
changed.

---

## AWS S3

**Scanner:** `s3` (`scanner/cloud.py`)
**Source type:** `aws_s3`

### What it supports

Per-object `ServerSideEncryption` metadata reported by `head_object`, via
`boto3`'s own default credential chain (HarvestGuard never prompts for or
stores AWS credentials). `list_objects_v2` is fully paginated.

### Confidence semantics

Every S3 finding carries a fixed `confidence` of `High`: this is a direct
read of the provider's own API response, not an inference. `High` confidence
describes the reliability of the observation that the API reported this
value — it does not certify that server-side encryption is effective against
every threat model (for example, it says nothing about IAM-principal-level
access to the underlying key).

### What this scanner can miss

- **Provider metadata is the entire evidence source.** If the bucket's or
  object's actual protection differs from what the API reports (a
  misconfigured bucket policy, a KMS key an attacker can also reach), this
  scanner cannot detect that — it is scoped to what `head_object` returns.
- **Per-object `head_object` failures** (e.g. `AccessDenied` on a single key)
  are recorded as a scan-level error rather than a per-object finding — the
  object's encryption status is simply unknown for that key, which is a
  coverage gap, not a "not encrypted" result. See
  [SCAN_COVERAGE.md](SCAN_COVERAGE.md).
- **A truncated `list_objects_v2` response with no continuation token** ends
  the scan as a reported failure, not a silently-complete result.
- **`--prefix` narrows what is even listed**; objects outside the prefix
  produce no findings and no boundary marker (recorded only in the report's
  *Scope* section, as with the sensitive-data classifier's `max_depth`).
- **False negative:** no false-positive risk in the traditional sense (the
  API value is reported as-is), but any encryption applied outside what
  `ServerSideEncryption` metadata reports (client-side encryption before
  upload, for example) is invisible to this scanner.

---

## Google Cloud Storage (GCS)

**Scanner:** `gcs` (`scanner/gcs.py`)
**Source type:** `gcs`

### What it supports

Per-blob CMEK (customer-managed encryption key) vs. Google-managed encryption
metadata, via the SDK's lazy `list_blobs` paging iterator and its own default
credential chain.

### Confidence semantics

Fixed `High`, for the same reason as S3: a direct provider API read, not an
inference. GCS encrypts every object at rest by default, so unlike S3 there
is no "unencrypted" state to observe — the meaningful signal is CMEK versus
the platform default, and `High` confidence describes certainty about which
of those two the API reported, not a claim about which is more secure in a
given threat model.

### What this scanner can miss

- **Same provider-metadata boundary as S3**: what the API reports is the
  entire evidence source.
- **Auth failures surface at `storage.Client()` construction**, before any
  listing happens (`DefaultCredentialsError` from `google.auth`, distinct
  from `GoogleAPIError` from later API calls) — both are recorded as scan
  failures, not silently swallowed.
- **A failure partway through iteration** (a later page, expired
  credentials) preserves blobs already observed and reports the failure
  rather than discarding prior evidence, per
  [SCAN_COVERAGE.md](SCAN_COVERAGE.md).
- **`--prefix` narrows scope** the same way it does for S3, with no
  per-blob boundary marker for excluded blobs.

---

## Azure Blob Storage

**Scanner:** `azure_blob` (`scanner/azure_blob.py`)
**Source type:** `azure_blob`

### What it supports

Per-blob customer-managed encryption scope vs. Microsoft-managed default, via
the SDK's lazy `ItemPaged` iterator and `DefaultAzureCredential`.

### Confidence semantics

Fixed `High`, for the same reason as S3 and GCS: a direct provider API read.
Azure Storage Service Encryption is mandatory and always on, so — like GCS —
there is no "unencrypted" state; the signal is customer-managed encryption
scope versus the Microsoft-managed default.

### What this scanner can miss

- **Same provider-metadata boundary as S3 and GCS.**
- **Auth and listing failures both raise `AzureError`** and are recorded as a
  scan failure with prior blobs preserved, matching the GCS/S3 partial-scan
  pattern.
- **`--prefix` (as `name_starts_with`) narrows scope** the same way it does
  for the other cloud scanners, with no per-blob boundary marker for excluded
  blobs.

---

## Coverage and errors interacting with detection limits

Two HG-008 findings bear directly on how to read the characterizations above
alongside a report:

- **A finding-level `errors` entry can coexist with `Coverage: No limits
  recorded`.** Coverage describes whether the *configured traversal/scope*
  was processed — it can legitimately be "no limits recorded" while
  individual findings still carry `errors` (an unparsable PEM block, a JKS
  entry the scanner cannot read, an encrypted key needing a passphrase).
  `"No limits recorded"` means the scan was not bounded by scope or stopped
  by a scanner-level failure; it does not mean zero per-asset errors were
  recorded. Read the report's *Errors and Warnings* section and each
  finding's `errors` array, not the `Coverage` row alone, before treating a
  scan as clean.
- **Default local `--max-depth 3`** means an ordinary `harvestguard scan
  <path>` invocation, with no explicit `--max-depth`, is bounded by that
  configured scope from the start — "I ran a scan" does not by itself mean
  "every file under the target was inspected," independent of any detection
  limit described above.
- **The installed CLI and the repository-root Streamlit dashboard are
  distinct operating paths.** The dashboard's `scan_filesystem` /
  `scan_filesystem_for_sensitive_data` calls share the same underlying
  detection logic characterized above (they call the same signature table
  and classifier), but the dashboard path does not produce the
  `NormalizedFinding` provenance fields (`confidence_rationale`, `unknowns`,
  `limitations`, `errors`) that the CLI's evidence path does. Detection
  limits are identical between the two; evidence detail available to read
  them by is not.

## Consistency with the evidence/inference boundary

Nothing in this document introduces or validates a risk score, an HNDL
exposure judgment, remediation guidance, or an executive-priority
conclusion. Confidence, false positives, false negatives, and detection
scope describe the reliability and boundaries of *observed evidence*; they
are evidence-layer concepts, not assessment-layer ones, per
[TERMINOLOGY.md](TERMINOLOGY.md) and
[ADR-005: Evidence versus inference](DECISIONS/ADR-005-evidence-versus-inference.md).
