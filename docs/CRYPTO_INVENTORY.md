# Cryptographic Asset Inventory

HarvestGuard includes a local cryptographic asset inventory scanner for
evidence discovery. It does not assign executive priority, quantum scores, or
remediation priority.

Run it against a file or directory:

```bash
python -m scanner.crypto_inventory tests/fixtures/crypto_inventory
```

Example output shape:

```json
[
  {
    "Asset Type": "PEM Certificate",
    "Location": "tests/fixtures/crypto_inventory/rsa_cert.pem",
    "Algorithm": "RSA",
    "Key Size": 2048,
    "Signature Algorithm": "sha256",
    "Expiration": "2027-01-01T00:00:00+00:00",
    "Issuer": "CN=rsa.harvestguard.test,O=HarvestGuard Test Fixtures,C=US",
    "Subject": "CN=rsa.harvestguard.test,O=HarvestGuard Test Fixtures,C=US",
    "Fingerprint": "sha256-hex-value",
    "Evidence": "PEM Certificate parsed successfully",
    "Confidence": "High",
    "Errors": "",
    "Scanner": "crypto_inventory",
    "Scanner Version": "0.1.0"
  }
]
```

## Supported Asset Types

- X.509 certificates
- PEM certificates
- DER certificates
- PEM private keys
- Encrypted PEM private keys, detected without decrypting key material
- OpenSSH private keys
- OpenSSH public keys
- PKCS#12 containers (`.p12`, `.pfx`) when no password is required
- Java Keystore magic-header detection
- OpenSSL `Salted__` encrypted files (leading-byte signature only, not
  decrypted; checked before any extension-based branch above)
- OpenPGP/GPG encrypted files, binary or ASCII-armored, identified by the
  leading encrypted-session-key packet (structure only, not decrypted;
  checked before any extension-based branch above). Support is partial — see
  [what is and is not supported](DETECTION_CHARACTERIZATION.md#openpgpgpg-encrypted-files-hg-031)
- gocryptfs cipher roots (standard forward mode, config format version 2
  only), identified by a root-level `gocryptfs.conf` plus `gocryptfs.diriv`
  pair — one finding per validated root directory, not per ciphertext file,
  and never decrypted, mounted, or unlocked. Reverse mode and `PlaintextNames`
  mode are unsupported. See
  [what is and is not supported](DETECTION_CHARACTERIZATION.md#gocryptfs-encrypted-filesystem-hg-032)

## Detector Framework

Internally, every supported format above is a **detector**: a small declaration
in a static registry (`scanner/crypto_detectors.py` defines the framework,
`scanner/crypto_inventory.py` declares the registry as `CRYPTO_DETECTORS`).
This is an implementation structure introduced by HG-033, not a capability:
**HG-033 added no new detection capability.** Every format the scanner
recognizes today was recognized before the framework existed, with the same
asset types, rule IDs, evidence wording, confidence values, and metadata.

**Traversal is owned by the scanner, never by a detector.** The scanner walks
the requested file or directory, applies exclusions and symlink rules, counts
inspected files, and hands each discovered asset to the registry. Detectors
have no filesystem entry point of their own — a root detector receives a
candidate root reached through a marker file the scanner already found, plus a
fixed-name sibling check, and cannot list or recurse into a directory.

**Shared scan context.** Each file is read once per scan, and every detector
that inspects it shares that read through a context offering three views:
leading bytes (for exact-position signature checks), full bytes (for the
parsers that genuinely need the whole asset), and a bounded text view (the
5 MB decode limit described under [Known Limitations](#known-limitations)).
Adding a detector therefore does not add a read of the file.

**File and root detectors.** Most detectors are file-scope: one asset, one
file. gocryptfs is root-scope, because the evidence is a directory structure —
one finding per validated root, never one per ciphertext file.

**Deterministic order and terminal results.** Each detector declares a
priority, and the registry is ordered by priority alone — never by import
order, filesystem order, or an environment variable. Priorities must be unique:
two detectors sharing one priority would have their relative order decided by
the order they were listed in, so the registry rejects a duplicate priority
instead of tie-breaking it. A detector's result is
either "no match", "match, and other evidence may coexist", or "match, and
this detector owns the asset" (terminal). Terminality is per detector, not a
general "first match wins" rule: it is what keeps an OpenSSL- or
OpenPGP-encrypted file saved with a misleading `.p12` extension from also
being reported as a malformed PKCS#12, while still letting one PEM file report
a certificate, a private key, and an SSH public key together.

**Safe metadata allowlists.** Detector output is treated as untrusted until
allowlisted. Each detector declares which of the ten approved metadata keys
(`Algorithm`, `Key Size`, `Signature Algorithm`, `Expiration`, `Issuer`,
`Subject`, `Fingerprint`, `Format`, `Config Version`, `Mode`) it may populate;
anything else it sets is omitted centrally before the finding is emitted, and a
declaration outside that set is rejected when the registry is built. There is
no generic dictionary path from a parser into a finding's technical metadata,
so key material, passphrases, salts, KDF parameters, ciphertext, plaintext, raw
config files, and parser payloads have no channel into JSON or Markdown output.

**Accounting is unaffected by detector count.** `Crypto files inspected`
counts files the scan visited and opened — one unit per regular file,
regardless of how many detectors inspect it, how many views they take of it, or
how many findings (including malformed ones) they produce. Directories a root
detector classifies are not counted as files.

**Error isolation.** An expected non-match is a result, not an exception, and
produces no finding and no error. Malformed input a detector owns produces the
existing `Malformed ...` findings. An unreadable file produces nothing. A
traversal failure raises `LocalScanError` with the findings already collected.
An *unexpected* detector exception is not silently converted into a clean
non-match: it stops the crypto-inventory scan through the same scanner-error
path, preserving findings already collected — including the evidence earlier
detectors already produced for the same file the failing detector was inspecting
— and the error text names the detector ID and the asset path, never the
exception's own message, which could quote file content.

**Adding a future detector** means: write a candidate predicate and a detect
function against the shared context, declare a `FileDetector` or
`RootDetector` (identifier, priority, rule ID where applicable, confidence,
evidence wording, terminal behavior, metadata allowlist), and add it to
`CRYPTO_DETECTORS`. Traversal, accounting, ordering, metadata safety, and error
isolation are then inherited rather than reimplemented. A new metadata key also
requires extending `SAFE_METADATA_KEYS`, the `to_record()` output, and the
normalized-finding adapter — deliberately a visible, reviewable change.

## Internal Relationship Model (Internal Only, No Output)

`scanner/crypto_relationships.py` is an **internal** model for representing that
two *already discovered* cryptographic assets are structurally connected — for
example a certificate whose public key material matches a private key's, or a
parsed container that directly contains a certificate object.

**It adds no detection capability and produces no output.** Nothing in this
model appears in the CLI, in JSON, in a Markdown report, in the Streamlit
dashboard, in the legacy DataFrame, or in `NormalizedFinding`. There are no new
flags, no new columns, no new report sections, and no relationship counts in any
summary. Findings remain the only first-class public inventory records;
relationships are internal evidence artifacts that later issues may build on.

- **Endpoints are references.** A relationship names two endpoints by the stable
  `finding_id` of findings HarvestGuard already produced. Both endpoints must
  exist: a dangling relationship is rejected. Relationships never create a
  synthetic asset, never mutate a finding, and never change a finding ID. Source
  and target must differ — self-relationships are rejected because no current
  relationship type requires one.
- **The vocabulary is fixed.** Exactly five types: `contains`,
  `corresponds_to`, `references`, `member_of`, `issued_by`. Anything else is
  rejected, so vague or assessment-flavored relations (`related_to`,
  `depends_on`, `uses`, `protects`, `owned_by`, `belongs_to`, `impacts`,
  `at_risk_from`) cannot be expressed. Adding a type requires an explicit code
  and test change.
- **Direction is explicit.** `contains`, `references`, `member_of`, and
  `issued_by` are directional: reversing the endpoints is a different
  relationship with a different ID. `corresponds_to` is symmetric: endpoints are
  canonically ordered, so the two orderings of one observation collapse into a
  single record with a single ID.
- **Identity is deterministic.** `relationship_id` is derived from four stable
  fields only — relationship type, both stable finding IDs (canonicalized for
  symmetric types), and the relationship rule ID. Timestamps, scan IDs, host,
  process, traversal or detector order, file counts, confidence, evidence
  wording, provenance text, limitations, errors, and construction order are all
  excluded, so re-observing the same relationship yields the same ID and
  rewording evidence never churns identity.
- **Deduplication is exact-identity suppression.** The same relationship
  observed several times collapses to one canonical record; different types and
  different rule IDs stay distinct. Ordering is derived from the same stable
  fields, so a collection's order does not depend on the order it was built in.
  There is no evidence-history aggregation and no transitive deduplication.
- **Evidence only, no inference.** Every relationship requires evidence text
  describing what was directly, structurally observed. Construction-time guards
  reject assessment wording (validity, trust, ownership, business impact,
  security strength, compliance, remediation, HNDL, quantum readiness,
  severity, priority) and inference wording, because no relationship may be
  created from guesswork, naming similarity, proximity, extension, directory
  co-location, owner or group, host, chronology, algorithm compatibility alone,
  subject-name similarity, or an assumed application dependency. Confidence uses
  the same `High`/`Medium`/`Low` vocabulary findings use and describes confidence
  in the relationship *evidence* only; `High` requires direct structural proof.
- **Provenance is required and safe.** Each relationship records which internal
  component created it, which relationship rule created it, the scan context,
  whether the observation is repeatable, and when HarvestGuard collected the
  evidence — as short, safe values.
- **The privacy boundary is structural.** The model has no metadata dictionary
  and no free-form field, so there is nowhere to put private key material, raw
  certificate bodies, raw or encrypted key blobs, ciphertext, plaintext,
  passphrases, salts, KDF values, raw config, OpenPGP packet bodies, Kubernetes
  or application secrets, parser exception payloads, or arbitrary blobs. Every
  text field is length-bounded and must be printable, and a field carrying a
  PEM/OpenPGP armor header or the OpenSSL `Salted__` magic is rejected rather
  than scrubbed. Unexpected keyword arguments raise rather than being absorbed.
- **Validation outcomes are distinguishable.** Valid, duplicate, missing
  endpoint, invalid type, self-relationship, malformed object, and unexpected
  implementation failure are separate outcomes. An unexpected failure is never
  converted into a clean "no relationship observed" result.
- **It is not a graph.** No graph database, graph library, graph API,
  persistence, visualization, traversal, path search, transitive closure, or
  cycle analysis. A future relationship set may contain cycles; nothing here
  requires or checks acyclicity.

**How later issues may use it:** a detector or scanner component that *directly
observes* a structural connection can build relationship candidates from the
finding IDs it already produced and hand them to the model, which validates,
normalizes, deduplicates, and orders them. Whether, where, and how relationships
are ever surfaced is a separate product decision that this model does not make.

## Extracted Evidence

Where available, findings include:

- asset type
- file location
- key algorithm
- key size
- certificate signature algorithm
- certificate expiration
- issuer
- subject
- SHA-256 fingerprint
- detection evidence
- detection confidence
- parsing errors for partial or malformed assets
- scanner name and version

## Exclusions and Symlinks

Use `--exclude` to skip files or relative paths by glob pattern:

```bash
python -m scanner.crypto_inventory ./target --exclude "*.tmp" --exclude "vendor/*"
```

Recursive scans do not follow symbolic links by default. Use
`--follow-symlinks` only when that is intentional for the target environment.

## Known Limitations

- Password-protected PKCS#12 containers are detected as malformed/partial in
  this MVP because the scanner does not prompt for passphrases.
- Encrypted PEM private keys are identified, but algorithm and key size may be
  unavailable without a passphrase.
- JKS support is limited to magic-header detection; entry-level parsing is not
  implemented.
- Random binary files are skipped unless their extension or header indicates a
  supported crypto asset.
- OpenPGP/GPG detection covers specific encrypted-file structures, not the
  whole OpenPGP specification: an encrypted file whose leading packet is not
  one of the supported shapes produces no finding, and the scanner never
  decrypts, prompts for a passphrase, verifies a signature, or invokes `gpg`.
- The scanner reports observed local evidence only. It does not calculate risk
  scores, quantum exposure, or executive priority.

The full detection boundary — unsupported keystores and containers, the
candidate-file gate, false-positive and false-negative conditions, what each
confidence level means, and why an empty inventory is not proof that no
cryptographic assets exist — is characterized in
[DETECTION_CHARACTERIZATION.md](DETECTION_CHARACTERIZATION.md).
