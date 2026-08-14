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
- Encrypted PKCS#8 private keys (`rule_id: private_key:pkcs8_encrypted`,
  confidence `High`), **the outer `EncryptedPrivateKeyInfo` structure only**,
  in DER form or RFC-style PEM labelled `ENCRYPTED PRIVATE KEY`. Validated
  structurally from the file's own bytes — a DER `SEQUENCE` at offset 0
  consuming the whole file with no trailing bytes, holding exactly an
  `AlgorithmIdentifier` and a non-empty primitive `OCTET STRING`, decoded from a
  complete PEM block when PEM-encoded — never by calling a key-loading API and
  reading its password-related failure as evidence. Never decrypted: no password
  is prompted for, accepted, read from the environment, guessed, or derived, and
  no external process is invoked. The encryption algorithm, KDF, cipher, salt,
  IV, iteration count, OIDs, and encrypted bytes are not reported; the only
  metadata emitted is `Format: PKCS#8`. The extension is not evidence, and the
  check runs ahead of the PKCS#12, DER, and generic PEM private-key branches —
  and ahead of the candidate gate — so a key with a misleading extension or none
  at all is still classified from its content. See
  [what is and is not supported](DETECTION_CHARACTERIZATION.md#encrypted-pkcs8-private-keys-hg-038)
- CMS / PKCS#7 encrypted objects, **the outer RFC 5652 `ContentInfo` structure
  only**, for two content types: `EnvelopedData`
  (`rule_id: cms:enveloped_data`, asset type `CMS/PKCS#7 Enveloped Data`) and
  `EncryptedData` (`rule_id: cms:encrypted_data`, asset type
  `CMS/PKCS#7 Encrypted Data`), both confidence `High`, in binary DER form or
  the RFC 7468 textual forms labelled `CMS` and `PKCS7`. Validated structurally
  from the object's own bytes — a DER `SEQUENCE` at offset 0 consuming the whole
  object with no trailing bytes, an outer content-type OID that is exactly one
  of the two supported values, an explicit `[0]` wrapper holding one inner
  `SEQUENCE`, the content-type-specific fields (a non-empty `recipientInfos`
  SET for `EnvelopedData`; the CMS version the specification fixes for
  `EncryptedData`), and an `EncryptedContentInfo` whose `encryptedContent` is
  present and non-empty. Certificate-only PKCS#7 bundles, `SignedData`, `Data`,
  and every other content type produce no finding, and the `CMS`/`PKCS7` label
  alone is never evidence. Never decrypted: no password, private key, secret
  key, or recipient certificate is prompted for or accepted, no signature or
  certificate is validated, no recipient is enumerated, and no external process
  is invoked. Recipient identities, algorithms, KDFs, IVs, OIDs, encrypted keys,
  and ciphertext are not reported; the only metadata emitted is
  `Format: CMS/PKCS#7`. The extension is not evidence, and the checks run ahead
  of the PKCS#12, DER, and generic PEM branches — and ahead of the candidate
  gate — so an object with a misleading extension or none at all is still
  classified from its content. See
  [what is and is not supported](DETECTION_CHARACTERIZATION.md#cms--pkcs7-encrypted-objects-hg-039)
- Encrypted legacy PEM private keys (`rule_id: private_key:legacy_pem_encrypted`,
  confidence `High`), **the traditional OpenSSL-style encrypted PEM form only**,
  for labels `RSA PRIVATE KEY`, `DSA PRIVATE KEY`, and `EC PRIVATE KEY` that
  declare `Proc-Type: 4,ENCRYPTED` and a syntactically valid `DEK-Info:
  <cipher>,<hex-IV>` header plus a non-empty strict-base64 body. Exact BEGIN/END
  boundaries are required (prefix/suffix contamination rejected). Never
  decrypted: no password is prompted for, accepted, read from the environment,
  guessed, or derived, and no external process or private-key load API is
  invoked. Cipher name, IV, and ciphertext are not reported; the only metadata
  emitted is `Format: Legacy PEM`. The extension is not evidence. The detector
  is non-terminal and runs after certificate PEM and before generic private-key
  PEM, without changing PKCS#12, encrypted PKCS#8, or CMS behavior. Encrypted
  PKCS#8 (`BEGIN ENCRYPTED PRIVATE KEY`) remains HG-038. See
  [what is and is not supported](DETECTION_CHARACTERIZATION.md#encrypted-legacy-pem-private-keys-hg-040)
- OpenSSH private keys
- OpenSSH public keys
- PKCS#12 containers (`.p12`, `.pfx`) when no password is required
- Java Keystore magic-header detection (JKS)
- BCFKS keystore containers, **the supported encrypted-object-store outer
  structure only**, identified from the file's own DER content — a two-element
  Bouncy Castle `ObjectStore` holding an `EncryptedObjectStoreData` and a
  `PbkdMacIntegrityCheck`, consuming the whole file. Never decrypted, no
  password is prompted for or validated, entries are not enumerated, and the
  finding does not prove truststore versus keystore. The extension is not
  evidence, and the check runs before the JKS, PKCS#12, and DER branches so a
  store with a misleading extension is still classified from its content.
  Unencrypted `ObjectStoreData` stores and signature-integrity (`[0]
  SignatureCheck`) stores are unsupported and produce no finding.
  See
  [what is and is not supported](DETECTION_CHARACTERIZATION.md#bcfks-keystore-containers-hg-036)
- JCEKS keystore containers (`rule_id: java_keystore:jceks`, confidence
  `Medium`), identified from the **top-level header only** — the magic
  `ce ce ce ce` at offset 0, a supported format version (1 or 2), a nonnegative
  entry count, and a file large enough for the fixed header plus the trailing
  integrity material. A separate format and detector from both BCFKS and JKS.
  Never opened or decrypted, no password is requested or accepted, the keyed
  digest is neither verified nor reported, entries are not parsed, no Java
  object is deserialized, and the finding does not prove truststore versus
  keystore. The extension is not evidence, and the check runs before the JKS,
  PKCS#12, and DER branches — and ahead of the candidate gate — so a store with
  a misleading extension or none at all is still classified from its content.
  Confidence is `Medium` because the container header was identified but the
  store was not authenticated or fully parsed. See
  [what is and is not supported](DETECTION_CHARACTERIZATION.md#jceks-keystore-containers-hg-037)
- Java trusted-certificate-only stores (`rule_id: java_truststore:jks` or
  `java_truststore:jceks`, asset type `Java Trusted-Certificate-Only Store`,
  confidence `High`), identified by reading the **complete declared entry
  table** of a JKS or JCEKS store (version 1 or 2) and finding only supported
  trusted-certificate entries, with exactly the 20-byte integrity trailer
  remaining afterwards. The observed fact is
  **trusted-certificate-only store structure**; this does **not** establish that
  an application uses the store as a runtime truststore, and the asset type is
  deliberately never the unqualified `Java Truststore`. Version-2 support is
  limited to the exact `X.509` certificate type — a trusted certificate of
  another Java-supported type is a deliberate false negative — and every
  accepted payload must parse as DER X.509 while every alias must be canonical
  `DataOutputStream.writeUTF` output. A store with any private-key entry, any
  JCEKS secret-key entry, an unknown entry tag, a mix of those with trusted
  certificates, or no entries at all is **not** classified here and falls
  through unchanged to the generic JKS/JCEKS classification; PKCS#12 and BCFKS
  stores used operationally for trust stay outside this rule. Content only:
  `cacerts` is not privileged by filename and identical bytes classify
  identically under any name. No password is requested or accepted, the trailing
  digest is never verified, key payloads are never parsed, JCEKS secret-key
  objects are never deserialized, `keytool` and Java are never invoked, and no
  alias or certificate content is reported. The only metadata emitted is
  `Format: JKS` or `Format: JCEKS`. See
  [what is and is not supported](DETECTION_CHARACTERIZATION.md#java-trusted-certificate-only-stores-hg-042)
- OpenSSH host identity evidence — three bounded, **file-local** observations,
  none of which pairs a private candidate with a public candidate, reads a
  sibling file, or resolves `sshd_config`/`HostKey`:
  - `rule_id: openssh_host_identity:private_key` (asset type
    `OpenSSH Host Private Key Candidate`, confidence `Medium`) — a supported
    unencrypted private key (OpenSSH, unencrypted PKCS#8, or traditional
    RSA/EC PEM) whose complete file, apart from permitted outer ASCII
    whitespace, is exactly one such block, at an *exact* canonical basename
    (`ssh_host_rsa_key`, `ssh_host_ecdsa_key`, `ssh_host_ed25519_key`) whose
    parsed key class agrees with that basename.
  - `rule_id: openssh_host_identity:public_key` (asset type
    `OpenSSH Host Public Key Candidate`, confidence `Medium`) — one supported
    OpenSSH public-key record, under the same one-record grammar, at the
    matching canonical `.pub` basename.
  - `rule_id: openssh_host_identity:host_certificate` (asset type
    `OpenSSH Host Certificate`, confidence `High`) — one structurally parsed
    OpenSSH certificate record whose encoded type is `HOST`. **No filename
    requirement.** The certificate signature is deliberately never verified
    (an intentional accepted false positive: a structurally valid but
    cryptographically tampered signature still matches; see
    [what is and is not supported](DETECTION_CHARACTERIZATION.md#openssh-host-identity-evidence-hg-043)
    for the exact tampered-signature control).

  RSA, ECDSA (`secp256r1`/`secp384r1`/`secp521r1` only), and Ed25519 are the
  only supported families for a private/public candidate and for both the
  certified key and the signing/CA key inside a certificate. For the
  private/public candidate rules, an unsupported algorithm/curve, a wrong
  canonical basename, a renamed key, a custom `HostKey` path, or an encrypted
  private key is a deliberate HG-043 no-match, and the key itself **still
  falls through to the existing generic private-key/public-key detectors
  unchanged** — visible there, at their own unspecialized asset type and
  confidence, not lost. A USER certificate, and a HOST certificate this rule
  declines (an unsupported certified or signing key, or one that fails to
  parse), are different: they freeze at **zero findings**, because the
  generic public-key detector never reports OpenSSH certificate content —
  structurally valid or not — under any rule. Evidence only: `Fingerprint`
  is always left unset for these three rules, no password is prompted for,
  guessed, or read from the environment, no `ssh`/`sshd`/`ssh-keygen`/
  `ssh-keyscan` process or network connection is invoked, and no comment,
  principal, key ID, serial, validity window, extension, or certificate
  signature is reported. See
  [what is and is not supported](DETECTION_CHARACTERIZATION.md#openssh-host-identity-evidence-hg-043)
- OpenSSL `Salted__` encrypted files (leading-byte signature only, not
  decrypted; checked before any extension-based branch above)
- OpenPGP/GPG encrypted files, binary or ASCII-armored, identified by the
  leading encrypted-session-key packet (structure only, not decrypted;
  checked before any extension-based branch above). Support is partial — see
  [what is and is not supported](DETECTION_CHARACTERIZATION.md#openpgpgpg-encrypted-files-hg-031)
- age encrypted files, **native age v1 only** (`age-encryption.org/v1`),
  identified by the format's own header structure — version line, recipient
  stanzas, header MAC line shape, and the presence of an encrypted payload
  (structure only, never decrypted; checked before any extension-based branch
  above). ASCII-armored age files are not supported, and no recipient identity
  is interpreted or reported. See
  [what is and is not supported](DETECTION_CHARACTERIZATION.md#age-encrypted-files-hg-035)
- gocryptfs cipher roots (standard forward mode, config format version 2
  only), identified by a root-level `gocryptfs.conf` plus `gocryptfs.diriv`
  pair — one finding per validated root directory, not per ciphertext file,
  and never decrypted, mounted, or unlocked. Reverse mode and `PlaintextNames`
  mode are unsupported. See
  [what is and is not supported](DETECTION_CHARACTERIZATION.md#gocryptfs-encrypted-filesystem-hg-032)
- Mozilla NSS SQL database sets (`rule_id: nss:sql_database_set`, asset type
  `NSS Cryptographic Database Set`, confidence `High`), **the supported
  canonical modern layout only** — `cert9.db`, `key4.db`, and `pkcs11.txt`
  together in one lexical directory, with a structurally recognized NSS
  internal-module stanza in `pkcs11.txt`. **One validated lexical directory
  produces one finding**, located at the containing directory; the component
  files are never separate NSS findings. `pkcs11.txt` is the only marker, and
  it must be a genuine regular non-symlink file. The two databases are
  **presence/eligibility checked only — never opened, read, parsed, locked, or
  internally validated**, so they do not increment `Crypto files inspected` on
  account of the aggregate check, and a database the scan excluded behaves
  exactly as a missing one. Never initialized or unlocked: no NSS or SQLite
  library, CLI, or FFI binding is loaded or invoked, no password is requested,
  accepted, read from the environment, or guessed, no certificate or key object
  is enumerated, and the marker's `configdir` is never resolved, followed, or
  reported. The only metadata emitted is `Format: NSS SQL`. Legacy DBM sets
  (`cert8.db`/`key3.db`/`secmod.db`), prefixed or renamed database sets,
  incomplete sets, and marker symlinks produce no finding. See
  [what is and is not supported](DETECTION_CHARACTERIZATION.md#mozilla-nss-sql-database-sets-hg-041)

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
one finding per validated root, never one per ciphertext file. The NSS SQL
database set (HG-041) is root-scope for the same reason: one finding per
validated lexical directory, never one per component file. A root detector's
fixed-name sibling check is also scope-aware — it asks the scanner's own
exclusion matcher whether that sibling is in scope for this scan, so aggregate
supporting evidence cannot ignore a `--exclude` pattern. It still opens
nothing, lists nothing, and counts nothing.

**Ownership of a marker is per detector.** gocryptfs owns its marker outright:
a `gocryptfs.conf` that failed root validation is not evidence of another asset
type either, so it never falls through. The NSS detector deliberately does not
(`owns_marker=False`): only a *validated* NSS root is terminal for its
`pkcs11.txt`. A rejected marker falls through to the later detectors, so a
defensible certificate or private key that happens to live in a file named
`pkcs11.txt` is still reported.

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
  Neither does *which* record survives: when duplicates disagree on a volatile
  field — evidence wording, confidence, creating component, scan context,
  collection time, repeatability, limitations, errors — the retained record is
  selected by a deterministic tie-break over those fields rather than by input
  order. That tie-break is not a ranking: there is no evidence-history
  aggregation, no merging of unrelated evidence, and no transitive
  deduplication.
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
  evidence — as short, safe values. None of these is optional: a record with no
  scan context is malformed rather than a record with unknown provenance, the
  component, rule, and scan context must be machine identifiers, and the
  collection time must be an ISO-8601 date-time (normalized to whole seconds,
  UTC when no offset is given) rather than arbitrary text.
- **The privacy boundary is structural.** The model has no metadata dictionary
  and no free-form field, so there is nowhere to put private key material, raw
  certificate bodies, raw or encrypted key blobs, ciphertext, plaintext,
  passphrases, salts, KDF values, raw config, OpenPGP packet bodies, Kubernetes
  or application secrets, parser exception payloads, or arbitrary blobs. Every
  text field is length-bounded and must be printable, and a field carrying a
  PEM/OpenPGP armor header or the OpenSSL `Salted__` magic is rejected rather
  than scrubbed. Unexpected keyword arguments raise rather than being absorbed.
  Rejection is not a channel either: a validation message names the refused
  *field* and at most the Python type supplied, never the value, so a passphrase
  a defective caller passed where an identifier belonged cannot travel out
  through an exception or through the collection's rejection text.
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
- Encrypted private keys are identified, but algorithm and key size are not
  available without a passphrase and are never reported for them.
- Encrypted PKCS#8 support is limited to the outer `EncryptedPrivateKeyInfo`
  container: the key is never decrypted, no password is requested or accepted,
  the inner private key is not identified, and no encryption algorithm, KDF,
  cipher, salt, IV, iteration count, OID, parameter, or encrypted byte is read
  into a finding — the only metadata emitted is `Format: PKCS#8`. `High`
  confidence applies to the **container type only**: it does not mean the
  password is known, the key is decryptable, the key is internally valid, the
  underlying algorithm is known, or that cryptographic strength was assessed. A
  deliberately crafted structure that is syntactically a valid
  `EncryptedPrivateKeyInfo` but whose encrypted data does not decrypt to a valid
  `PrivateKeyInfo` is still reported as encrypted PKCS#8, because ruling that
  out would require decryption. Non-DER (BER) encodings — indefinite lengths,
  non-minimal lengths, constructed `OCTET STRING`s — and structures embedded at
  a nonzero offset produce no finding, as does a malformed PEM block. A file
  whose only encrypted PKCS#8 block is malformed is left unreported rather than
  reported as an encrypted key on the strength of its label alone. Absence of a
  `private_key:pkcs8_encrypted` finding is not proof that no encrypted PKCS#8
  key exists in the target.
- CMS / PKCS#7 support is limited to two encrypted content types,
  `EnvelopedData` and `EncryptedData`, in a definite-length, minimally encoded
  DER subset. The object is never decrypted, no password, private key, secret
  key, or recipient certificate is requested or accepted, no signature or
  certificate chain is verified, no recipient is identified, and no OID,
  algorithm, KDF, salt, IV, encrypted key, or ciphertext byte is read into a
  finding — the only metadata emitted is `Format: CMS/PKCS#7`. `High` confidence
  applies to the **object structure only**: a syntactically valid supported
  structure whose `encryptedContent` holds arbitrary non-empty bytes still
  matches, because proving those bytes decrypt would require keys. BER
  indefinite-length/streaming CMS, detached or absent `encryptedContent`,
  malformed-but-tolerated encodings outside the strict subset, and unsupported
  content types such as `AuthEnvelopedData` produce no finding. Absence of a
  `cms:enveloped_data` or `cms:encrypted_data` finding is not proof that no CMS
  encrypted object exists in the target.
- Generic JKS support is limited to magic-header detection; general entry-level
  parsing is not implemented. The one exception is the bounded
  trusted-certificate-only classification described below, which reads the
  declared entry table to decide whether *every* entry is a trusted-certificate
  entry and hands every other store back to this generic classification.
- BCFKS support is limited to the supported encrypted-object-store outer
  container: entries are not enumerated, the store is never decrypted, no
  password is prompted for or validated, and no alias, certificate, key,
  encrypted content, MAC, salt, IV, or KDF parameter is read into a finding —
  the only metadata emitted is `Format: BCFKS`. Unsupported BCFKS forms
  (unencrypted `ObjectStoreData`, `[0] SignatureCheck` integrity)
  produce no finding. Absence of a `java_keystore:bcfks` finding is not proof
  that no BCFKS store exists in the target.
- JCEKS support is limited to the top-level container header: the store is never
  opened, no password is requested or accepted, the keyed integrity digest is
  never verified, recomputed, or reported, entry records are not parsed, no Java
  serialized object is deserialized, and the only metadata emitted is
  `Format: JCEKS`. Because entries are not parsed and the digest is not
  authenticated, a crafted binary reproducing a valid JCEKS header and plausible
  length — or a genuine store truncated above the structural minimum — would be
  reported as JCEKS; this is why confidence is `Medium`. Absence of a
  `java_keystore:jceks` finding is not proof that no JCEKS store exists in the
  target.
- Java trusted-certificate-only store classification is a **structural
  observation about the store's declared entries, not a runtime-role claim**: it
  does not establish that any application uses the store as a truststore, that
  the certificates are trustworthy or current, that the store is authenticated
  or unlockable, or that it holds every certificate an application trusts.
  Supported versions are JKS/JCEKS 1 and 2 only, and version-2 support is
  limited to the exact `X.509` certificate type. Deliberate false negatives:
  trusted certificates of any other Java-supported certificate type, any store
  containing a private-key entry, a JCEKS secret-key entry, or an unknown entry
  tag, empty stores, PKCS#12 and BCFKS stores used operationally as truststores,
  runtime truststore configuration that cannot be proven from the store's bytes,
  and alias or certificate-type fields that a permissive
  `DataInputStream.readUTF` would accept but that are not canonical
  `DataOutputStream.writeUTF` output. The trailing 20-byte integrity trailer is
  structural evidence only — it is never read, recomputed, or verified, which
  would require the store password — so a store whose trailer is arbitrary bytes
  still matches. Certificate contents are not reported: X.509 parsing is a
  boolean structural check and no alias, subject, issuer, serial number, SAN,
  fingerprint, validity date, or DER byte reaches a finding. The only metadata
  emitted is `Format: JKS` or `Format: JCEKS`. Absence of a `java_truststore:*`
  finding is not proof that no Java truststore exists in the target.
- OpenSSH host identity evidence does not establish that `sshd` is installed,
  running, or configured to use the file, that a public candidate matches any
  private candidate, that a certificate signature is valid or its CA trusted,
  that certificate principals apply to the scanned machine, or host ownership.
  It is **file-local by design**: no sibling file is read, no cross-file state
  is kept, and two files under an unrelated key's matching canonical basenames
  may each independently produce a candidate finding with no claim that they
  pair. Supported algorithms are exactly RSA, ECDSA (`secp256r1`/`secp384r1`/
  `secp521r1`), and Ed25519; DSA, Ed448, FIDO/security-key variants, and any
  other ECDSA curve are deliberate false negatives, as are custom `HostKey`
  paths, renamed keys, encrypted private keys, and multi-record/embedded input
  outside the frozen one-block/one-record grammars. A user key renamed to an
  exact canonical basename becomes a candidate finding — an explicit accepted
  false positive, since ordinary key bytes cannot encode host-versus-user
  role. The certificate rule deliberately never calls
  `verify_cert_signature()`: a structurally valid HOST certificate with a
  tampered signature still matches, and a USER certificate never does,
  regardless of signature validity. `Fingerprint` is always unset for these
  three rules. Absence of an `openssh_host_identity:*` finding is not proof
  that no OpenSSH host key or certificate exists in the target.
- Random binary files are skipped unless their extension or header indicates a
  supported crypto asset.
- OpenPGP/GPG detection covers specific encrypted-file structures, not the
  whole OpenPGP specification: an encrypted file whose leading packet is not
  one of the supported shapes produces no finding, and the scanner never
  decrypts, prompts for a passphrase, verifies a signature, or invokes `gpg`.
- age detection covers native age v1 files only: ASCII-armored age files, other
  age versions, and malformed or truncated age-like content produce no finding,
  and the scanner never decrypts, prompts for a passphrase or identity file,
  reads a keyring or SSH agent, resolves recipients, or invokes `age`. Absence
  of an `encrypted_file:age` finding is not proof that no age-encrypted content
  exists in the target.
- The scanner reports observed local evidence only. It does not calculate risk
  scores, quantum exposure, or executive priority.

The full detection boundary — unsupported keystores and containers, the
candidate-file gate, false-positive and false-negative conditions, what each
confidence level means, and why an empty inventory is not proof that no
cryptographic assets exist — is characterized in
[DETECTION_CHARACTERIZATION.md](DETECTION_CHARACTERIZATION.md).
