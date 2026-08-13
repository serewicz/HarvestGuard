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
bit flag). A file whose signature matches produces its own `file` finding,
at `High` confidence. Symlinks, FIFOs, sockets, and device files are never
followed or opened (see [SCAN_COVERAGE.md](SCAN_COVERAGE.md)) and produce a
`skipped_special_file` finding instead of file-content evidence.

An **ordinary file** — readable, no signature match, no file-specific
failure — produces **no finding of its own**. Its only evidence is the
volume/filesystem/platform context it shares with every other such file on
the same mount, so that context is recorded once per mount as an **aggregate
`filesystem_context` finding** (`asset_type: "volume"`) instead of once per
file. Emitting one record per ordinary file previously made a 20,000-file
scan report roughly 20,000 near-identical "findings"; see "Aggregate
filesystem context" below.

A per-file record still exists for a **file-specific failure** — the file's
header could not be read (permission denied, the file vanished mid-scan) —
because that is evidence about that specific file, not shared context.

### Aggregate filesystem context

One `filesystem_context` finding is emitted per mount that has at least one
ordinary file to represent, reusing existing `NormalizedFinding` fields
rather than adding new ones:

- `location` and `identity_key` are both derived from the mount point path
  alone — never a timestamp, hostname, process ID, scan duration, or
  per-file ownership/ACL value — so the same mount produces the same
  identity across repeated scans and different hosts, and two distinct
  mounts scanned in one run produce two distinct, stable identities.
- `technical_metadata` carries the volume-level `Encryption` status, the
  mount point, the platform, and three counts: how many regular files were
  inspected on that mount, how many of those are represented by this
  aggregate record (had no signature match and no file-specific failure),
  and how many produced their own finding.
- **`Unknown` volume-encryption status is never presented as observed
  `Unencrypted` status.** `Unknown` means the platform or tooling could not
  determine the status at all (unsupported platform, missing tool, a failed
  or timed-out check); `Unencrypted` means the platform determined the
  volume is genuinely not encrypted. They carry different `rule_id` values
  (`volume_status:unknown` vs. `volume_status:unencrypted`), different
  evidence text, and different confidence, and are never collapsed into one
  label.
- A platform-wide limitation such as "ACL presence could not be portably
  determined on this platform" is recorded once on the aggregate record for
  the mount, not once per ordinary file it represents.
- A mount whose every inspected file produced its own per-file finding (for
  example, every file had a recognized signature) has nothing left for an
  aggregate record to represent, so none is emitted for that mount.

### Confidence semantics

- `High` — a file-level signature matched on a specific file. The
  observation is a direct read of that file's content, independent of the
  volume.
- `Medium` — the aggregate context record's volume-level status is a known
  value (encrypted or not). No individual file was independently verified;
  the files it represents inherit the volume's status.
- `Low` — either a specific file's header could not be read (permission
  denied, the file vanished mid-scan) and volume status was used as a
  fallback for that file with no file-level verification at all, or the
  aggregate context record's volume-level status is `Unknown` (neither
  file-level nor volume-level status could be established for the files it
  represents).

`confidence_rationale` on every filesystem finding (per-file and aggregate
alike) states which of these applied. Host-dependent confidence is expected:
the same file scanned on a FileVault-enabled Mac versus an unrelated Linux
host can legitimately produce `Medium` in one case and `Low` in the other on
its mount's aggregate record, because volume-level detection depends on the
host's own platform and tooling, not on the file itself.

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
  remains for `MESSAGE`-armored files specifically. This scanner's behavior is
  unchanged; the crypto-inventory scanner does read the leading packet tag and
  therefore does not repeat this false positive (see [OpenPGP/GPG encrypted
  files](#openpgpgpg-encrypted-files-hg-031)). Other PGP armor types —
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

Each supported format below is implemented as one detector in a static internal
registry (HG-033). That framework is an implementation boundary only: **it added
no new detection capability, and no format, asset type, rule ID, evidence
wording, confidence value, or metadata field in this section changed when it was
introduced.** Everything characterized here — including every false-positive and
false-negative condition — describes the same detection rules that existed
before it. The registry's own properties (scanner-owned traversal, one shared
read per file, deterministic ordering and terminality, detector-declared safe
metadata allowlists, accounting that counts files rather than detector
invocations, and detector error isolation) are described in
[CRYPTO_INVENTORY.md](CRYPTO_INVENTORY.md#detector-framework). One consequence
is worth stating here as a coverage fact: an unexpected detector defect stops
the crypto-inventory scan and is reported as a scanner error with the findings
already collected preserved, so a detector failure is never presented as a
clean, complete result.

**OpenSSL `Salted__` encrypted files (HG-030).** A file whose content begins
with the exact 8-byte header `openssl enc -salt` writes is reported as asset
type `Encrypted File` (`rule_id: encrypted_file:openssl`), based solely on
that leading-byte signature — not decryption, not parameter parsing. This
check runs before every extension-based branch below, so a `Salted__` file
saved with a `.p12`, `.pfx`, `.cer`, `.crt`, or `.der` extension is still
reported as `Encrypted File`, not as a malformed PKCS#12/DER asset. The
filesystem scanner ([local filesystem encryption
evidence](#local-filesystem-encryption-evidence)) recognizes the same
signature independently; when both scanners run in the same scan
(`--type all`), only the crypto-inventory finding for that file is kept in
the combined output — see [docs/CLI.md](CLI.md#openssl-encrypted-file-evidence-hg-030).

#### OpenPGP/GPG encrypted files (HG-031)

A file whose leading OpenPGP packet is one of the supported encrypted-session-key
shapes below is reported as asset type `Encrypted File`
(`rule_id: encrypted_file:openpgp`, confidence `High`), based solely on that
directly observed packet structure. Like the `Salted__` check, it runs before
every extension-based branch, so an OpenPGP file saved with a `.p12`, `.der`,
or any other extension is still reported as `Encrypted File` rather than as a
malformed asset.

**What is supported**, verified against real `gpg --symmetric` and
`gpg --encrypt` output:

- **Symmetric-Key Encrypted Session Key packet, tag 3, version 4** — the shape
  `gpg --symmetric` writes and the field-observed case in HG-031 (a file
  beginning `8c 0d 04 …`, which `file(1)` reports as "PGP symmetric key
  encrypted data").
- **Public-Key Encrypted Session Key packet, tag 1, version 3** — the shape
  `gpg --encrypt` writes (a file beginning e.g. `84 5e 03 …` or `85 01 0c …`).
- **Both of the above inside `-----BEGIN PGP MESSAGE-----` ASCII armor.** RFC
  4880 §6.2 fixes the armor layout (header line alone on the first line,
  optional armor headers, a mandatory blank line, radix-64 body, checksum,
  tail), and each of those parts is required: trailing content on the header
  line, or a body not preceded by the blank separator, is not read as armor at
  all. The first decoded byte of the body is therefore the first byte of the
  first packet — the armored counterpart of offset 0, not a search for a
  signature at an arbitrary position. The whole body is decoded, not a prefix of
  it, so the decoded stream is the armored counterpart of a binary file's bytes
  and is held to the same checks.

Both the packet header and the fixed metadata fields the specification defines
for that packet are validated (version, symmetric algorithm, string-to-key
specifier and its hash algorithm, or public-key algorithm), so a file that
merely happens to start with a plausible header octet does not match. The
packet's declared body length is validated with them: every field read must lie
inside the body the packet declares, and the declared body must be long enough
to hold the fields the specification requires there (the salt and coded
iteration count of a salted or iterated string-to-key specifier, the non-empty
encrypted session key of a public-key packet). A packet whose declared length
stops short of its own required fields is malformed, and the bytes that follow
it are a different packet's — reading them as this packet's metadata is what
would turn a near match into a `High`-confidence claim. The
observed algorithm identifier is reported in `Algorithm` and named in the
evidence text because it is read directly out of the packet; nothing is
inferred from it.

**What is not supported** — each of these produces no finding at all:

- RFC 9580 version 6 (and draft version 5) session-key packets, and AEAD-only
  encrypted-message forms.
- Packets whose length is partial (new-format) or indeterminate (old-format),
  and multipart armor (`-----BEGIN PGP MESSAGE, PART …-----`).
- Packets whose declared body length is inconsistent with their contents: too
  short to hold the fields the specification requires, or declared to run past
  the end of the packet stream that holds them. Both checks apply equally to a
  binary file and to an armored one, whose whole radix-64 body is decoded for
  exactly that reason. A genuine encrypted file that has been truncated on disk
  therefore produces no finding.
- A file that begins with a bare encrypted-data packet with no session-key
  packet in front of it, or with any other packet type.
- Any OpenPGP structure not at the start of the file, including an encrypted
  message embedded in a larger container.

**What is deliberately not classified as an encrypted file:** ASCII-armored
signed messages (`-----BEGIN PGP SIGNED MESSAGE-----`, and the `MESSAGE`-armored
compressed-data packet `gpg --armor --sign` writes), detached signatures,
`PUBLIC KEY BLOCK`, and `PRIVATE KEY BLOCK` armor. This scanner distinguishes
them by reading the leading packet tag, which is what lets it avoid the
residual `MESSAGE`-armor false positive the filesystem scanner documents above;
the HG-009 narrowing of that scanner's `-----BEGIN PGP` prefix is unchanged.

**Scanner ownership.** The filesystem scanner independently recognizes a
narrower set of the same shapes (`MESSAGE` armor and the binary `85 01`/`85 02`
prefixes) as `File-level (PGP/GPG)`, and `--type filesystem` still reports
exactly that, unchanged. Under `--type all`, crypto inventory owns this
evidence: exactly one record per file survives, deterministically, regardless
of scanner order — see [docs/CLI.md](CLI.md#openpgpgpg-encrypted-file-evidence-hg-031).

**No decryption.** The scanner never decrypts, never requests or accepts a
passphrase, never enumerates recipients (the key ID in a public-key packet is
read past, never reported), never verifies a signature, and never invokes
`gpg` or any other external tool. Absence of an `encrypted_file:openpgp`
finding is not proof that no encrypted OpenPGP files exist in the target.

#### age encrypted files (HG-035)

A file whose content is a **native age v1** encrypted file is reported as asset
type `Encrypted File` (`rule_id: encrypted_file:age`, confidence `High`,
evidence `Observed age encrypted file.`), based solely on the directly observed
header structure described below. Like the `Salted__` and OpenPGP checks, it
runs before every extension-based branch, so valid age content saved with a
`.p12`, `.pfx`, `.der`, `.pem`, `.gpg`, or any other extension is still
classified from its content rather than as a malformed container. One finding is
emitted per valid supported file, and the match is terminal: no later detector
also reads that file as PEM, DER, PKCS#12, JKS, SSH, OpenPGP, or OpenSSL
content.

**What is supported** — the native (non-armored) age v1 format, and only when
every one of these holds:

- The file begins **at byte offset 0** with the exact version line
  `age-encryption.org/v1` followed by LF. A near-match version string, a
  different version, or the same line further into the file is not a match.
- **One or more recipient stanzas**, in the native header grammar: a line
  beginning `-> ` followed by one or more non-empty, space-separated printable
  arguments, then the stanza body — zero or more lines of exactly 64
  unpadded-base64 characters (`A-Z`, `a-z`, `0-9`, `+`, `/`) followed by one
  final line shorter than 64 characters. At least one body character is
  required, so a stanza with an empty body is not a match. Stanza arguments are
  parsed only far enough to confirm the line is structurally a stanza.
- A **header MAC line** of exactly `--- ` plus 43 unpadded-base64 characters,
  followed by LF. Only the *shape* is validated — verifying the HMAC itself
  would require the file key, which would mean decryption.
- An **encrypted payload present immediately after the header**, at least 32
  bytes long (a 16-byte nonce plus at least one chunk authentication tag). The
  payload's length is the only thing read from it.
- **LF line endings.** Every parsed header line must be LF-terminated; a CRLF
  native header is out of scope for HG-035 and produces no finding rather than
  being accepted on a relaxed reading of the grammar.

**What is not supported** — each of these produces no finding at all, and never
a lower-confidence partial finding or a "malformed age" asset type:

- **ASCII-armored age files** (`-----BEGIN AGE ENCRYPTED FILE-----`). Deferred:
  HG-035 covers the native format only.
- Non-v1 (older or future) native age versions.
- A file with only the version line, only a stanza prefix, a header with no MAC
  line, a header with no payload, or a payload shorter than 32 bytes — a
  genuine age file truncated on disk therefore produces no finding.
- Malformed stanzas: a bad argument line, an empty stanza body, body characters
  outside the unpadded-base64 alphabet, or body line lengths that do not follow
  the wrapping rule.
- A malformed MAC line: wrong prefix, wrong length, or characters outside the
  unpadded-base64 alphabet.
- Copied documentation or example text, arbitrary text containing the word
  `age`, plaintext carrying a `.age` extension, and random bytes. **No detection
  is based on filename, extension, entropy, or random-looking content**, so an
  encrypted file this rule does not recognize is not caught by a fallback
  heuristic either.

**No decryption, no recipients, no key material.** The scanner never decrypts,
never prompts for or accepts a passphrase or identity file, never reads a local
keyring or SSH agent, never resolves or reports recipients, and never invokes
`age` or any other external tool. Recipient types and arguments, stanza bodies,
the header MAC, the payload, and its length are all absent from output: an age
finding carries no technical metadata at all. It also makes no claim about
encryption strength, decryptability, confidentiality, or who holds a key.
Absence of an `encrypted_file:age` finding is not proof that no age-encrypted
content exists in the target — this is one narrow rule for one explicitly
enumerated on-disk shape, not general encrypted-file detection.

**Scanner ownership.** Crypto inventory owns `encrypted_file:age`; the
filesystem scanner never emits it, and `--type filesystem` produces no
`Encrypted File` finding. The filesystem scanner does independently recognize
the *leading bytes* `age-encryption.org/v1` as `File-level (age)` (see [local
filesystem encryption evidence](#local-filesystem-encryption-evidence)) — a
broader, prefix-only signature that also matches age-like content this rule
rejects. HG-035 adds no cross-scanner deduplication pairing for age, so under
`--type all` that separate `local_filesystem` `file` record still appears
alongside the one crypto-inventory `Encrypted File` finding, exactly as it did
before HG-035. Accounting is unchanged and stays separate: an age file counts
once in `Crypto files inspected`, there is no age-specific count, and no
summary bucket was added.

**No relationship output.** HG-035 adds age detection only; it creates no
[internal relationship records](CRYPTO_INVENTORY.md#internal-relationship-model-internal-only-no-output)
and emits nothing beyond the single finding described above.

#### gocryptfs encrypted filesystem (HG-032)

A directory containing both a supported `gocryptfs.conf` and a root-level
`gocryptfs.diriv` is reported as one asset-type `Encrypted Filesystem` finding
(`rule_id: encrypted_filesystem:gocryptfs`, confidence `High`, `location` the
root directory itself) for the *container*, not one finding per file inside
it. Unlike the OpenSSL and OpenPGP checks above, this is a directory-level
structural check, not a per-file content signature: it fires when a file
named exactly `gocryptfs.conf` is visited, and validates that directory (its
parent) as a candidate root.

**What is supported** — a *standard forward-mode* cipher root, and only
config format version `2` (the on-disk format version gocryptfs has used
continuously since v1.2; an unrecognized `Version` value produces no finding
rather than an unverified guess that a newer or older format matches):

- `gocryptfs.conf` and `gocryptfs.diriv` are both regular files (not
  symlinks) directly inside the candidate root directory — both are
  mandatory, and either one missing produces no finding.
- `gocryptfs.conf` decodes as a JSON object carrying the stable fields every
  forward-mode config has: `Version`, `FeatureFlags`, `EncryptedKey`,
  `ScryptObject`. `EncryptedKey` must be non-empty valid base64, and
  `ScryptObject` must contain the required version-2 structural fields with a
  valid base64 salt and positive integer work-factor/key-length values. These
  checks validate supported structure only; HarvestGuard does not verify or
  emit the underlying secret material.
- `FeatureFlags` does not contain `PlaintextNames` — a materially different
  mode where filenames are stored unencrypted rather than encrypted, which
  HG-032 does not claim to detect the same way.

**Reverse mode is unsupported, and is excluded structurally rather than by a
config field.** gocryptfs.conf carries no persisted "this is reverse mode"
value at all — a forward-mode and a reverse-mode config are the same JSON
shape. What differs on disk is that forward mode physically writes a
`gocryptfs.diriv` file to every real directory, including the root, while
reverse mode computes directory IVs live from the plaintext side and never
writes one anywhere — there is nothing on-disk for a reverse root to collect.
Requiring a root-level `gocryptfs.diriv` (already mandatory above) is
therefore what rejects reverse-mode roots; there is no separate reverse-mode
content check to make.

**What is not supported** — each of these produces no finding at all, and
never a lower-confidence partial finding:

- An unsupported or malformed `Version` (anything other than the integer
  `2`), including a non-integer or boolean value.
- Empty or malformed (not valid JSON, or not a JSON object) `gocryptfs.conf`.
- `PlaintextNames` mode.
- Reverse mode (see above — detected by the missing root `gocryptfs.diriv`).
- A `gocryptfs.conf` with no root-level `gocryptfs.diriv` of its own,
  including one copied or left behind in an unrelated directory.
- A directory containing only ordinary or base64-/radix64-shaped filenames,
  with no `gocryptfs.conf` at all.
- A `gocryptfs.conf`/`gocryptfs.diriv` pair present, but not directly inside
  the same candidate directory (for example, one level too deep).

**No per-file amplification, and independent nested roots.** Ordinary
ciphertext files, encrypted subdirectories, a nested `gocryptfs.diriv` with
no `gocryptfs.conf` beside it, and long-name sidecar files inside a validated
root are internal structure only and never produce their own findings — a
root with hundreds of ciphertext files still produces exactly one finding. A
nested directory that independently satisfies the full structural contract
(its own valid, supported `gocryptfs.conf` plus its own root-level
`gocryptfs.diriv`) is a separate cipher root and produces one additional,
separate finding. Root identity is derived only from the normalized root
path, scanner identity, and `rule_id` — never traversal order, timestamps,
hostname, permissions, file counts, or collection time — so the same root
produces the same finding identity across repeated scans.

**Coverage.** A validated root finding may still be emitted when traversal
beneath the root is incomplete (a permission failure or unreadable
subdirectory, for example) — confidence describes only the directly validated
root structure, never completeness of what lies beneath it. HG-032 does not
report an aggregate ciphertext-file or subdirectory count at all, so no such
count is ever claimed as complete or incomplete.

**Scanner ownership.** The filesystem scanner does not recognize gocryptfs
structure at all — neither `gocryptfs.conf` nor `gocryptfs.diriv` matches any
filesystem-scanner signature — so there is nothing for `--type all` to
deduplicate here; the crypto-inventory root finding simply appears alongside
whatever unrelated filesystem context and coverage records exist for the same
target. See
[docs/CLI.md](CLI.md#gocryptfs-encrypted-filesystem-evidence-hg-032).

**No decryption, mounting, or correlation.** The scanner never mounts,
unlocks, or decrypts a gocryptfs container, never prompts for or accepts a
password, and never correlates a mounted, plaintext-visible directory back to
its cipher root — a mounted view is a different, unrelated directory with no
`gocryptfs.conf`/`gocryptfs.diriv` markers of its own, and is not
misclassified as a cipher root. Absence of an `encrypted_filesystem:gocryptfs`
finding is not proof that no gocryptfs cipher root exists in the target — this
is one narrow, explicitly enumerated detection rule, not general
encrypted-filesystem or FUSE coverage.

#### BCFKS keystore containers (HG-036)

A file whose content is a **supported Bouncy Castle BCFKS `ObjectStore`** is
reported as asset type `Java Keystore` (`rule_id: java_keystore:bcfks`,
confidence `High`, evidence `Observed supported BCFKS keystore structure.`,
technical metadata `Format: BCFKS` and nothing else), based solely on the outer
DER container structure described below. Like the `Salted__`, OpenPGP, and age
checks, it runs ahead of the extension-based branches — before JKS, PKCS#12, and
DER certificate parsing — so a valid store saved as `truststore.p12`,
`certs.der`, `keystore.jks`, or with no extension at all is classified from its
content rather than as a malformed PKCS#12, DER certificate, or JKS keystore.
One finding is emitted per supported file, and the match is terminal: no later
detector also reads that file as PEM, DER, PKCS#12, JKS, or SSH content.

**What is supported** — the default encrypted object store the Bouncy Castle
provider's `engineStore(OutputStream, char[])` path writes (password/MAC
protected), and only when every one of these holds:

- The file is a **complete DER `SEQUENCE` beginning at byte offset 0** whose
  declared length consumes the whole file with **no trailing bytes**. Supported
  bytes embedded at a nonzero offset inside a larger file are not a match.
- The top-level sequence has **exactly two elements**.
- The **first element structurally matches `EncryptedObjectStoreData`**: a
  sequence of exactly an `AlgorithmIdentifier` (a sequence whose first element
  is a well-formed, non-empty OBJECT IDENTIFIER, with at most one parameters
  element) and a **non-empty OCTET STRING** of encrypted content.
- A **parameters element is walked to confirm its nested DER is well formed** —
  truncated or unconsumed content anywhere inside the encryption, MAC, or
  key-derivation parameters is a corrupted encoding and produces no finding.
- A **primitive parameters element must also carry content its universal tag
  permits**: a NULL is empty, a BOOLEAN is one octet holding `0x00` or `0xFF`,
  an INTEGER or ENUMERATED is non-empty and free of a redundant leading padding
  octet, a BIT STRING declares at most seven unused bits and leaves them zero,
  and an OBJECT IDENTIFIER or RELATIVE-OID follows the subidentifier rules
  below. Universal tags in the wrong form — a constructed OCTET STRING, a
  primitive SEQUENCE, end-of-contents, the reserved number — are rejected on the
  same grounds. Each of these is length-consistent but invalid DER, so none of
  them may earn a High-confidence finding. The parameter *values* are still
  never interpreted or reported.
- The **second element structurally matches `PbkdMacIntegrityCheck`**: a
  sequence of exactly a MAC `AlgorithmIdentifier`, a key-derivation-function
  identifier of the same `AlgorithmIdentifier` shape, and a **non-empty MAC
  OCTET STRING**.
- Every length is a **well-formed, minimally encoded, definite DER length**, and
  every element's content is consumed exactly by its children.

The algorithm, MAC, and key-derivation OIDs are checked for *encoding* only —
non-empty, every base-128 subidentifier terminated, and none padded with a
leading `0x80` group, so bytes that merely wear the OID tag are rejected. Their
*values* are never decoded, compared against a table, or reported: HG-036 claims
the container's structure, not which cipher, MAC, or KDF a particular store
used.

**What is not supported** — each of these produces no finding at all, and never
a lower-confidence partial finding or a "malformed BCFKS" asset type:

- **Unencrypted `ObjectStoreData` stores** (the form written without store
  encryption), whose first top-level element is a version INTEGER rather than an
  encryption `AlgorithmIdentifier`.
- **Signature-integrity stores** using the explicit `[0] SignatureCheck` arm of
  `ObjectStoreIntegrityCheck` in place of the PBKD MAC.
- Future or variant BCFKS top-level structures not matching the shape above.
- A truncated store, a corrupted length octet, an indefinite or non-minimal
  length encoding, trailing bytes after an otherwise complete store, an empty
  encrypted-content or MAC octet string, or any near-match ASN.1 structure
  (including an `EncryptedPrivateKeyInfo`, a CMS/PKCS#7 `ContentInfo`, a DER
  certificate, a PKCS#12 container, and a JKS keystore) — a genuine BCFKS file
  truncated on disk therefore produces no finding.
- Copied ASN.1 documentation text, arbitrary text containing the word `BCFKS`,
  and plaintext carrying a `.bcfks` extension. **No detection is based on
  filename, extension, entropy, or file size**; the extension is not evidence
  and is not consulted at all, so an extension-only `.bcfks` file produces
  nothing.

**JCEKS is a separate detector**, added by HG-037 and described below; HG-036
recognizes the Bouncy Castle container only. Broader Java truststore inventory
remains unimplemented.

**Residual false positive.** Because the algorithm OIDs are deliberately not
interpreted, any non-BCFKS DER file that happens to have exactly this outer
shape — a whole-file two-element sequence of an `AlgorithmIdentifier` plus a
non-empty `OCTET STRING`, followed by a three-element sequence of two
`AlgorithmIdentifier`s plus a non-empty `OCTET STRING` — would be reported as a
BCFKS container. No such format is known to this repository, and the common
near-matches (X.509 certificates and CRLs, PKCS#12, CMS/PKCS#7 `ContentInfo`,
`EncryptedPrivateKeyInfo`, JKS) are all excluded by element count, element type,
or both; the boundary is recorded here because it is a structural match, not an
identified-format match.

**The finding does not prove truststore versus keystore.** Entry aliases, entry
types, certificates, and private-key material all live inside the encrypted
store data, so the outer container cannot distinguish a trusted-certificate
store from a private-key store, an empty store from a populated one, or one
entry from many. A BCFKS finding is a container-structure observation, and
HarvestGuard makes no claim beyond it.

**No decryption, no entries, no key material.** The scanner never decrypts,
never prompts for or accepts a password, never validates a password, never
enumerates entries, never inspects contained certificates or keys, and never
invokes Java, `keytool`, Bouncy Castle, OpenSSL, or any other external tool or
network service. Aliases, entry counts, entry types, certificate subjects and
issuers, key identifiers, encrypted content, MAC values, salts, IVs, KDF
parameters, raw ASN.1 fragments, and parser exception payloads are all absent
from output — a BCFKS finding carries exactly one metadata value,
`Format: BCFKS`. It also makes no claim about encryption strength,
decryptability, or confidentiality. Absence of a `java_keystore:bcfks` finding
is not proof that no BCFKS store exists in the target — this is one narrow rule
for one explicitly enumerated container shape, not general keystore detection.

**Scanner ownership.** Crypto inventory owns `java_keystore:bcfks`; the
filesystem scanner never emits it, recognizes no BCFKS structure of its own, and
`--type filesystem` is unchanged. There is therefore nothing for `--type all` to
deduplicate: the crypto-inventory finding simply appears alongside whatever
unrelated filesystem context and coverage records exist for the same target, and
HG-036 adds no cross-scanner deduplication pairing. Accounting is unchanged: a
BCFKS file counts once in `Crypto files inspected`, contributes nothing to
`Files scanned`, and there is no BCFKS-specific count and no new summary bucket.
JSON remains a bare normalized-finding array, Markdown remains evidence-only,
CLI output and DataFrame columns are unchanged, and Streamlit behavior is
unchanged.

**No relationship output.** HG-036 adds BCFKS detection only; it creates no
[internal relationship records](CRYPTO_INVENTORY.md#internal-relationship-model-internal-only-no-output)
and emits nothing beyond the single finding described above.

#### JCEKS keystore containers (HG-037)

A file carrying the **JCEKS top-level header** is reported as asset type
`Java Keystore` (`rule_id: java_keystore:jceks`, confidence `Medium`, evidence
`JCEKS keystore header detected`, technical metadata `Format: JCEKS` and nothing
else). Like the `Salted__`, OpenPGP, age, and BCFKS checks, it runs ahead of the
extension-based branches — before JKS, PKCS#12, and DER certificate parsing, and
ahead of the shared candidate gate — so a valid store saved as `store`,
`store.bin`, `truststore.p12`, `certs.der`, or `keystore.jks` is classified from
its content rather than missed by the gate or reported as a malformed PKCS#12 or
DER certificate. One finding is emitted per file, and the match is terminal: no
later detector also reads that file as PEM, DER, PKCS#12, JKS, or SSH content.

**What is detected** — the top-level header OpenJDK's `JceKeyStore`
(`com.sun.crypto.provider.JceKeyStore`) writes, and only when every one of these
holds:

- The file has **enough bytes for the fixed 12-byte top-level header**.
- Bytes 0-3 are the **big-endian JCEKS magic `ce ce ce ce`** at offset 0. This is
  what separates JCEKS from JKS, whose magic is `fe ed fe ed`; the JKS detector
  and its `java_keystore:jks_magic` identity are untouched by HG-037. Magic bytes
  at a nonzero offset are not a match.
- The **format version is 1 or 2**, the versions `JceKeyStore` supports.
- The **entry count is a nonnegative signed 32-bit value**, as
  `DataInputStream.readInt()` reads it.
- The file is **large enough to be structurally possible**: at least the 12-byte
  header plus the 20-byte trailing keyed SHA-1 digest. An empty store written by
  `keytool` is exactly those 32 bytes.

**Why confidence is `Medium`, not `High`.** HarvestGuard has identified the
container header and a plausible top-level structure; it has **not**
authenticated the store or parsed its contents. `JceKeyStore.engineLoad()` goes
on to read the entry records and, for secret-key entries, to deserialize Java
`SealedObject` data. HarvestGuard deliberately does none of that — deserializing
untrusted Java objects to name a file would be both unnecessary and unsafe — and
the keyed digest is not verified because verification requires the store
password. The evidence claim is therefore *"this file has the identifying header
and plausible top-level structure of a JCEKS keystore,"* never *"this JCEKS
keystore has been completely parsed and cryptographically authenticated."*

**Known false-positive boundary.** Because entry records are not parsed and the
digest is not authenticated, a **deliberately crafted binary reproducing a valid
JCEKS top-level header and a plausible container length would be classified as
JCEKS**. So would a genuine JCEKS store truncated on disk *above* the 32-byte
minimum, whose header is intact but whose entry records are incomplete. Both are
accepted consequences of stopping short of Java deserialization and digest
verification, and both are why the finding is `Medium` rather than `High`.

**Known false negatives** — each of these produces no finding at all, and never
a lower-confidence partial finding or a "malformed JCEKS" asset type:

- A file whose **magic is absent, truncated, or a near-match** (`ce ce ce cf`,
  `cd ce ce ce`), or whose JCEKS magic appears at a nonzero offset.
- A **version outside 1 and 2**, including deliberately unsupported historical
  or nonstandard variants and any future format version.
- A **truncated header** — missing or partial version or entry-count field — or a
  file shorter than the 32-byte structural minimum.
- A **negative entry count**.
- Neighbouring formats: **JKS, BCFKS, PKCS#12, and DER** files, each of which
  keeps its own classification.
- A file **named `.jceks` without JCEKS content**. **No detection is based on
  filename, extension, entropy, or file size**; the extension is not evidence and
  is not consulted at all.

**The finding does not prove what the store holds.** Aliases, entry types,
certificates, private keys, and secret keys all live in the entry records this
detector does not read, so the header cannot distinguish a truststore from a
private-key store, a secret-key store from either, or an empty store from a
populated one. A JCEKS finding is a container-header observation, and
HarvestGuard makes no claim beyond it.

**No password, no deserialization, no key material.** The scanner never requests
or accepts a password, never decrypts, never guesses a password, never extracts
aliases, certificates, private keys, or secret keys, never instantiates a Java
object or reads a Java serialization stream, never validates or recomputes the
keyed integrity digest, and never invokes `java`, `keytool`, or any other
external process or network service. Aliases, entry counts, entry types,
certificate subjects and issuers, the integrity digest, serialized Java content,
raw keystore bytes, and parser exception payloads are all absent from output — a
JCEKS finding carries exactly one metadata value, `Format: JCEKS`. It makes no
claim about encryption strength, decryptability, operational use, configuration
correctness, or quantum exposure. Absence of a `java_keystore:jceks` finding is
not proof that no JCEKS store exists in the target — this is one narrow rule for
one explicitly enumerated container header, not general keystore detection.

**Scanner ownership.** Crypto inventory owns `java_keystore:jceks`; the
filesystem scanner never emits it, recognizes no JCEKS structure of its own, and
`--type filesystem` is unchanged. There is therefore nothing for `--type all` to
deduplicate, and HG-037 adds no cross-scanner deduplication pairing. Accounting
is unchanged: a JCEKS file counts once in `Crypto files inspected`, contributes
nothing to `Files scanned`, and there is no JCEKS-specific count and no new
summary bucket. JSON remains a bare normalized-finding array, Markdown remains
evidence-only, CLI output and DataFrame columns are unchanged, and Streamlit
behavior is unchanged.

**No relationship output.** HG-037 adds JCEKS detection only; it creates no
[internal relationship records](CRYPTO_INVENTORY.md#internal-relationship-model-internal-only-no-output)
and emits nothing beyond the single finding described above.

#### Encrypted PKCS#8 private keys (HG-038)

A file whose content is a **complete PKCS#8 `EncryptedPrivateKeyInfo`
structure** (RFC 5958) is reported as asset type `Encrypted PKCS#8 Private Key`
(`rule_id: private_key:pkcs8_encrypted`, confidence `High`, evidence
`Encrypted PKCS#8 private-key structure detected`, technical metadata
`Format: PKCS#8` and nothing else), based solely on the outer DER structure
described below, in either DER or RFC-style PEM labelled
`ENCRYPTED PRIVATE KEY`. Like the `Salted__`, OpenPGP, age, BCFKS, and JCEKS
checks, it runs ahead of the extension-based branches — before PKCS#12 and DER
certificate parsing, and ahead of the shared candidate gate — so a valid key
saved as `key`, `key.bin`, `key.p8`, `key.pk8`, `key.key`, `key.der`, `key.crt`,
`key.cer`, `key.pem`, `key.p12`, or `key.pfx` is classified from its content
rather than missed by the gate or reported as a malformed DER certificate or
PKCS#12 container. `key.p12`/`key.pfx` in particular would otherwise be taken
terminally by `pkcs12:container`, whose candidate gate is extension-only; a real
PKCS#12/PFX file is never misclassified by this ordering because its own
top-level structure begins with a version `INTEGER`, which can never satisfy the
`AlgorithmIdentifier` this detector requires. One finding is emitted per file —
several encrypted PKCS#8 blocks in one file are one container asset at one
location — and the match is terminal: no later detector also reads that file as
PEM, DER, or PKCS#12 content.

This replaces the pre-HG-038 recognition path for this label: previously,
`BEGIN ENCRYPTED PRIVATE KEY` was reported only indirectly, by calling a
key-loading API without a password and treating the resulting password-related
failure as evidence of encryption. That exception-driven signal is gone for this
label; traditional RSA/DSA/EC labels without encryption headers, OpenSSH, and
encrypted OpenSSH keep their existing recognition paths. Traditional
`Proc-Type: 4,ENCRYPTED` blocks are owned by HG-040.

**What is detected** — the outer structure only, and only when every one of
these holds:

- **DER form:**
  - The file is a **complete DER `SEQUENCE` beginning at byte offset 0** whose
    declared length consumes the whole file with **no trailing bytes**.
    Supported bytes embedded at a nonzero offset inside a larger file are not a
    match.
  - The top-level sequence has **exactly two elements**.
  - The **first element structurally matches `AlgorithmIdentifier`**: a
    sequence whose first child is a well-formed, non-empty OBJECT IDENTIFIER,
    with at most one parameters element that is itself well-formed DER. The
    parameters value is never interpreted or reported, only confirmed to be
    validly encoded.
  - The **second element is a non-empty, primitive `OCTET STRING`** — the
    encrypted private-key bytes. A constructed `OCTET STRING`, or an empty one,
    is not a match.
  - Every length is a **well-formed, minimally encoded, definite DER length**,
    and every element's content is consumed exactly by its children. Indefinite
    and non-minimal length encodings are rejected.
- **PEM form:** an exact `-----BEGIN ENCRYPTED PRIVATE KEY-----` /
  `-----END ENCRYPTED PRIVATE KEY-----` pair — both labels present, in order,
  forming a complete block, not merely a header with no matching footer — whose
  base64 body decodes successfully under strict validation and whose decoded
  bytes satisfy every DER requirement above. A header with no footer, a
  truncated block, or an invalid base64 body produces no finding rather than a
  partial or low-confidence one.

The DER reader is the same bounded, defensive one BCFKS already uses
(`_der_read`/`_der_children`/`_der_is_algorithm_identifier`/
`_der_is_non_empty_octet_string`), reused unchanged: bounded nesting, no
indefinite-length encodings, no high-tag-number expansion, no unbounded
allocation, no recursion into the encrypted `OCTET STRING` payload, and
malformed or truncated input returns no match rather than raising. BCFKS
validation is untouched by this reuse.

**Why confidence is `High`, not `Medium`.** Unlike JCEKS's header-only claim,
the complete outer `EncryptedPrivateKeyInfo` structure is validated: exact
top-level element count, a structurally valid `AlgorithmIdentifier`, a
non-empty primitive encrypted-data `OCTET STRING`, complete DER consumption
with no trailing bytes, and complete PEM decoding when PEM-encoded. `High`
confidence applies to the **container type only**. It does not mean the
password is known, the encrypted key is decryptable, the encrypted key is
internally valid, the underlying private-key algorithm is known, or that
cryptographic strength has been assessed.

**Known false positive.** A deliberately crafted DER structure that is
syntactically a valid `EncryptedPrivateKeyInfo` — a correct outer SEQUENCE, a
well-formed `AlgorithmIdentifier`, and a non-empty OCTET STRING — but whose
`encryptedData` does not actually decrypt to a valid `PrivateKeyInfo` is still
classified as encrypted PKCS#8, because ruling that out would require
decryption. This is a deliberate, accepted limitation: the claim is structural,
not cryptographic.

**Known false negatives** — each of these produces no finding at all, and never
a lower-confidence partial finding:

- An **empty or truncated file**, or a top-level DER `SEQUENCE` with **trailing
  bytes** after it.
- A top-level sequence with **one element or three or more elements**.
- An **invalid or malformed `AlgorithmIdentifier`** — a missing or non-OID
  first element, or malformed nested parameters DER.
- A **wrong-tag or empty second element** — anything other than a non-empty
  primitive `OCTET STRING`, including a constructed `OCTET STRING`.
- **Indefinite-length or non-minimal-length DER** encodings anywhere in the
  structure.
- A structure **embedded at a nonzero offset** inside a larger file.
- Arbitrary binary that merely begins with DER-like bytes.
- A PEM block with a **header and no footer**, a **missing or empty body**, or
  an **invalid base64 body**.
- Valid base64 whose decoded DER is **not** an `EncryptedPrivateKeyInfo` — most
  notably an **unencrypted PKCS#8 `PrivateKeyInfo`** (DER or PEM
  `BEGIN PRIVATE KEY`), whose first element is a version `INTEGER`, not an
  `AlgorithmIdentifier`.
- Neighbouring formats, each of which keeps its own existing classification:
  **traditional unencrypted RSA/DSA/EC PEM private keys, encrypted OpenSSH
  private keys, PKCS#12 containers, DER certificates, and BCFKS, JCEKS, and JKS
  keystores.** Traditional `Proc-Type: 4,ENCRYPTED` PEM is owned by HG-040, not
  this rule.
- A file **named `key`, `key.p8`, `key.pk8`, `key.key`, `key.der`, `.pem`,
  `.crt`, `.cer`, `.p12`, or `.pfx` without encrypted PKCS#8 content**. **No
  detection is based on filename, extension, entropy, or file size**; the
  extension is not consulted at all, not even the shared candidate gate.
- The bare word `ENCRYPTED PRIVATE KEY` appearing in ordinary text with no
  actual PEM block around it.

**The finding does not prove what is inside the encrypted key.** The private-key
algorithm, key size, and validity all live inside `encryptedData`, which this
detector never decrypts or reads as anything but a length. An
`private_key:pkcs8_encrypted` finding is a container-structure observation, and
HarvestGuard makes no claim beyond it.

**No password, no decryption, no key material.** The scanner never requests,
accepts, reads from the environment, guesses, or derives a password or
encryption key; never decrypts `encryptedData`; never calls a private-key
load API, including merely to use its exception as the detection signal — the
recognition path this rule replaced; and never invokes `openssl`, `java`,
`keytool`, or any other external process or network service. The encryption
algorithm, KDF, cipher, salt, IV, iteration count, raw OID values, parameter
bytes, and encrypted bytes are all absent from output — a finding carries
exactly one metadata value, `Format: PKCS#8`. It also makes no claim about
encryption strength, decryptability, or confidentiality. Absence of a
`private_key:pkcs8_encrypted` finding is not proof that no encrypted PKCS#8 key
exists in the target — this is one narrow rule for one explicitly enumerated
structure, not general private-key inventory.

**Scanner ownership.** Crypto inventory owns `private_key:pkcs8_encrypted`; the
filesystem scanner never emits it, recognizes no PKCS#8 structure of its own,
and `--type filesystem` is unchanged. There is therefore nothing for
`--type all` to deduplicate, and HG-038 adds no cross-scanner deduplication
pairing. Accounting is unchanged: an encrypted PKCS#8 file counts once in
`Crypto files inspected`, contributes nothing to `Files scanned`, and there is
no PKCS#8-specific count and no new summary bucket. JSON remains a bare
normalized-finding array, Markdown remains evidence-only, CLI output and
DataFrame columns are unchanged, and Streamlit behavior is unchanged.

**No relationship output.** HG-038 adds encrypted PKCS#8 detection only; it
creates no
[internal relationship records](CRYPTO_INVENTORY.md#internal-relationship-model-internal-only-no-output)
and emits nothing beyond the single finding described above.

#### CMS / PKCS#7 encrypted objects (HG-039)

A file whose content is a **complete RFC 5652 `ContentInfo` carrying one of two
supported encrypted content types** is reported as one of:

| Content type | Asset type | Rule ID | Evidence |
| --- | --- | --- | --- |
| `EnvelopedData` | `CMS/PKCS#7 Enveloped Data` | `cms:enveloped_data` | `CMS/PKCS#7 EnvelopedData encrypted-content structure detected` |
| `EncryptedData` | `CMS/PKCS#7 Encrypted Data` | `cms:encrypted_data` | `CMS/PKCS#7 EncryptedData encrypted-content structure detected` |

Both are confidence `High` with technical metadata `Format: CMS/PKCS#7` and
nothing else. The two content types are distinguished by asset type, rule ID,
and evidence wording rather than by a new metadata field, so no existing
report or evidence-store schema changes. Both encodings are supported: binary
DER, and the RFC 7468 textual forms labelled `CMS` and `PKCS7`.

Like the `Salted__`, OpenPGP, age, BCFKS, JCEKS, and encrypted-PKCS#8 checks,
both run ahead of the extension-based branches — before extension-gated PKCS#12,
generic DER certificate parsing, and generic PEM handling, and ahead of the
shared candidate gate — so a valid object saved as `message`, `message.bin`,
`message.cms`, `message.p7m`, `message.p7e`, `message.p7b`, `message.p7c`,
`message.der`, `message.cer`, `message.crt`, `message.p12`, or `message.pfx` is
classified from its content rather than missed by the gate or reported as a
malformed DER certificate or PKCS#12 container. They run after the keystore and
encrypted-PKCS#8 detectors, whose formats a CMS `ContentInfo` cannot satisfy.
One finding is emitted per file per rule — several supported blocks of the
*same* content type in one file are one encrypted-object asset at one
location — and a match is terminal, so a claimed object is never also read as
PKCS#12, DER, or generic PEM. Terminal does not mean mutually exclusive between
the two CMS rules themselves: a single textual file can genuinely carry a
separate `EnvelopedData` block and a separate `EncryptedData` block (a binary
`ContentInfo`'s own outer content type can only be one or the other), and both
findings are preserved. The `cms:enveloped_data` detector runs first by
priority and, when it observes both supported content types in the same
structural pass, reports both findings itself — otherwise `cms:encrypted_data`
would never run for a file the earlier detector already claimed, and that
finding would be silently lost rather than reported.

**What is detected** — the outer structure only, and only when every one of
these holds:

- **Outer `ContentInfo`:**
  - a **complete DER `SEQUENCE` beginning at byte offset 0** whose declared
    length consumes the whole file (or the whole decoded textual body) with **no
    trailing bytes**; a supported object embedded at a nonzero offset inside a
    larger binary file is not a match;
  - **exactly two children**;
  - the first child is a **structurally valid OBJECT IDENTIFIER** whose value is
    **exactly** `id-envelopedData` or `id-encryptedData`;
  - the second child is a **constructed context-specific `[0]`** wrapper — the
    explicit CMS content wrapper — holding **exactly one** element, which is a
    `SEQUENCE`.
- **`EnvelopedData`:** a minimally encoded INTEGER version; an optional
  context-specific `[0]` `originatorInfo`; a required **non-empty constructed
  SET** of `recipientInfos`; a required `EncryptedContentInfo`; an optional
  context-specific `[1]` unprotected-attributes field; and nothing else. The
  recipient infos are checked for presence and well-formedness only and are
  never decoded.
- **`EncryptedData`:** a minimally encoded INTEGER CMS version — **0** when
  unprotected attributes are absent and **2** when they are present; a required
  `EncryptedContentInfo`; an optional context-specific `[1]`
  unprotected-attributes field; and nothing else.
- **`EncryptedContentInfo`** (both rules): a `SEQUENCE` of exactly a structurally
  valid content-type OBJECT IDENTIFIER, a structurally valid
  `AlgorithmIdentifier`, and a **present, non-empty context-specific `[0]`
  encrypted content**. A fourth or later child is not a match.
- **Textual form:** an exact `-----BEGIN CMS-----`/`-----END CMS-----` or
  `-----BEGIN PKCS7-----`/`-----END PKCS7-----` pair — both boundaries present
  as exact lines, with matching labels, forming a complete block — whose base64
  body decodes under strict validation and whose decoded bytes satisfy every
  structural requirement above. LF and CRLF line endings are both supported, and
  explanatory text on separate lines is ignored. A header with no matching
  footer, a mismatched label, a prefix or suffix on a boundary line, an empty
  body, or invalid base64 produces no finding rather than a partial one.

The DER reader is the same bounded, defensive one BCFKS and encrypted PKCS#8
already use, reused unchanged: definite, minimally encoded lengths only, bounded
nesting, no high-tag-number expansion, no unbounded allocation, no recursion
into the encrypted content, and malformed or truncated input returns no match
rather than raising. No general BER engine, general CMS parser, or new ASN.1
dependency is introduced, and BCFKS/JCEKS/JKS/encrypted-PKCS#8 behavior is
untouched.

**Certificate-only and signed objects are separated, not matched.** A PKCS#7
certificate bundle (degenerate `SignedData`), an ordinary CMS `SignedData`, a
CMS `Data` object, and any other valid `ContentInfo` whose content OID is not
one of the two supported values produce **no** HG-039 finding: `id-data`,
`id-signedData`, `id-digestedData`, and `id-authenticatedData` are never treated
as encryption evidence. The `CMS` or `PKCS7` textual label alone is never
evidence either — the decoded body must still pass the full structural check.

**Why confidence is `High`.** The complete supported `ContentInfo` structure is
validated, including the exact outer content-type OID, the explicit `[0]`
wrapper, the content-type-specific field sequence, and a present, non-empty
`encryptedContent`. `High` applies to the **object structure only**. It does not
mean the object is decryptable, that any recipient is valid or reachable, that
any signature or certificate was checked, that the payload is still
operationally relevant, or that any algorithm was assessed.

**Known false positive.** A syntactically valid supported CMS structure whose
`encryptedContent` holds arbitrary non-empty bytes still matches, because
proving those bytes decrypt correctly would require keys and decryption. The
claim is structural, not cryptographic.

**Known false negatives** — each produces no finding at all, never a
lower-confidence partial finding:

- **BER indefinite-length or streaming CMS** outside the supported
  definite-length subset. The reader is deliberately DER-oriented and is not
  weakened to accept it.
- **Detached or absent `encryptedContent`** — an object whose ciphertext lives
  elsewhere. HarvestGuard saw no encrypted bytes, so it claims none.
- **Malformed-but-tolerated encodings** outside the strict subset: non-minimal
  lengths, high-tag-number forms, a constructed (chunked) `encryptedContent`, or
  content whose children do not exactly consume their parent.
- **Unsupported CMS content types**, notably `AuthEnvelopedData`, as well as
  `SignedData`, `Data`, `DigestedData`, and `AuthenticatedData`.
- An **empty or truncated object**, **trailing bytes** after the outer
  `SEQUENCE`, or a supported object **embedded at a nonzero offset** inside a
  larger binary file.
- A **missing, primitive, empty, or multi-child `[0]` content wrapper**, or a
  wrapper whose inner element is not a `SEQUENCE`.
- An **unsupported, truncated, or malformed outer OID**.
- A structurally invalid field: a missing or non-minimal version, an
  `EncryptedData` version that does not match the presence of unprotected
  attributes, an empty or non-SET `recipientInfos`, a malformed
  `AlgorithmIdentifier`, an empty `encryptedContent`, or an unexpected trailing
  child.
- A file **named `message.p7m`, `.p7e`, `.p7b`, `.p7c`, `.cms`, `.der`, `.cer`,
  `.crt`, `.p12`, or `.pfx` without supported CMS content**. **No detection is
  based on filename, extension, entropy, or file size**; the extension is not
  consulted at all, not even the shared candidate gate.
- Neighbouring formats, each of which keeps its own existing classification:
  **DER certificates, PKCS#12 containers, encrypted PKCS#8 private keys, PEM
  certificates and keys, and BCFKS, JCEKS, and JKS keystores.**

**No decryption, no secrets, no identities.** The scanner never requests or
accepts a password, private key, secret key, or recipient certificate; never
reads secret material from the environment; never decrypts a content-encryption
key or a payload; never verifies a signature; never validates a recipient
certificate or chain; performs no S/MIME policy evaluation; invokes `openssl` or
any other external process at runtime; and makes no network call. Recipient
identities, issuer and serial numbers, subject key identifiers, encrypted
content-encryption keys, KEK and password-recipient details, originator
certificates, unprotected attributes, signer information, content-type and
algorithm OIDs, cipher/KDF names and parameters, key sizes, salts, IVs and
nonces, raw ASN.1 fragments, ciphertext bytes, and plaintext are all absent from
findings, normalized findings, JSON, Markdown, evidence-store records, and
scanner errors — a finding carries exactly one metadata value,
`Format: CMS/PKCS#7`. Absence of a `cms:enveloped_data` or `cms:encrypted_data`
finding is not proof that no CMS encrypted object exists in the target: these
are two narrow rules for two explicitly enumerated structures, not general CMS
inventory.

**Scanner ownership.** Crypto inventory owns both rules; the filesystem scanner
never emits them, recognizes no CMS structure of its own, and `--type
filesystem` is unchanged. There is therefore nothing for `--type all` to
deduplicate, and HG-039 adds no cross-scanner deduplication pairing. Accounting
is unchanged: a CMS object counts once in `Crypto files inspected`, contributes
nothing to `Files scanned`, and there is no CMS-specific count and no new
summary bucket. JSON remains a bare normalized-finding array, Markdown remains
evidence-only, CLI output and DataFrame columns are unchanged, and Streamlit
behavior is unchanged.

**No relationship output.** HG-039 adds CMS/PKCS#7 encrypted-object detection
only; it creates no
[internal relationship records](CRYPTO_INVENTORY.md#internal-relationship-model-internal-only-no-output)
and emits nothing beyond the single finding described above.

#### Encrypted legacy PEM private keys (HG-040)

A file whose content contains a **complete traditional PEM private-key block**
labelled `RSA PRIVATE KEY`, `DSA PRIVATE KEY`, or `EC PRIVATE KEY` that declares
the legacy OpenSSL encryption headers is reported as asset type
`Encrypted Legacy PEM Private Key` (`rule_id: private_key:legacy_pem_encrypted`,
confidence `High`, evidence `Legacy PEM encrypted private-key structure detected`,
technical metadata `Format: Legacy PEM` and nothing else).

**What is detected** — only when every one of these holds:

- Exact `-----BEGIN <label>-----` and matching `-----END <label>-----` boundary
  lines (LF or CRLF). Prefix or suffix contamination on boundary lines is
  rejected.
- Both encryption headers in the header area before the base64 body:
  - `Proc-Type: 4,ENCRYPTED` (exactly one occurrence; wrong version or status
    rejected)
  - `DEK-Info: <cipher>,<hex-IV>` with a non-empty cipher token, exactly one
    comma, and a non-empty even-length hexadecimal IV (duplicate/conflicting
    headers, empty tokens, non-hex or odd-length IV rejected)
- A non-empty body that strict-base64-decodes to non-empty ciphertext bytes

The detector is **non-terminal** and runs at priority 48 (after CMS, ahead of
extension-gated PKCS#12) so a traditional encrypted PEM key saved as `key.p12`
or `key.pfx` is classified from its content rather than as a malformed PKCS#12.
One finding is emitted per file for this rule even when multiple same-type
blocks are present. A file may still also report a certificate PEM or other
non-terminal PEM asset.

This replaces the pre-HG-040 exception-driven path for these blocks: previously
a passwordless key-load failure was treated as evidence of encryption. That
path is no longer used for traditional `Proc-Type` blocks.

**What is not detected**

- Encrypted PKCS#8 (`BEGIN ENCRYPTED PRIVATE KEY`) — owned exclusively by
  HG-038 / `private_key:pkcs8_encrypted`
- Unencrypted traditional RSA/DSA/EC PEM, unencrypted PKCS#8, OpenSSH private
  keys, certificates, public keys
- `Proc-Type` or `DEK-Info` text outside a complete supported private-key block
- Extension alone (`.pem`, `.key`, `.p12`, etc.) without valid content
- Malformed headers, missing/invalid base64 body, mismatched BEGIN/END labels

**The finding does not prove the key decrypts or is valid.** Cipher name, IV,
passphrase state, underlying algorithm, key size, and ciphertext are never
reported. High confidence applies to the legacy encrypted-PEM *container*
evidence only.

**No password, no decryption, no external process.** The scanner never requests,
accepts, reads from the environment, guesses, or derives a password; never
decrypts the body; never calls a private-key load API for classification; and
never invokes OpenSSL or any other external process at runtime.

**No relationship output.** HG-040 adds legacy encrypted PEM detection only; it
creates no internal relationship records and emits nothing beyond the single
finding described above.

### Confidence semantics

`confidence` varies per parse outcome, not per file:

- `High` — a certificate or key was fully parsed and its cryptographic
  properties extracted, or an encrypted PEM/OpenSSH private key block was
  positively identified by its header (algorithm/key-size may still be
  unavailable without a passphrase), or an OpenSSL `Salted__` header, a
  supported OpenPGP encrypted-session-key packet structure, a supported
  native age v1 header structure, or a supported BCFKS `ObjectStore` container
  structure was directly
  observed in the file's content (a signature or structure match, not a
  parse of the protected content — `High` here describes the certainty of the
  byte-level observation, not anything about the encryption's strength or
  recoverability). An `Encrypted File` finding is never emitted at any other
  confidence level: if the observation is not direct, there is no finding.
- `Medium` — a JKS magic header matched, or a JCEKS top-level header matched
  (HG-037: the container header and a plausible top-level structure were
  observed, but the store was not authenticated and its entries were not
  parsed), or an OpenSSH private key's block
  was found but could not be loaded (an inconsistency with the PEM path,
  where an encrypted PEM key is `High`; both are documented, unvalidated
  differences in this MVP scanner, not a claim that Medium is more or less
  reliable in a measured sense).
- `Low` — a candidate block was found (PEM certificate, DER file extension,
  PKCS#12 extension, SSH public-key prefix) but parsing failed, reported as a
  `Malformed ...` asset type with the parser's error message in `errors`.

### What this scanner can miss

- **The candidate-file gate is a silent pre-filter.** A file is inspected if
  it begins with the OpenSSL `Salted__` signature (HG-030), a supported OpenPGP
  encrypted-file structure (HG-031), the native age v1 version line
  (HG-035), a supported BCFKS `ObjectStore` container (HG-036), or the JCEKS
  top-level header (HG-037), all checked ahead of the gate;
  otherwise `_could_contain_crypto_asset` requires it to have a recognized
  extension (`.cer`, `.crt`, `.der`, `.jks`, `.p12`, `.pfx`), start with an SSH
  public-key prefix, match the JKS magic header, or contain the literal bytes
  `-----BEGIN ` somewhere in its first 5 MB. **A file that matches none of
  these produces no finding and no limitation record at all** — unlike the
  filesystem scanner, there is no explicit "not inspected" marker for
  gate-excluded files. An empty crypto-inventory result does not distinguish
  "no crypto assets present" from "assets present in a format or extension
  this gate does not recognize." `Salted__`, the supported OpenPGP shapes,
  native age v1 files, supported BCFKS stores, and JCEKS stores are now
  recognized and no longer examples of this gap,
  but every other encrypted-container format (LUKS, encrypted
  ZIP/PDF/Office, armored age files, the OpenPGP, age, BCFKS, and JCEKS
  structures listed as unsupported above, and any signature not listed
  above)
  remains outside this gate for the crypto-inventory scanner specifically —
  HG-030, HG-031, HG-035, HG-036, and HG-037 added exactly five named detection
  rules, not general encrypted-file or keystore detection.
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
