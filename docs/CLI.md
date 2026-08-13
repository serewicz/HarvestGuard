# HarvestGuard CLI

HarvestGuard's unified CLI runs the same scanners as the dashboard through the
normalized finding model. It does not add storage, dashboard functionality,
risk scoring, or executive reporting.

## Installation

### Requirements

**Python 3.10 or newer.** Check before anything else:

```bash
python3 --version
```

On macOS the system interpreter (`/usr/bin/python3`) is **Python 3.9.6, which is
too old** — HarvestGuard will not install or run on it, and upgrading the system
Python is neither necessary nor recommended. Install a current Python (for
example `brew install python@3.12`, or a python.org installer) and build the
virtual environment from that interpreter instead:

```bash
python3.12 -m venv venv          # macOS: not /usr/bin/python3
source venv/bin/activate
python -m pip install .
```

### Install the CLI

From a clean virtual environment, in a checkout of this repository, one command
is enough:

```bash
git clone https://github.com/serewicz/HarvestGuard.git
cd HarvestGuard

python3 -m venv venv
source venv/bin/activate         # venv\Scripts\activate on Windows

python -m pip install .
```

That installs the `harvestguard` command **and everything it needs**.
`pyproject.toml` declares the CLI's runtime dependencies, so there is no second
`pip install -r requirements.txt` step: `requirements.txt` is repository-root
convenience for running the Streamlit dashboard from a checkout, and
`requirements-dev.txt` is for contributors running the tests and linter. A
normal user needs neither.

Confirm the install:

```bash
harvestguard --version           # e.g. "harvestguard 0.1.0"
```

Contributors who want their edits to take effect without reinstalling use an
editable install instead — same dependencies, same command:

```bash
python -m pip install -e .
```

### What to expect during installation

`pip` may print long runs of repeated "Downloading …" / "INFO: pip is looking at
multiple versions of …" messages while it resolves the Semgrep and
OpenTelemetry dependency graph. That backtracking is **normal**, can take
several minutes on a cold cache, and is not a hang. What is *not* normal is pip
finishing with an error, a `ResolutionImpossible`, or a nonzero exit code —
those are real failures, and the install did not succeed no matter how much
output scrolled past first.

### Running the CLI

Once installed, `harvestguard` works from **any** directory, not just the
repository root:

```bash
cd ~
harvestguard scan /path/to/target --type filesystem --summary
```

The install covers the CLI and the scanners only. The Streamlit dashboard is
run from the repository root with `streamlit run main.py` (after
`pip install -r requirements.txt`) and is deliberately not part of the installed
package.

Without installing the console script at all, run the same CLI as a module from
the repository root:

```bash
python -m harvestguard scan ./target
```

Both paths run the same code. To confirm either one works before you trust its
output, see [Validating an install end to end](#validating-an-install-end-to-end).

## Usage

```bash
harvestguard [--version]
harvestguard scan <target> [--type <type>] [--max-depth N] [--prefix <prefix>] \
    [--summary] [--json [PATH]] [--markdown [PATH]] [--quiet] \
    [--exclude <pattern>] [--fail-on-error | --no-fail-on-error] \
    [--evidence-db PATH]
harvestguard evidence list --evidence-db PATH
harvestguard evidence verify <scan-id> --evidence-db PATH
harvestguard evidence export <scan-id> --evidence-db PATH \
    (--json [PATH] | --markdown [PATH] | --summary) [--quiet]
```

`<target>` is a local file or directory path for local scan types, a bucket
name for `s3`/`gcs`, or `account-name/container-name` for `azure`.

`--version` (or `-V`) prints the HarvestGuard version and exits — the same
version a Markdown report records in its *Scan Information* table, so an
artifact can be traced back to the release that produced it. `--json` output
carries no version field: it stays a bare finding array. See
[docs/RELEASE.md](RELEASE.md#identifying-the-version-that-produced-an-artifact).

### Scan types

`--type` selects which scanner runs (default `all`):

| `--type`         | Target                          | Scanner                                     |
| ---------------- | ------------------------------- | ------------------------------------------- |
| `all` (default)  | local path                      | every local scanner below                   |
| `filesystem`     | local path                      | local filesystem encryption evidence        |
| `crypto`         | local path                      | cryptographic asset inventory               |
| `sensitive-data` | local path                      | sensitive-data category detection           |
| `code`           | local path                      | local Semgrep crypto code analysis (Python source only) |
| `s3`             | bucket name                     | AWS S3 object encryption status             |
| `gcs`            | bucket name                     | GCS object encryption status                |
| `azure`          | `account-name/container-name`   | Azure Blob encryption status                |

`--max-depth` bounds directory recursion for `filesystem` and `sensitive-data`
scans (and the `all` bundle), and **defaults to `3`** — a scan run without an
explicit `--max-depth` is bounded configured scope from the start, not unlimited
recursion, and the report's *Scope* section records the bound that applied.
`--prefix` restricts cloud scans to a key or blob prefix. Each option is ignored
by scan types it does not apply to.

`--type code` matches source **text** only, and the vendored rule set
(`code_analysis/rules/crypto.yaml`) currently declares `languages: [python]`,
so equivalent weak-crypto usage in another language produces no finding. There
is no binary, bytecode, runtime, or network/TLS discovery. See
[DETECTION_CHARACTERIZATION.md](DETECTION_CHARACTERIZATION.md).

#### OpenSSL encrypted-file evidence (HG-030)

A file whose leading bytes are `Salted__` — the header `openssl enc -salt`
writes — is cryptographic evidence, and the crypto-inventory scanner owns it:
a `--type crypto` (or `--type all`) scan reports it as asset type
`Encrypted File`, `rule_id: encrypted_file:openssl`, confidence `High`, with
evidence text limited to the observed signature (never a claim about
decryptability, password/key/algorithm, or encryption strength). Detection is
based on the file's actual content, evaluated before any extension-based
parsing, so a `Salted__` file saved with a misleading extension (e.g.
`secret.p12` or `secret.der`) is still reported as `Encrypted File`, not
routed into PKCS#12/DER parsing and reported as malformed.

The filesystem scanner also recognizes this same signature independently, as
it always has (`--type filesystem`, `rule_id: file_signature:file_level_openssl`,
asset type `file`, `Encryption: File-level (OpenSSL)`) — that behavior is
unchanged. When both scanners run together (`--type all`), the same file is
never reported twice: the crypto-inventory finding is the one that survives
in the combined output, and the filesystem scanner's record for that same
file is excluded. This dedup is deterministic and does not depend on which
scanner happened to run first.

`Files scanned` keeps its existing meaning (inspected regular files, from the
filesystem scanner's own activity — see below) and correctly reads `0` for a
pure `--type crypto` run, since the crypto-inventory scanner is not the
filesystem scanner. That is expected, not a bug. A separate, additive
`Crypto files inspected` line (console: `Crypto files inspected: N`;
Markdown: a `Crypto Files Inspected` row in *Scan Information*) reports how
many files the crypto-inventory scanner actually visited and opened —
including files that matched no recognized shape and produced no finding —
whenever that scanner ran. It is never arithmetically merged, reconciled, or
deduplicated against `Files scanned`, even when both scanners inspect the
same files under `--type all`.

As with every crypto-inventory finding, the absence of an `Encrypted File`
finding is not proof no encrypted files exist: the scanner's other
candidate-gate limitations (see
[DETECTION_CHARACTERIZATION.md](DETECTION_CHARACTERIZATION.md#local-cryptographic-asset-inventory))
still apply to every signature this issue did not add — only the exact
`Salted__` OpenSSL header is recognized by *this* rule (OpenPGP/GPG and age are
covered separately, below), not LUKS, encrypted ZIP, or any other
encrypted-container format.

#### OpenPGP/GPG encrypted-file evidence (HG-031)

A file whose leading OpenPGP packet is a supported encrypted-session-key
packet — what `gpg --symmetric` and `gpg --encrypt` write, in binary form or
inside `-----BEGIN PGP MESSAGE-----` ASCII armor — is cryptographic evidence,
and the crypto-inventory scanner owns it: a `--type crypto` (or `--type all`)
scan reports it as asset type `Encrypted File`,
`rule_id: encrypted_file:openpgp`, confidence `High`. Confidence is `High`
only because the packet structure was read directly out of the file; an
`Encrypted File` finding is never emitted on weaker grounds. Evidence text
names just the observed structure (packet tag, version, and the algorithm
identifier the packet itself declares) and never claims decryptability,
encryption strength, or complete OpenPGP support. As with the `Salted__`
check, content is evaluated before any extension-based parsing.

The scanner does **not** decrypt, prompt for or accept a passphrase, name the
recipient of a public-key encrypted file, verify signatures, or shell out to
`gpg`.

Supported and unsupported OpenPGP shapes are enumerated in
[DETECTION_CHARACTERIZATION.md](DETECTION_CHARACTERIZATION.md#openpgpgpg-encrypted-files-hg-031).
Two boundaries matter when reading output: **coverage is partial** (v6/AEAD
packets and several other real OpenPGP forms produce no finding), and
**signed-only material is not encrypted-file evidence** — clearsigned
messages, `gpg --armor --sign` output, detached signatures, and public/private
key blocks are deliberately not reported as encrypted files.

The filesystem scanner independently recognizes a narrower set of the same
shapes, as it always has (`--type filesystem`,
`rule_id: file_signature:file_level_pgp_gpg`, asset type `file`,
`Encryption: File-level (PGP/GPG)`) — that behavior is unchanged, including
for a `MESSAGE`-armored file the crypto scanner does not claim. When both
scanners run together (`--type all`), the same file is never reported twice:
the crypto-inventory finding is the one that survives, and the filesystem
record for that same file is excluded. As with HG-030, the dedup is
deterministic and independent of which scanner ran first.

`Files scanned` and `Crypto files inspected` keep exactly the meanings
described above; this rule changes neither, and the two are still never
merged or reconciled against each other.

Absence of an `encrypted_file:openpgp` finding is not proof that no encrypted
OpenPGP files exist in the target.

#### age encrypted-file evidence (HG-035)

A **native age v1** encrypted file — one whose content begins with the
`age-encryption.org/v1` version line and follows the format's own header
grammar — is cryptographic evidence, and the crypto-inventory scanner owns it:
a `--type crypto` (or `--type all`) scan reports it as asset type
`Encrypted File`, `rule_id: encrypted_file:age`, confidence `High`, with
evidence text limited to `Observed age encrypted file.` One finding is emitted
per valid supported file, and as with the `Salted__` and OpenPGP checks, content
is evaluated before any extension-based parsing, so valid age content saved as
`secret.p12` is still reported as `Encrypted File`. Confidence is `High` only
because the header structure was read directly out of the file.

**Support is narrow and explicit.** Only the native format is recognized:
the exact version line at byte offset 0, one or more structurally valid
recipient stanzas, a header MAC line of exactly `--- ` plus 43
unpadded-base64 characters, LF line endings, and an encrypted payload of at
least 32 bytes immediately after the header. **ASCII-armored age files
(`-----BEGIN AGE ENCRYPTED FILE-----`) are not supported in HG-035**, nor are
other age versions, CRLF native headers, or malformed/truncated age-like
content — each produces no finding rather than a lower-confidence guess, and
nothing is inferred from a filename, a `.age` extension, or entropy. The full
supported/unsupported enumeration is in
[DETECTION_CHARACTERIZATION.md](DETECTION_CHARACTERIZATION.md#age-encrypted-files-hg-035).

The scanner does **not** decrypt, prompt for or accept a passphrase or identity
file, read a keyring or SSH agent, resolve or name recipients, or shell out to
`age`. Recipient types and arguments, stanza bodies, the header MAC, and the
encrypted payload never appear in output — an age finding carries no technical
metadata at all — and no claim is made about encryption strength,
decryptability, or who holds a key.

The filesystem scanner independently recognizes the leading bytes
`age-encryption.org/v1` as a broader, prefix-only signature, as it always has
(`--type filesystem`, `rule_id: file_signature:file_level_age`, asset type
`file`, `Encryption: File-level (age)`). That behavior is unchanged, and HG-035
adds no dedup pairing for age: under `--type all`, that separate filesystem
record still appears alongside the one crypto-inventory `Encrypted File`
finding. `Files scanned` and `Crypto files inspected` keep exactly the meanings
described above — an age file counts once in `Crypto files inspected`, and no
age-specific count or summary bucket was added.

Absence of an `encrypted_file:age` finding is not proof that no age-encrypted
content exists in the target — this is one narrow detection rule for one
explicitly enumerated on-disk shape, not general encrypted-file detection.

#### BCFKS keystore evidence (HG-036)

A file whose content is a **supported Bouncy Castle BCFKS `ObjectStore`** is
cryptographic evidence, and the crypto-inventory scanner owns it: a
`--type crypto` (or `--type all`) scan reports it as asset type
`Java Keystore`, `rule_id: java_keystore:bcfks`, confidence `High`, with
evidence text limited to `Observed supported BCFKS keystore structure.` and
technical metadata limited to `Format: BCFKS`. One finding is emitted per
supported file, and as with the `Salted__`, OpenPGP, and age checks, content is
evaluated before any extension-based parsing — so a valid store saved as
`truststore.p12`, `certs.der`, `keystore.jks`, or with no extension at all is
reported as `Java Keystore` rather than as a malformed PKCS#12, DER
certificate, or JKS keystore. Confidence is `High` only because the container
structure was read directly out of the file.

**Support is narrow and explicit.** Only the default encrypted object store the
Bouncy Castle provider writes is recognized: a complete DER `SEQUENCE` at byte
offset 0 consuming the whole file, holding exactly an `EncryptedObjectStoreData`
(an `AlgorithmIdentifier` plus a non-empty encrypted-content `OCTET STRING`) and
a `PbkdMacIntegrityCheck` (a MAC `AlgorithmIdentifier`, a key-derivation-function
identifier, and a non-empty MAC `OCTET STRING`). **Unencrypted `ObjectStoreData`
stores and signature-integrity (`[0] SignatureCheck`) stores are not supported**,
nor are truncated, corrupted, embedded, or near-match ASN.1
structures — each produces no finding rather than a lower-confidence guess, and
nothing is inferred from a filename, a `.bcfks` extension, entropy, or file
size. The full supported/unsupported enumeration is in
[DETECTION_CHARACTERIZATION.md](DETECTION_CHARACTERIZATION.md#bcfks-keystore-containers-hg-036).

**The finding does not prove truststore versus keystore.** Aliases, entry types,
certificates, and keys live inside the encrypted store data, which is never
read. The scanner does **not** decrypt, prompt for or validate a password,
enumerate entries, inspect contained certificates or keys, or shell out to
Java, `keytool`, Bouncy Castle, or OpenSSL. Aliases, entry counts, certificate
subjects, key identifiers, encrypted content, MAC values, salts, IVs, KDF
parameters, and raw ASN.1 fragments never appear in output.

The filesystem scanner recognizes no BCFKS structure, so `--type filesystem` is
unchanged and there is nothing for `--type all` to deduplicate — the one
crypto-inventory finding appears alongside whatever unrelated filesystem context
and coverage records exist for the same target. `Files scanned` and `Crypto
files inspected` keep exactly the meanings described above: a BCFKS file counts
once in `Crypto files inspected`, and no BCFKS-specific count or summary bucket
was added.

Absence of a `java_keystore:bcfks` finding is not proof that no BCFKS store
exists in the target — this is one narrow detection rule for one explicitly
enumerated container shape, not general keystore detection.

JCEKS is a **separate detector with its own identity** (see below), not part of
this rule.

#### JCEKS keystore evidence (HG-037)

A file carrying the **JCEKS top-level header** is cryptographic evidence, and the
crypto-inventory scanner owns it: a `--type crypto` (or `--type all`) scan
reports it as asset type `Java Keystore`, `rule_id: java_keystore:jceks`,
confidence `Medium`, with evidence text limited to
`JCEKS keystore header detected` and technical metadata limited to
`Format: JCEKS`. One finding is emitted per file, and as with the `Salted__`,
OpenPGP, age, and BCFKS checks, content is evaluated before any extension-based
parsing — so a valid store saved as `store`, `store.bin`, `truststore.p12`,
`certs.der`, or `keystore.jks` is reported as `Java Keystore` rather than being
missed or reported as a malformed PKCS#12 or DER certificate.

**Support is narrow and explicit.** Recognized from the header OpenJDK's
`JceKeyStore` writes: the big-endian magic `ce ce ce ce` at offset 0, a format
version of 1 or 2, a nonnegative entry count, and a file at least large enough
for that 12-byte header plus the 20-byte trailing keyed digest. A missing,
truncated, near-match, or offset magic, an unsupported version, a negative entry
count, and a file below the structural minimum each produce no finding, and
nothing is inferred from a filename, a `.jceks` extension, entropy, or file size.

**Confidence is `Medium`, not `High`,** because the header and plausible
top-level structure were observed but the store was not authenticated and its
entries were not parsed: no password is requested or accepted, the keyed digest
is neither verified nor reported, no alias, certificate, private key, or secret
key is read, no Java serialized object is deserialized, and `java`, `keytool`,
and every other external process are never invoked. A JCEKS finding therefore
makes no truststore-versus-keystore claim, and absence of a
`java_keystore:jceks` finding is not proof that no JCEKS store exists in the
target. The full supported/unsupported enumeration is in
[DETECTION_CHARACTERIZATION.md](DETECTION_CHARACTERIZATION.md#jceks-keystore-containers-hg-037).

The filesystem scanner recognizes no JCEKS structure, so `--type filesystem` is
unchanged and there is nothing for `--type all` to deduplicate. A JCEKS file
counts once in `Crypto files inspected`, and no JCEKS-specific count or summary
bucket was added.

#### Encrypted PKCS#8 private-key evidence (HG-038)

A file whose content is a complete PKCS#8 `EncryptedPrivateKeyInfo` is
cryptographic evidence, and the crypto-inventory scanner owns it: a
`--type crypto` (or `--type all`) scan reports it as asset type
`Encrypted PKCS#8 Private Key`, `rule_id: private_key:pkcs8_encrypted`,
confidence `High`, with evidence text limited to
`Encrypted PKCS#8 private-key structure detected` and technical metadata limited
to `Format: PKCS#8`. One finding is emitted per file — a file holding several
encrypted PKCS#8 blocks is one container asset at one location — and as with the
`Salted__`, OpenPGP, age, BCFKS, and JCEKS checks, content is evaluated before
any extension-based parsing, so a valid key saved as `key`, `key.bin`, `key.p8`,
`key.pk8`, `key.key`, `key.der`, `key.crt`, `key.cer`, `key.pem`, `key.p12`, or
`key.pfx` is reported as an encrypted PKCS#8 key rather than being missed or
reported as a malformed DER certificate or PKCS#12 container. Content wins over
extension, and an extension alone never produces this finding.

**Support is narrow and explicit.** Both encodings of the same structure share
one detector identity:

- **DER** — a `SEQUENCE` beginning at byte offset 0, consuming the entire file
  with no trailing bytes, containing exactly two elements: a structurally valid
  `AlgorithmIdentifier` and a non-empty *primitive* `OCTET STRING`. All lengths
  must be definite, minimally encoded, and in bounds.
- **PEM** — an exact `-----BEGIN ENCRYPTED PRIVATE KEY-----` /
  `-----END ENCRYPTED PRIVATE KEY-----` pair with a complete base64 body that
  decodes and satisfies the DER requirements above.

An empty or truncated file, trailing bytes, one or three top-level elements, a
malformed `AlgorithmIdentifier`, a missing algorithm OID, malformed parameters, a
wrong second-element tag, an empty encrypted-data `OCTET STRING`, a constructed
`OCTET STRING`, an indefinite or non-minimal length, a structure embedded at a
nonzero offset, a PEM header with no footer, and an invalid base64 body each
produce no finding. Neither does an unencrypted PKCS#8 key, a traditional
RSA/DSA/EC PEM key, a legacy `Proc-Type: 4,ENCRYPTED` encrypted PEM key, an
encrypted OpenSSH key, a PKCS#12 file, a DER certificate, or a BCFKS, JCEKS, or
JKS store — each keeps its own existing classification.

**Nothing is decrypted and no password is involved.** The claim is established
from the structure alone, before any decryption-capable operation would be
necessary: no password is prompted for, accepted, read from an environment
variable, guessed, or derived; a private-key load API is never called — not even
to use its password-related exception as the detection signal, which is the
recognition path this rule replaced; and `openssl`, `java`, `keytool`, and every
other external process are never invoked.

**`High` confidence applies to the container type only.** It does not mean the
password is known, the key is decryptable, the key is internally valid, the
underlying private-key algorithm is known, or that cryptographic strength was
assessed. The outer `AlgorithmIdentifier` is validated as well-formed DER and
then discarded: no PBES/PBKDF/scrypt/cipher/hash name, salt, IV, nonce,
iteration count, key length, OID, parameter byte, or encrypted byte appears in
any finding, report, or stored record. Absence of a
`private_key:pkcs8_encrypted` finding is not proof that no encrypted PKCS#8 key
exists in the target. The full supported/unsupported enumeration is in
[DETECTION_CHARACTERIZATION.md](DETECTION_CHARACTERIZATION.md#encrypted-pkcs8-private-keys-hg-038).

The filesystem scanner recognizes no PKCS#8 structure, so `--type filesystem` is
unchanged and there is nothing for `--type all` to deduplicate. An encrypted
PKCS#8 file counts once in `Crypto files inspected`, and no PKCS#8-specific count
or summary bucket was added.

#### CMS / PKCS#7 encrypted-object evidence (HG-039)

A file whose content is a complete RFC 5652 `ContentInfo` carrying one of two
supported encrypted content types is cryptographic evidence, and the
crypto-inventory scanner owns it. A `--type crypto` (or `--type all`) scan
reports it as either or both of:

- asset type `CMS/PKCS#7 Enveloped Data`, `rule_id: cms:enveloped_data`,
  evidence `CMS/PKCS#7 EnvelopedData encrypted-content structure detected`;
- asset type `CMS/PKCS#7 Encrypted Data`, `rule_id: cms:encrypted_data`,
  evidence `CMS/PKCS#7 EncryptedData encrypted-content structure detected`.

A binary file's outer `ContentInfo` can only carry one content type, so it
produces at most one of these; a textual file can carry a separate block of
each, and both findings are reported for it. Both are confidence `High` with
technical metadata limited to `Format: CMS/PKCS#7`. One finding is emitted per
file per rule — several supported blocks of the *same* content type in one
file are one encrypted-object asset at one location — and as with the
`Salted__`, OpenPGP, age, BCFKS, JCEKS, and encrypted-PKCS#8 checks,
content is evaluated before any extension-based parsing, so a valid object saved
as `message`, `message.bin`, `message.cms`, `message.p7m`, `message.p7e`,
`message.p7b`, `message.p7c`, `message.der`, `message.cer`, `message.crt`,
`message.p12`, or `message.pfx` is reported as the CMS object it is rather than
being missed or reported as a malformed DER certificate or PKCS#12 container.
Content wins over extension, and an extension alone never produces this finding.

**Support is narrow and explicit.** Both encodings share the same structural
requirements:

- **Binary DER** — a `SEQUENCE` beginning at byte offset 0 and consuming the
  entire file with no trailing bytes, holding exactly a content-type OBJECT
  IDENTIFIER that is exactly `id-envelopedData` or `id-encryptedData` and a
  constructed `[0]` wrapper containing exactly one inner `SEQUENCE`. All lengths
  must be definite, minimally encoded, and in bounds.
- **Textual** — an exact `-----BEGIN CMS-----`/`-----END CMS-----` or
  `-----BEGIN PKCS7-----`/`-----END PKCS7-----` pair with matching labels and a
  complete base64 body that decodes and satisfies the requirements above. LF and
  CRLF are both supported; explanatory text on separate lines is ignored.

Inside the wrapper, `EnvelopedData` must carry a minimally encoded version, a
non-empty `recipientInfos` SET, and an `EncryptedContentInfo`, with
`originatorInfo` and unprotected attributes permitted; `EncryptedData` must
carry the CMS version RFC 5652 fixes for the unprotected attributes present and
an `EncryptedContentInfo`. In both cases `EncryptedContentInfo` must hold a
content-type OID, a structurally valid `AlgorithmIdentifier`, and a **present,
non-empty** `[0]` encrypted content.

**Certificate-only and signed PKCS#7/CMS bundles are separated, not matched.** A
PKCS#7 certificate bundle, a degenerate or ordinary `SignedData`, a CMS `Data`
object, and any other content type — `id-digestedData` and `id-authenticatedData`
included — produce no finding, and the `CMS`/`PKCS7` label alone is never
evidence. Neither is a truncated object, trailing bytes, an object embedded at a
nonzero offset, a missing or malformed `[0]` wrapper, an indefinite-length (BER)
or non-minimal encoding, a malformed `AlgorithmIdentifier`, an empty
`recipientInfos`, or an absent, detached, or empty `encryptedContent`. A DER
certificate, PKCS#12 file, encrypted PKCS#8 key, or BCFKS, JCEKS, or JKS store
keeps its own existing classification.

**Nothing is decrypted and no secret is involved.** The claim is established from
the structure alone: no password, private key, secret key, or recipient
certificate is prompted for, accepted, or read from an environment variable; no
content-encryption key or payload is decrypted; no signature is verified and no
recipient certificate or chain is validated; no S/MIME policy is evaluated; and
`openssl` and every other external process are never invoked at runtime.

**`High` confidence applies to the object structure only.** It does not mean the
object is decryptable, that any recipient is valid or reachable, that any
signature or certificate was checked, or that any algorithm was assessed — a
syntactically valid supported structure whose `encryptedContent` holds arbitrary
non-empty bytes still matches. No recipient identity, issuer or serial number,
subject key identifier, encrypted content-encryption key, originator identity,
unprotected attribute, signer information, OID, cipher/KDF name, parameter,
salt, IV, nonce, key size, raw ASN.1 fragment, or ciphertext byte appears in any
finding, report, or stored record. Absence of a `cms:enveloped_data` or
`cms:encrypted_data` finding is not proof that no CMS encrypted object exists in
the target. The full supported/unsupported enumeration is in
[DETECTION_CHARACTERIZATION.md](DETECTION_CHARACTERIZATION.md#cms--pkcs7-encrypted-objects-hg-039).

The filesystem scanner recognizes no CMS structure, so `--type filesystem` is
unchanged and there is nothing for `--type all` to deduplicate. A CMS object
counts once in `Crypto files inspected`, and no CMS-specific count or summary
bucket was added.

#### Encrypted legacy PEM private-key evidence (HG-040)

A file whose content contains a complete traditional PEM private-key block
(`RSA PRIVATE KEY`, `DSA PRIVATE KEY`, or `EC PRIVATE KEY`) that declares
`Proc-Type: 4,ENCRYPTED` and a syntactically valid `DEK-Info: <cipher>,<hex-IV>`
header with a non-empty strict-base64 body is cryptographic evidence, and the
crypto-inventory scanner owns it. A `--type crypto` (or `--type all`) scan
reports it as asset type `Encrypted Legacy PEM Private Key`,
`rule_id: private_key:legacy_pem_encrypted`, confidence `High`, with evidence
`Legacy PEM encrypted private-key structure detected` and technical metadata
limited to `Format: Legacy PEM`. One finding is emitted per file for this rule.
The detector is non-terminal so a file may also report a certificate PEM or
other coexisting PEM asset. It runs after certificate PEM and before generic
private-key PEM, without changing PKCS#12, encrypted PKCS#8, or CMS behavior.
Encrypted PKCS#8 (`BEGIN ENCRYPTED PRIVATE KEY`) remains HG-038.

**Support is narrow and explicit.** Exact BEGIN/END boundaries are required
(prefix/suffix contamination rejected; LF and CRLF accepted). Both encryption
headers must be present and valid; the body must strict-base64-decode to
non-empty ciphertext. No password is requested, accepted, read, or guessed; no
decryption occurs; no private-key load API or external process is used. Cipher
name, IV, and ciphertext never appear in findings or reports. The full
supported/unsupported enumeration is in
[DETECTION_CHARACTERIZATION.md](DETECTION_CHARACTERIZATION.md#encrypted-legacy-pem-private-keys-hg-040).

#### gocryptfs encrypted-filesystem evidence (HG-032)

A directory containing both a supported `gocryptfs.conf` and a root-level
`gocryptfs.diriv` — the two on-disk markers a standard `gocryptfs -init`
cipher root always has — is encrypted-filesystem evidence, and the
crypto-inventory scanner owns it: a `--type crypto` (or `--type all`) scan
reports the *root directory* as asset type `Encrypted Filesystem`,
`rule_id: encrypted_filesystem:gocryptfs`, confidence `High`, with evidence
text limited to the observed root structure
(`Observed supported gocryptfs cipher-root structure.`) — never a claim about
decryption, password/key availability, mounted-state, or configuration
correctness. This is a *container*-level finding, not a per-file one: a root
with hundreds of ciphertext files still produces exactly one finding, for the
root directory, and ordinary ciphertext files, encrypted subdirectories,
nested `gocryptfs.diriv` files, and long-name sidecars inside it never
produce their own findings. A directory that independently contains its own
complete, valid `gocryptfs.conf`/`gocryptfs.diriv` pair nested inside another
cipher root is a separate root and produces its own separate finding.

**Support is narrow and explicit.** Only standard gocryptfs **forward mode**
is recognized, and only config format version `2` (the version gocryptfs has
used since v1.2) is treated as supported — an unrecognized version produces
no finding rather than an unverified guess. `gocryptfs.conf` must decode as a
JSON object carrying the stable fields every forward-mode config has
(`Version`, `FeatureFlags`, `EncryptedKey`, `ScryptObject`), and must not have
`PlaintextNames` set in `FeatureFlags` (a materially different, unsupported
mode where filenames are stored unencrypted). **Reverse mode is unsupported**
and is excluded structurally rather than by a config content check: a
gocryptfs.conf carries no "this is reverse mode" field at all (forward and
reverse configs are the same JSON shape), but reverse mode never writes a
`gocryptfs.diriv` to disk anywhere — its "cipher view" is computed live from
the plaintext side — so requiring a root-level `gocryptfs.diriv` (already
mandatory) is what rejects it. Missing either marker, an empty or malformed
config, an unsupported version, `PlaintextNames`, or a `gocryptfs.conf`
copied somewhere with no root `gocryptfs.diriv` of its own all produce no
finding — HG-032 has exactly one behavior for every unsupported/partial case
(no finding), never a lower-confidence partial finding. See
[DETECTION_CHARACTERIZATION.md](DETECTION_CHARACTERIZATION.md#gocryptfs-encrypted-filesystem-hg-032)
for the full supported/unsupported enumeration.

The **cipher root is not the same thing as a mounted, plaintext-visible
gocryptfs directory** — HG-032 detects only the on-disk cipher root; it does
not mount, unlock, decrypt, or correlate a mounted view back to its cipher
root. The scanner never reads `EncryptedKey`, `ScryptObject`, or any other
config value beyond what is needed to confirm a supported forward-mode root,
and none of that is included in output — reported `technical_metadata` is
limited to the format name (`gocryptfs`), the observed config version, and
the mode (`forward`).

A validated root finding may still be emitted when traversal beneath the root
is incomplete (a permission failure or unreadable subdirectory, for example);
confidence describes only the root-structure observation, not completeness of
what lies beneath it. HG-032 does not report an aggregate ciphertext or
subdirectory count at all, so no such count is ever claimed as complete or
incomplete — existing scanner-error and finding-limitation behavior for an
actual read or traversal failure is unchanged.

The filesystem scanner does not recognize gocryptfs structure at all (neither
`gocryptfs.conf` nor `gocryptfs.diriv` matches any filesystem-scanner
signature), so there is nothing for `--type all` to deduplicate here — the one
crypto-inventory root finding simply appears alongside whatever aggregate
filesystem context and coverage records the filesystem scanner produced for
the same target, which are unrelated evidence and are not removed.

`Files scanned` and `Crypto files inspected` keep exactly the meanings
described above. Absence of an `encrypted_filesystem:gocryptfs` finding is not
proof that no gocryptfs cipher root exists in the target — this is one narrow
detection rule for one specific, well-defined on-disk shape, not general
encrypted-filesystem or FUSE coverage.

Cloud scans use the provider SDK's default credential resolution (for example
`AWS_PROFILE`/instance role for S3, application-default credentials for GCS,
`DefaultAzureCredential` for Azure). The CLI does not read, prompt for, or
store credentials itself.

## Examples

Default summary (all local scanners):

```bash
harvestguard scan ./target
```

Example output:

```text
HarvestGuard Scan Complete

Files scanned: 412

Record Categories

Aggregate filesystem context records: 3
Per-file filesystem evidence records: 6
Coverage limitation records: 0
Skipped or inaccessible entry records: 2
Cryptographic inventory records: 18
Sensitive-data records: 7
Code-analysis records: 4
Cloud storage records: 0

Findings

Certificates: 18
Private Keys: 5
Encrypted Keys: 1
SSH Keys: 2
PKCS#12: 1
Expired Certificates: 2
Sensitive Files: 7
Semgrep Findings: 4
Malformed Assets: 1
Errors: 0

Material evidence records: 35
Total normalized records: 40
Findings with finding-level errors: 0
Scanner execution errors: 0
```

`Files scanned` counts inspected regular files, not records: an ordinary
readable file with no file-level evidence and no file-specific failure
produces no record of its own, and is represented by its mount's aggregate
`filesystem_context` record instead (one per mount actually scanned) rather
than one record per file. `Total normalized records` is named for exactly
what it counts — it is not a count of distinct material findings, which is
what `Material evidence records` states instead. See [What Each Scanner Can
Miss](#what-each-scanner-can-miss) and
[DETECTION_CHARACTERIZATION.md](DETECTION_CHARACTERIZATION.md) for what each
record category means.

JSON normalized findings:

```bash
harvestguard scan ./target --json --quiet
```

Write JSON normalized findings to a file:

```bash
harvestguard scan ./target --json findings.json --quiet
```

Markdown report:

```bash
harvestguard scan ./target --markdown --exclude "vendor/*"
```

Write a professional Markdown evidence report:

```bash
harvestguard scan ./target --markdown report.md --exclude "vendor/*"
```

Scan a single local scan type with a bounded depth:

```bash
harvestguard scan ./target --type sensitive-data --max-depth 4 --json findings.json
```

Scan an AWS S3 bucket (uses AWS SDK default credentials):

```bash
harvestguard scan my-bucket --type s3 --prefix data/ --json --quiet
```

Scan a GCS bucket:

```bash
harvestguard scan my-bucket --type gcs --json --quiet
```

Scan an Azure Blob container:

```bash
harvestguard scan my-account/my-container --type azure --json --quiet
```

The Markdown report's sections are listed under
[Markdown output](#markdown-output).

## Demo Walkthrough

`demo/sample_target/` (GitHub issue [#18](https://github.com/serewicz/HarvestGuard/issues/18),
roadmap [HG-006](ROADMAP.md)) is a small, deterministic fixture so anyone can
see real HarvestGuard output without scanning real confidential data.

**All values in the fixture are synthetic and intentionally fake.** Do not
copy anything from it into a real `.env` file or substitute real credentials
or sensitive data into it. It exists only so the scanners have something
evidence-shaped to find, and its contents are documented in full in
[`demo/sample_target/sensitive/leaked_config.env`](../demo/sample_target/sensitive/leaked_config.env)'s
own header comment. It requires no credentials and no network access.

Run every local scanner against it:

```bash
harvestguard scan demo/sample_target --type all --summary
```

Expected output (files scanned and finding counts are deterministic; see
"What varies by host" below for the one platform-dependent field):

```text
HarvestGuard Scan Complete

Files scanned: 1

Record Categories

Aggregate filesystem context records: 1
Per-file filesystem evidence records: 0
Coverage limitation records: 0
Skipped or inaccessible entry records: 0
Cryptographic inventory records: 1
Sensitive-data records: 1
Code-analysis records: 0
Cloud storage records: 0

Findings

Certificates: 0
Private Keys: 1
Encrypted Keys: 0
SSH Keys: 0
PKCS#12: 0
Expired Certificates: 0
Sensitive Files: 1
Semgrep Findings: 0
Malformed Assets: 1
Errors: 1

Material evidence records: 2
Total normalized records: 3
Findings with finding-level errors: 1
Scanner execution errors: 0
```

Three normalized records, one from each of three scanners:

- **Filesystem context** (`--type filesystem`) — `leaked_config.env` is an
  ordinary file with no file-level encrypted-format signature and no
  file-specific failure, so it produces no record of its own. It is
  represented instead by one aggregate `filesystem_context` finding for the
  demo fixture's mount, with `Evidence` starting `"Volume-level encryption
  status observed for mount <path>: <value>"` (or, if the status could not be
  determined on your host, `"...could not be determined for mount
  <path>..."`), a populated `Confidence` (`Medium` or `Low`) plus
  `Confidence Rationale`, and `technical_metadata["Files Represented By This
  Context"] == 1`. The exact `<value>` and confidence level depend on how
  encryption status was determined on your host (see "What varies by host"
  below) — this is expected, not a bug. See [Design: Aggregate Filesystem
  Context](DETECTION_CHARACTERIZATION.md#local-filesystem-encryption-evidence)
  for why ordinary files are represented this way.
- **Cryptographic inventory evidence** (`--type crypto`) — one finding, asset
  type `Malformed PEM Private Key`, confidence `Low`. The fixture's PEM
  header (`-----BEGIN RSA PRIVATE KEY-----`) is real enough to be detected as
  a PEM block, but its body is plain fake text, not valid base64/DER, so
  parsing correctly fails. The `errors` field is non-empty and names the
  parse failure; `technical_metadata` (algorithm, key size, fingerprint,
  etc.) stays unset because parsing never succeeded. This is the intended,
  deterministic outcome for this fixture, not a scanner defect.
- **Sensitive-data categories** (`--type sensitive-data`) — one finding for
  `leaked_config.env` with `Categories: Email, Generic Secret, Private Key`.
  `Slack Token`, `GitHub Token`, and `AWS Access Key` do **not** appear: the
  fixture's Slack/GitHub/AWS-shaped lines are deliberately inert (they do not
  match those services' real credential formats), specifically so nothing
  committed to this repository can be mistaken for a live credential by
  GitHub push protection or any other scanner. Category names and counts are
  reported; the matched sensitive text itself is never included in output.

JSON (machine-readable, same normalized finding schema as
[NORMALIZED_FINDINGS.md](NORMALIZED_FINDINGS.md)):

```bash
harvestguard scan demo/sample_target --type all --json --quiet
```

Markdown (professional evidence report):

```bash
harvestguard scan demo/sample_target --type all --markdown --quiet
```

Both report exactly the same three findings as structured evidence records
(`Detailed Findings` in the Markdown report) — never the raw matched
sensitive value, the fixture's fake password, or its fake PEM body text, only
category names, counts, and evidence-layer fields such as confidence and
rule ID.

### What varies by host

Encryption status for an ordinary file with no matching file-level signature
falls back to volume-level encryption status, recorded on the mount's
aggregate `filesystem_context` finding rather than a per-file one. That
status is detected differently per platform (FileVault on macOS,
`lsblk`/similar on Linux) and is not deterministic across environments — CI
and your local machine may report a different value or a different
confidence level for that one field.
This is expected: `docs/TERMINOLOGY.md` documents this as evidence quality
that depends on what could be observed, not a claim that HarvestGuard can
always determine full-disk or volume encryption status the same way on every
supported platform. Every other field described above is fixed, since it
depends only on the fixture's unchanging content.

### Reading the results

Per [docs/TERMINOLOGY.md](TERMINOLOGY.md): everything the demo scan reports
above is **observed evidence** (encryption status, confidence, sensitive-data
categories, PEM parse errors) — direct scanner output about what the fixture
contains, not a business conclusion. The demo does not exercise the
dashboard's **Risk Score** or **HNDL Exposure** fields, which the same
terminology document marks as inferred heuristics (`Needs Validation`) and
which must never be read as measured facts. Nothing in this walkthrough is a
complete quantum-readiness assessment; it is a small, fixed evidence sample
for seeing real output.

## Validating an Install End to End

Everything below is exercised automatically by
`tests/test_end_to_end_validation.py` (roadmap HG-008), which runs the same
documented commands: a real `pip install .` and `pip install -e .` of this
repository into a throwaway virtual environment whose installed `harvestguard`
console script is then invoked from outside the checkout, the demo fixture, a
representative non-demo target built at runtime, and S3/GCS/Azure scans faked at
the provider SDK boundary only. Run
`pytest -v tests/test_end_to_end_validation.py` to check an environment, or walk
the steps yourself:

1. **Install and invoke.** `pip install -e .` then `harvestguard scan
   demo/sample_target --type all --summary` (or `python -m harvestguard scan
   demo/sample_target --type all --summary` without installing). Expect exit
   code `0` and the summary shown in [Demo Walkthrough](#demo-walkthrough).
   Progress lines (`Running filesystem scanner...`) go to stderr, so stdout is
   safe to pipe.
2. **Demo artifacts.** Add `--json findings.json` and `--markdown report.md`.
   Expect three findings in the JSON array and every section listed under
   [Markdown output](#markdown-output) in the report.
3. **A representative target.** Point the same commands at a real repository or
   directory (`harvestguard scan /path/to/repo --type all --json findings.json`).
   Nothing about the output shape depends on the demo fixture. Individual scan
   types are worth running on their own too: `--type crypto` for certificate and
   key inventory, `--type code` for Semgrep crypto findings, `--type
   sensitive-data` for category counts.
4. **Cloud targets.** `--type s3`, `--type gcs`, and `--type azure` need working
   provider credentials from that SDK's own default chain (HarvestGuard never
   prompts for or stores them). A successful cloud scan with no `--prefix`
   reports `Coverage: No limits recorded`.
5. **Read the coverage status.** Use the table below to tell a complete scan
   from a limited, partial, or failed one. This is the only thing you need in
   order to interpret an artifact — no source-code reading required.

Two further test modules cover the installation itself rather than the scan
behavior. `tests/test_clean_install.py` performs both documented installs into a
virtual environment created **without** `--system-site-packages` and installed
**without** `--no-deps`, then runs `--version`, a filesystem summary scan, JSON,
and Markdown from outside the checkout — so a dependency that is only present
because the host happened to have it cannot make those checks pass. They
download real packages; set `HARVESTGUARD_SKIP_CLEAN_INSTALL_TESTS=1` to skip
them when working offline. `tests/test_packaging_dependencies.py` is the offline
counterpart: it fails if a packaged module imports something `pyproject.toml`
does not declare, or if `pyproject.toml` and `requirements.txt` drift apart.

### Reading coverage from an artifact

| What happened | Exit code | Markdown `Coverage` row | Other evidence in the artifact |
| --- | --- | --- | --- |
| **Complete** — the configured scope was processed, nothing was skipped | `0` | `No limits recorded` | *Errors and Warnings* says no scanner errors, finding-level errors, or limitations were reported |
| **Limited** — you configured `--prefix`, `--exclude`, or a depth bound the scanner does not enumerate | `0` | `Bounded by configured scan scope` | *Scope* lists each configured constraint; `--exclude` also appears in *Scan Information* |
| **Limited with enumerated boundaries** — a filesystem `--max-depth` boundary, unreadable directory, or skipped special file | `0` | `Not complete` | "Coverage was not complete: … N finding(s) with recorded limitations", a `max_depth_boundary`/`directory_traversal_error`/`skipped_special_file` count, and **no** `Scanner error:` line |
| **Partial** — findings were collected, then a provider, credential, or traversal failure stopped the scan | `1` | `Not complete` | The collected findings are still listed in *Detailed Findings*, and a `- Scanner error:` line names the failure |
| **Failed** — a scanner errored before producing anything | `1` | `Not complete` | A `- Scanner error:` line, plus a *Scanner Versions* row for that scanner with a finding count of `0`, so it is never silently dropped |

A `--type code` execution failure is the one case this table does not cover: it
exits `0`, reports `Coverage` as if nothing constrained the scan, and shows a
code-analysis *Scanner Versions* row with `0` findings that is indistinguishable
from a genuinely clean result. Its diagnostic appears on stderr only. See
[Exit Codes](#exit-codes).

A per-finding `errors` entry is a different thing from a scanner failure: it
records an observation that partly failed (an unparsable PEM, a JKS entry the
current scanner cannot read, an encrypted key whose metadata needs a
passphrase). The scan still exits `0`, and the `Coverage` row does not change;
the fact is reported as "Finding-level errors are listed in Detailed Findings"
in *Errors and Warnings*, with the reason in that finding's `Errors` column (and
its `errors` array in JSON). Read those two places, not just the `Coverage` row,
before treating a scan as clean.

With `--json`, the same distinctions come from the exit code, the stderr
messages, and each finding's `limitations` and `errors` arrays; scan-level
scanner errors are deliberately not part of the JSON array (see
[JSON output shape](#json-output-shape)).

## Local Evidence Store

Every `harvestguard scan` generates one UUID **scan ID** before the scanners
run. Every normalized finding that run emits carries it, and a Markdown report
records it in the *Scan Information* table as `Scan ID`. The scan ID does not
participate in `finding_id` generation, so stable finding identity is
unchanged; JSON output stays a bare finding array with the run identity in each
element's existing `scan_id` field.

By default the scan is otherwise ephemeral: when the process exits, nothing is
retained. `--evidence-db PATH` opts in to storing the run in a local SQLite
database, creating it if it does not exist:

```bash
harvestguard scan ./project --type crypto --json report.json \
    --evidence-db ./evidence.db
```

The record is written in one transaction before any report output is emitted,
and contains the scan context (target, scan time, duration, scan type, selected
scanners, scanner versions, exclusions, scope constraints, scanner errors,
crypto-file accounting, and the HarvestGuard version that executed the scan)
plus one immutable serialized snapshot of every retained finding. A run that
failed partway through is still a valid record: its partial findings and its
scanner errors are stored together.

There is no default database path and no retention policy — HarvestGuard never
stores evidence unless you pass `--evidence-db`.

### Reading stored runs back

```bash
harvestguard evidence list --evidence-db ./evidence.db
harvestguard evidence verify <scan-id> --evidence-db ./evidence.db
harvestguard evidence export <scan-id> --evidence-db ./evidence.db --json report.json
harvestguard evidence export <scan-id> --evidence-db ./evidence.db --markdown report.md
harvestguard evidence export <scan-id> --evidence-db ./evidence.db --summary
```

`evidence list` prints one row per stored run — scan ID, scan time, scan type,
target, finding count, and whether scanner errors were recorded. It is the way
to find a **zero-finding run**: such a run is a complete, meaningful evidence
record, but its bare-array JSON is empty and therefore carries no finding-level
scan ID to look it up by.

`evidence export` re-emits a stored run through the same JSON, Markdown, and
console-summary formatters a live scan uses, without rescanning the target. The
original scan context, scanner errors, scope constraints, scanner versions, and
finding snapshots are the ones that were stored, not values recomputed from
today's code. For the same HarvestGuard release, an immediate stored JSON
export of a run persisted with `--evidence-db` is byte-identical to that run's
live JSON output aside from the trailing newline. Across releases, note that
the `HarvestGuard Version` a stored run recorded is the release that *executed*
the scan, which may differ from the release performing a later export. A stored
Markdown export reports the executing release in that row and, when the
exporting release differs, adds an `Exported By` row naming the release that
rendered the document; the separate `Report Generator` row remains the report
format's own identity. A future report-format change may alter the Markdown
while the stored evidence is unchanged.

The store is append-only: there is no update, delete, or purge command, and
storing a scan ID that already exists fails instead of replacing prior
evidence. To remove stored evidence, delete the database file yourself.

### Integrity verification

Each stored run carries a SHA-256 digest over its canonical scan context and
its ordered finding snapshots. `evidence verify` recomputes that digest, and
every `evidence export` verifies before emitting anything. A mismatch is
reported on stderr and exits `1`; the inconsistent payload is never printed as
though it had been verified.

**What this does and does not mean.** The digest detects corruption or internal
inconsistency — a truncated write, a damaged file, an edited row. It is not a
signature, not an attestation, not tamper-proof, and not a chain of custody:
anyone who can write to the SQLite file can change the stored data and the
stored digest together. Signing and external timestamping are deliberately out
of scope.

### The database is a sensitive evidence artifact

The database retains exactly what HarvestGuard already reports — and that is
confidential: file paths, cloud object names, certificate subjects and issuers,
technical ownership signals such as uid/gid/mode, scanner error text, and the
scan target. It never stores raw matched sensitive-data values, plaintext, file
contents, key material, ciphertext, passphrases, cloud credentials or tokens,
environment variables, or raw provider exception objects — the same redaction
rules that govern reporting govern storage.

The database is **not encrypted at rest**. Treat the file with the same care as
a Markdown or JSON evidence artifact: store it where the underlying scan
results themselves would be allowed to live, and apply your own filesystem
permissions, volume encryption, or secure deletion as your engagement requires.

## Exit Codes

- `0`: scan completed without scanner-level failures.
- `1`: at least one scanner failed, but other recoverable scanner results were
  returned. Suppress with `--no-fail-on-error` to exit `0` in this case.
- `2`: invalid CLI usage, such as an unknown `--type`, a negative `--max-depth`,
  a malformed Azure target, or a local path that does not exist.

Evidence-store failures use the same `1`/`2` split. A failure to write the
store, an unreadable or unsupported database, an unknown scan ID, and a failed
integrity check are all execution failures (`1`), reported on stderr; a missing
`--evidence-db` or an unknown subcommand is invalid usage (`2`).

Two ordering guarantees follow from persisting before emitting output:

- if persistence fails, the requested in-memory output is still emitted, the
  error goes to stderr only (so `--json` stdout stays parseable), the run is
  never reported as stored, and the command exits `1`;
- if persistence succeeds but writing a `--json PATH` / `--markdown PATH` file
  then fails, the command still exits `1`, but the stored run remains complete
  and retrievable with `harvestguard evidence export`.

Exit code `2` always means invalid input, and `1` always means a scan
execution failure, so automation can branch on the difference.

**One documented exception to `1`:** a `--type code` *execution* failure —
`semgrep` not installed, timed out, exiting non-zero, or emitting output that
cannot be parsed — writes its diagnostic to stderr and returns an empty result
instead of raising. It is therefore not recorded as a scanner error, and the run
exits `0` with no findings, unlike an equivalent S3/GCS/Azure failure. Read
stderr, not just the exit code, before treating an empty code-analysis result as
"the source was analyzed and nothing matched". This asymmetry is characterized
in [DETECTION_CHARACTERIZATION.md](DETECTION_CHARACTERIZATION.md#source-code-crypto-analysis)
and tracked as a separate scanner-error-propagation concern in
[CLAIMS_AUDIT.md](CLAIMS_AUDIT.md#identified-for-a-separate-issue); HG-010 did
not change the behavior.

A scope you asked for is not a failure: a cloud `--prefix`, an `--exclude`
pattern, or a `--max-depth` boundary still exits `0`. Boundaries the filesystem
scanner knows about are reported as explicit findings instead; see
[Partial and limited scans](#partial-and-limited-scans) for which constraints
produce findings and which are reported only as scope.

## Scan Coverage and Partial Results

[SCAN_COVERAGE.md](SCAN_COVERAGE.md) documents what "complete" means for a
scan, `--max-depth` depth semantics and boundary findings, S3 pagination and
prefix behavior, GCS/Azure SDK iterator behavior, cloud provider/auth/API
failure handling, and how partial findings are preserved alongside a nonzero
exit code.

In short: when a scanner fails partway through, the findings it already
collected are still emitted, the failure is still reported, and the exit code is
still `1`. Reports and JSON that record scanner errors or limitation findings
must not be read as proof of complete coverage.

## What Each Scanner Can Miss

Coverage semantics answer "was the configured scope processed?"
[DETECTION_CHARACTERIZATION.md](DETECTION_CHARACTERIZATION.md) answers the
other half: for each scan type above, what evidence that scanner actually
supports, what formats and inputs it does not recognize, its likely
false-positive and false-negative conditions, what its `confidence` value
means, and when a clean result must not be read as proof that no cryptographic
asset, sensitive data, weak crypto usage, or encryption gap exists. Read it
before treating any `--type` result as complete.

## Output Notes

### JSON output shape

`--json` emits a **JSON array of normalized findings** — one serialized
[NORMALIZED_FINDINGS.md](NORMALIZED_FINDINGS.md) record per array element, with
the schema unchanged. It is not a report envelope: there is no wrapper object,
and scan-level run metadata is not part of the array. Each element preserves
`schema_version`, `finding_id`, provenance fields (`scanner_name`,
`scanner_version`, `collection_method`, `collection_source`, `rule_id`,
`observed_at`, `repeatable`, `verification_rationale`), `evidence`,
`confidence`, `confidence_rationale`, `ownership_signals`, `unknowns`,
`limitations`, `errors`, and `technical_metadata`, serialized as plain JSON
objects, arrays, and scalars.

Scan-level scanner errors are deliberately outside that array. They are
reported through stderr, the exit code (see [Exit Codes](#exit-codes)), and the
Markdown report's *Errors and Warnings* section. Even when a scanner fails
partway through, `--json` stdout stays valid, machine-readable JSON containing
the findings collected before the failure; progress and failure messages never
mix into stdout.

With `--json PATH` the same JSON is written to `PATH`; with `--quiet` stdout
stays empty.

### Markdown output

`--markdown` emits a human-readable **evidence report** generated locally,
suitable for attaching to an issue, email, or advisory note. Its major sections
are stable:

- Executive Summary — evidence counts and scan context only
- Scan Information — scan time, the HarvestGuard version that produced the
  report, report generator/version, target, duration, files scanned, excluded
  paths, coverage status
- Scanner Versions — scanner name, version, and finding count, listing every
  scanner the run invoked; a scanner that produced no findings, or that failed
  before producing any, still appears with its version and a count of `0`
- Scope — target, scan type, the scanners that actually ran for that scan
  type, and the scope constraints that bounded the run
- Findings Summary
- Finding Breakdown by Type
- Detailed Findings — per finding: location, asset type, the scanner name and
  version that produced it, when it was collected (`observed_at`), observed
  technical metadata, confidence, observed evidence, unknowns, limitations, and
  finding-level errors
- Errors and Warnings — scanner errors and coverage-limitation counts by type
- Known Limitations
- Appendix — normalized schema version and schema-preservation note

The report is evidence-only. It does not provide a risk score, HNDL exposure,
remediation advice or priority, business impact, ownership conclusions,
recommendations, compliance conclusions, quantum-readiness conclusions, or an
executive priority score. "Executive Summary" here means a concise summary of
what was observed, not an executive assessment. See
[TERMINOLOGY.md](TERMINOLOGY.md) for the evidence-versus-inference vocabulary.

The Scope section reports only the scanners the selected `--type` actually
ran — a `--type filesystem` or `--type s3` report never claims the other
scanners ran — together with the constraints those scanners honored
(`--max-depth` for `filesystem`/`sensitive-data`, `--prefix` for cloud scans,
and any `--exclude` patterns).

With `--markdown PATH` the report is written to `PATH`; with `--quiet` stdout
stays empty. Both `--json` and `--markdown` produce deterministic output apart
from genuinely volatile values (scan time, duration, and the host-dependent
fields noted above): findings are ordered by asset type, then location, then
finding ID, in both outputs.

PDF and HTML reports, hosted report sharing, and a JSON report envelope with
run metadata are not implemented; see [ROADMAP.md](ROADMAP.md).

### Partial and limited scans

A scope you configured (`--max-depth`, `--prefix`, `--exclude`) is not a
failure, but it does bound coverage. How each constraint is represented differs,
and the report distinguishes them:

- `--max-depth` produces explicit limitation findings **in the filesystem
  scanner only** (`--type filesystem`, and the filesystem pass of `--type
  all`). A directory past the configured depth is reported as a
  `max_depth_boundary` finding with a populated `limitations` field, alongside
  the `directory_traversal_error` and `skipped_special_file` findings the
  filesystem scanner records for entries it could not read or could not safely
  inspect.
- `--type sensitive-data` honors the same depth boundary — it inspects files in
  directories up to and including the configured depth — but does **not** emit
  boundary findings of its own: content below the boundary is skipped without a
  `max_depth_boundary` record. In a `--type all` run the filesystem pass still
  records the boundary directories. In a `--type sensitive-data` run the depth
  constraint is visible only in the report's *Scope* section, so read that
  section, not the absence of limitation findings, as the statement of how far
  a sensitive-data scan reached.
- `--prefix` and `--exclude` do **not** produce limitation findings.
  A cloud prefix narrows what the provider is asked to list, and an exclude
  pattern drops matching findings from output; in neither case does the scanner
  enumerate what it skipped. These constraints are visible in the report's
  *Scope* section (and `--exclude` in *Scan Information*), not as per-finding
  `limitations`.

Uninspected scope is never counted as a scanned file. When any scanner error or
limitation finding exists, the Markdown report states that coverage was not
complete and repeats that absence of a finding is not evidence that an asset was
inspected and found clean. When no error or limitation finding exists but a
scope constraint was configured, *Scan Information* reports coverage as
`Bounded by configured scan scope` rather than as unlimited; only a run with no
recorded constraint, error, or limitation reports `No limits recorded`. See
[SCAN_COVERAGE.md](SCAN_COVERAGE.md) for the full coverage semantics.

### Handling report output

Report generation is entirely local. HarvestGuard does not send findings or
reports to any external service, and it does not persist raw file contents.
Sensitive-data findings report category names and counts only — never the
matched values.

Even so, **treat generated reports as potentially sensitive artifacts**. File
paths, object and blob keys, bucket and container names, certificate subjects
and issuers, usernames, and other ownership signals can each be sensitive on
their own, and a report aggregates them. Store, transmit, and share
`findings.json` and `report.md` with the same care as the environment they
describe.

Provider credentials always come from each cloud SDK's own default credential
resolution. HarvestGuard does not manage, store, or emit credentials, and
provider error text is sanitized before it appears in output.
