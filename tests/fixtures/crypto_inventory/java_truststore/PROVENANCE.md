# Java trusted-certificate-only store fixture provenance (HG-042)

Fixtures for HG-042, which classifies a JKS or JCEKS store whose **complete
declared entry table** holds only supported trusted-certificate entries. The
asset type HG-042 emits is `Java Trusted-Certificate-Only Store`, a structural
observation. Nothing here — and nothing in the detector — establishes that any
application uses these stores for trust decisions.

Two kinds of file live in this directory:

- **Tool-generated stores.** Real keystores written by OpenJDK's own `keytool`.
  HG-042's positive version-2 coverage does not rest on bytes a test invented.
- **Byte-constructed version-1 stores.** No `keytool` available here writes a
  version-1 store, so the two v1 fixtures are assembled field-by-field from
  OpenJDK's own version-1 load grammar (documented below) around a **real**
  `keytool`-generated DER X.509 certificate. Their construction is recorded
  exactly so it can be re-derived rather than trusted.

These are disposable test artifacts. The private key and self-signed
certificates inside them were generated here, exist only to give the stores
realistic content, and protect nothing — no production key, certificate, or
passphrase is involved. The store passwords are recorded below **only so the
fixtures can be regenerated**. HarvestGuard never reads them: HG-042 requires no
password, accepts none, and never unlocks, decrypts, deserializes, or verifies
any of these files. It reads the container header, the declared entry records,
and the file's own length, nothing else.

The distinguished names and aliases below are deliberately recognizable so the
privacy tests in `tests/test_java_truststore_detection.py` can use them as
canaries and prove they never reach a finding, a DataFrame, a JSON or Markdown
report, or an evidence-store record.

## Generation environment

- **Java:** OpenJDK 17.0.20 (Temurin-17.0.20+8)
- **Tool:** the `keytool` shipped with that JDK
- **Providers:** the JDK's built-in `SUN` `JKS` and `SunJCE` `JceKeyStore`
  implementations (no third-party provider JAR is involved)

`keytool` prints a "proprietary format" migration warning for `-storetype JKS`
and `-storetype JCEKS` on this JDK; that warning is expected and does not affect
the bytes written. This JDK writes **version 2** stores only.

## Shared certificate material

Two throwaway RSA 2048 self-signed certificates, generated first and reused by
everything below so the fixtures stay small and comparable:

```
keytool -genkeypair -alias k1 -keyalg RSA -keysize 2048 \
    -dname "CN=HarvestGuard JKS Test" -validity 3650 \
    -storetype JKS -keystore private_key_store.jks \
    -storepass password123 -keypass password123
keytool -exportcert -alias k1 -storetype JKS \
    -keystore private_key_store.jks -storepass password123 -file cert.der

keytool -genkeypair -alias k2 -keyalg RSA -keysize 2048 \
    -dname "CN=HarvestGuard JKS Test Two" -validity 3650 \
    -storetype JKS -keystore tmp2.jks \
    -storepass password123 -keypass password123
keytool -exportcert -alias k2 -storetype JKS \
    -keystore tmp2.jks -storepass password123 -file cert2.der
```

- `cert.der` — 743 bytes, SHA-256
  `008ecefdb8b3424053784526526201bbc341a1ec0cf2e37326e30732c380b621`
- `cert2.der` — 752 bytes, SHA-256
  `dea41b2ceebf5fefa455cf814fe57f99e3a806d6b7a517823374649860443322`

Neither `cert.der`, `cert2.der`, nor `tmp2.jks` is committed: they are
intermediates, and every byte of `cert.der` that matters is already inside the
committed fixtures.

## Tool-generated fixtures

Every store below is written through the provider's own
`engineStore(OutputStream, char[])`, which emits the format magic
(`0xfeedfeed` for JKS, `0xcececece` for JCEKS), format version `2`, a big-endian
entry count, the serialized entry records, and a trailing keyed SHA-1 digest.

### `trusted_certificate_store.jks`

- **Contents at generation time:** one trusted-certificate entry (alias
  `trusted1`), no private key — the canonical HG-042 JKS v2 positive
- **Store password:** `trustpass456`
- **Size:** 808 bytes
- **SHA-256:**
  `6731d3b5b6d486f7939ab3610e9f53fa75f00eb0aa07b719f31e827aada645b4`
- **Command:**

  ```
  keytool -importcert -noprompt -alias trusted1 -file cert.der \
      -storetype JKS -keystore trusted_certificate_store.jks \
      -storepass trustpass456
  ```

### `multi_trusted_certificate_store.jks`

- **Contents at generation time:** two trusted-certificate entries (aliases
  `trusted1` and `trusted2`, two distinct certificates). Committed to prove
  HG-042 examines the *complete* entry table and still emits exactly one finding
  per file location regardless of entry count.
- **Store password:** `trustpass456`
- **Size:** 1593 bytes
- **SHA-256:**
  `300c4fdadc0ba58a47e51c9a3f545fdf5e5030588256b4f1ca9fa5e84c80ae18`
- **Commands:**

  ```
  cp trusted_certificate_store.jks multi_trusted_certificate_store.jks
  keytool -importcert -noprompt -alias trusted2 -file cert2.der \
      -storetype JKS -keystore multi_trusted_certificate_store.jks \
      -storepass trustpass456
  ```

### `non_ascii_alias_store.jks`

- **Contents at generation time:** one trusted-certificate entry whose alias is
  the non-ASCII string `trüsted-ünïcode-☃`, which `keytool` lowercases and the
  provider writes with `DataOutputStream.writeUTF`. Committed so HG-042's
  canonical Java modified-UTF validator is exercised against **real** writer
  output containing canonical two-byte (`c3 bc`) and three-byte (`e2 98 83`)
  sequences, not only against hand-written byte vectors.
- **Store password:** `trustpass456`
- **Size:** 822 bytes
- **SHA-256:**
  `101af6556330a726daeab1bd1407e7905f163b5a723006668a057095accc1bb0`
- **Command:**

  ```
  keytool -importcert -noprompt -alias 'trüsted-ünïcode-☃' -file cert.der \
      -storetype JKS -keystore non_ascii_alias_store.jks \
      -storepass trustpass456
  ```

### `private_key_store.jks`

- **Contents at generation time:** one RSA 2048 private-key entry (alias `k1`)
  with its self-signed certificate. HG-042's JKS key-store negative control: it
  must produce **no** `java_truststore:*` finding and must fall through to the
  generic JKS classification unchanged.
- **Store password:** `password123`
- **Size:** 2090 bytes
- **SHA-256:**
  `2b9213fb94a51e4a277e4fc110b16f8e5c313052637dd5a3873db8ca3b78ca02`
- **Command:** the `-genkeypair` command under "Shared certificate material".

### `mixed_store.jks`

- **Contents at generation time:** one private-key entry (`k1`) **and** one
  trusted-certificate entry (`trusted1`). HG-042's mixed-store negative control:
  a store that may well be used operationally as a truststore, but which is not
  trusted-certificate-*only*, so it stays under generic keystore classification.
- **Store password:** `password123`
- **Size:** 2866 bytes
- **SHA-256:**
  `d02513b60cee8d2c17c3cb5e5251ea97991e36de3b4c4d4817eea39a736ed729`
- **Commands:**

  ```
  cp private_key_store.jks mixed_store.jks
  keytool -importcert -noprompt -alias trusted1 -file cert.der \
      -storetype JKS -keystore mixed_store.jks -storepass password123
  ```

### `mixed_store.jceks`

- **Contents at generation time:** one private-key entry (`k1`, tag 1), one
  trusted-certificate entry (`trusted1`, tag 2), and one AES 256 secret-key
  entry (`sk1`, tag 3 — stored by `JceKeyStore` as a Java-serialized
  `SealedObject`). The JCEKS mixed negative control, and the fixture that proves
  HG-042 disqualifies the store **without** deserializing that object.
- **Store password:** `password123`
- **Size:** 3334 bytes
- **SHA-256:**
  `c1f4c11c05d7c3c420d9788bd793d0b03e14e972948537ad01873c5f106e1821`
- **Commands:** built on the HG-037 fixture
  `tests/fixtures/crypto_inventory/jceks/private_key_store.jceks`, whose own
  provenance is recorded in that directory:

  ```
  cp ../jceks/private_key_store.jceks mixed_store.jceks
  keytool -importcert -noprompt -alias trusted1 -file cert.der \
      -storetype JCEKS -keystore mixed_store.jceks -storepass password123
  keytool -genseckey -alias sk1 -keyalg AES -keysize 256 \
      -storetype JCEKS -keystore mixed_store.jceks \
      -storepass password123 -keypass password123
  ```

## Reused HG-037 JCEKS fixtures

HG-042's JCEKS v2 positive and its JCEKS tag-1/tag-3/empty negatives are the
existing, already-documented stores in
`tests/fixtures/crypto_inventory/jceks/` — `trusted_certificate_store.jceks`,
`private_key_store.jceks`, `secret_key_store.jceks`, and `empty_store.jceks`.
They are real `keytool` output with full provenance in that directory's
`PROVENANCE.md`, and re-generating byte-equivalent duplicates here would add
binary weight without adding evidence.

## Byte-constructed version-1 fixtures

`keytool` on any JDK available here writes version 2 only, so version-1 support
is not asserted from synthetic guesswork: the two fixtures below are assembled
directly from OpenJDK's own version-1 **load** grammar
(`sun.security.provider.JavaKeyStore.engineLoad` and
`com.sun.crypto.provider.JceKeyStore.engineLoad`, plus their shared
`readCertificate` helper), field by field, around a real certificate.

The one structural difference between the versions is the certificate-type
field: `readCertificate` reads a `readUTF` certificate type **only when the
store version is 2**. For version 1 the type is implicitly X.509 and the field
is absent entirely. That absence is what the v1 fixtures exist to exercise, and
`tests/test_java_truststore_detection.py` asserts it byte-exactly rather than
taking this note's word for it.

### Byte layout

Both files have exactly this layout, differing only in the 4 magic bytes:

| Offset | Size | Field | Value |
| --- | --- | --- | --- |
| 0 | 4 | magic | `fe ed fe ed` (JKS) / `ce ce ce ce` (JCEKS) |
| 4 | 4 | version, big-endian `int` | `00 00 00 01` |
| 8 | 4 | entry count, big-endian `int` | `00 00 00 01` |
| 12 | 4 | entry tag, big-endian `int` | `00 00 00 02` (trusted certificate) |
| 16 | 2 | alias `writeUTF` encoded length | `00 08` |
| 18 | 8 | alias encoded bytes | `trusted1` (ASCII, identical under Java modified UTF) |
| 26 | 8 | creation date, big-endian `long` | `00 00 01 8f 1b 2c 3d 4e` (a fixed arbitrary epoch-milliseconds value, so the fixture is reproducible) |
| — | — | *certificate type* | **absent — this is the version-1 grammar** |
| 34 | 4 | certificate length, big-endian `int` | `00 00 02 e7` (743) |
| 38 | 743 | certificate | the `cert.der` bytes above, unmodified |
| 781 | 20 | integrity trailer | 20 `00` bytes |

### The trailer is deliberately not a valid digest

The trailing 20 bytes are zeros, **not** a real password-keyed SHA-1 over the
store. HG-042 reserves and length-checks the trailer as structural evidence and
never reads, recomputes, or verifies it — that would require the store password,
which HG-042 does not accept — so a genuine digest would add nothing the tests
could observe. Consequently these two files are intentionally **not** loadable
by `keytool` or `KeyStore.load` with any password; they are HG-042 parser
fixtures, not working keystores.

### Construction command

```
python3 - <<'EOF'
import struct, pathlib
cert = pathlib.Path("cert.der").read_bytes()
alias = b"trusted1"
for name, magic in (("trusted_certificate_store_v1.jks", b"\xfe\xed\xfe\xed"),
                    ("trusted_certificate_store_v1.jceks", b"\xce\xce\xce\xce")):
    out = magic + struct.pack(">i", 1) + struct.pack(">i", 1)
    out += struct.pack(">i", 2)                      # trusted-certificate tag
    out += struct.pack(">H", len(alias)) + alias     # writeUTF alias
    out += struct.pack(">q", 0x0000018F1B2C3D4E)     # creation date
    out += struct.pack(">i", len(cert)) + cert       # v1: no certificate type
    out += bytes(20)                                 # unverified trailer
    pathlib.Path(name).write_bytes(out)
EOF
```

### `trusted_certificate_store_v1.jks`

- **Size:** 801 bytes
- **SHA-256:**
  `5f869d5c0004788d049d2a20d68ea5764294d5d4d71d79c035a594254a7bd46f`

### `trusted_certificate_store_v1.jceks`

- **Size:** 801 bytes
- **SHA-256:**
  `a437a1efd57c96486d8bf168c097cd2258b54a288f5aedd67eecfde9248d6615`

## What these notes are, and are not

This is **test provenance only**. HarvestGuard's own output reports none of it:
no alias, no certificate subject, issuer, serial number, SAN, fingerprint, or
validity date, no certificate type, no entry count, no entry type, no password,
no integrity digest byte, no serialized Java content, and no raw store byte ever
reaches a finding. The "contents at generation time" lines above are the one
place this repository knows what each store holds; HG-042 reports only that a
supported store's entire declared entry table was trusted-certificate entries.

Negative and adversarial inputs (wrong magic, unsupported version, zero and
infeasible entry counts, truncated fields, bad certificate lengths, invalid DER,
trailer-length variants, malformed and near-match certificate types, and the
byte-exact Java modified-UTF vectors) are constructed narrowly in
`tests/test_java_truststore_detection.py` rather than committed here.
