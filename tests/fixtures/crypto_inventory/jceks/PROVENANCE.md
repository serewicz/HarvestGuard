# JCEKS test fixture provenance (HG-037)

Every file in this directory is a **real JCEKS keystore written by OpenJDK's own
`keytool` with `-storetype JCEKS`**, generated for this repository's regression
tests. None of it is synthesized from a hand-written byte template: HG-037's
positive detection coverage must not rest on bytes the test itself invented.

These are disposable test artifacts. The keys, secret keys, and self-signed
certificates inside them were generated here, exist only to give the stores
realistic content, and protect nothing — no production key, certificate, or
passphrase is involved. The store passwords are recorded below **only so the
fixtures can be regenerated**. HarvestGuard never reads them: the JCEKS detector
requires no password, accepts none, and never opens, decrypts, unlocks,
deserializes, or enumerates any of these files. Detection reads the 12-byte
top-level header and the file's own length, nothing else.

## Generation environment

- **Java:** OpenJDK 17.0.19 (Temurin-17.0.19+10)
- **Tool:** the `keytool` shipped with that JDK, `-storetype JCEKS`
- **Provider:** the JDK's built-in SunJCE `JceKeyStore` implementation (no
  third-party provider JAR is involved)

Every store below is written through `JceKeyStore.engineStore(OutputStream,
char[])`, which emits the magic `0xcececece`, format version `2`, a big-endian
entry count, the serialized entry records, and a trailing keyed SHA-1 digest.
`keytool` prints a "proprietary format" migration warning for `-storetype JCEKS`
on this JDK; that warning is expected and does not affect the bytes written.

Note that this JDK writes **version 2** stores only. HG-037 also accepts version
`1` (OpenJDK's `JceKeyStore` supports both), which no `keytool` available here
can emit; that branch is covered in
`tests/test_jceks_keystore_detection.py` by taking a real fixture and changing
only its four version bytes, so the case is still derived from real keystore
bytes rather than invented ones.

## Fixtures

### `private_key_store.jceks`

- **Contents at generation time:** private-key store — one RSA 2048 private key
  entry with a self-signed certificate (`CN=HarvestGuard JCEKS Test`)
- **Store password:** `password123`
- **Size:** 2076 bytes
- **SHA-256:**
  `0651d635d670a282d5d99e0353f1661dde2946b24fda7f28789ae153107cd61e`
- **Command:**

  ```
  keytool -genkeypair -alias k1 -keyalg RSA -keysize 2048 \
      -dname "CN=HarvestGuard JCEKS Test" -validity 3650 \
      -storetype JCEKS -keystore private_key_store.jceks \
      -storepass password123 -keypass password123
  ```

### `trusted_certificate_store.jceks`

- **Contents at generation time:** truststore — one trusted certificate entry,
  no private key
- **Store password:** `trustpass456`
- **Size:** 812 bytes
- **SHA-256:**
  `bb123e882a844d311d5b25b86c5f3b8816843bd89d66b119bf9de7efe6581826`
- **Commands:** the certificate was first exported from
  `private_key_store.jceks`, then imported into a new store:

  ```
  keytool -exportcert -alias k1 -storetype JCEKS \
      -keystore private_key_store.jceks -storepass password123 -file cert.der

  keytool -importcert -noprompt -alias trusted1 -file cert.der \
      -storetype JCEKS -keystore trusted_certificate_store.jceks \
      -storepass trustpass456
  ```

### `secret_key_store.jceks`

- **Contents at generation time:** secret-key store — one AES 256 secret key
  entry. This is the JCEKS-specific entry type: `JceKeyStore` stores it as a
  Java-serialized `SealedObject`. It is committed precisely so the tests can
  prove HarvestGuard identifies the container **without** deserializing that
  object. Written with a different password, and therefore a different digest
  and protected content, from every other fixture here.
- **Store password:** `aDifferentPassphrase!42`
- **Size:** 514 bytes
- **SHA-256:**
  `98148113b3c34465c022f97e25909d21c6a79fc9a3b07abe927968db6a5eb0dc`
- **Command:**

  ```
  keytool -genseckey -alias sk1 -keyalg AES -keysize 256 \
      -storetype JCEKS -keystore secret_key_store.jceks \
      -storepass 'aDifferentPassphrase!42' -keypass 'aDifferentPassphrase!42'
  ```

### `empty_store.jceks`

- **Contents at generation time:** empty store — no entries. At 32 bytes this is
  the smallest store `keytool` writes, and it is exactly the 12-byte top-level
  header plus the 20-byte trailing keyed SHA-1 digest, which is where HG-037's
  minimum structural size comes from.
- **Store password:** `password123`
- **Size:** 32 bytes
- **SHA-256:**
  `8f89123158004dd861d60a3b99e0a9e043ef1dca3b727b792e363f06d60f893c`
- **Command:** a copy of `private_key_store.jceks` with its only entry removed,
  which rewrites the store:

  ```
  cp private_key_store.jceks empty_store.jceks
  keytool -delete -alias k1 -storetype JCEKS -keystore empty_store.jceks \
      -storepass password123
  ```

## What these notes are, and are not

This is **test provenance only**. HarvestGuard's own output reports none of it:
no alias, no certificate subject or issuer, no key identifier, no entry count,
no entry type, no password, no integrity digest, no serialized Java content, and
no raw keystore byte ever reaches a finding. In particular, the "contents at
generation time" line above is the one place this repository knows whether a
given store is a truststore, a keystore, or a secret-key store — the detector
cannot tell, because that distinction lives in the entry records HG-037
deliberately does not parse, and it makes no such claim.

Negative controls (empty, truncated, unsupported-version, near-match, and
misleading-extension inputs) are constructed narrowly in
`tests/test_jceks_keystore_detection.py` rather than committed here.
