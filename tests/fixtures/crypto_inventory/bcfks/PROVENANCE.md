# BCFKS test fixture provenance (HG-036)

Every file in this directory is a **real BCFKS store written by the official
Bouncy Castle provider**, generated for this repository's regression tests. None
of it is synthesized from a hand-written byte template: HG-036's positive
detection coverage must not rest on bytes the test itself invented.

These are disposable test artifacts. The keys and self-signed certificates
inside them were generated here, exist only to give the stores realistic
content, and protect nothing — no production key, certificate, or passphrase is
involved. The store passwords are recorded below only so the fixtures can be
regenerated; HarvestGuard never reads them, and the BCFKS detector never opens,
decrypts, or unlocks any of these files.

## Generation environment

- **Java:** OpenJDK 17.0.19 (Temurin-17.0.19+10), `keytool`
- **Bouncy Castle provider:** `bcprov-jdk18on` 1.84 (official Bouncy Castle
  provider JAR)
- **Provider registration:**
  `-providerclass org.bouncycastle.jce.provider.BouncyCastleProvider -providerpath <path to bcprov-jdk18on-1.84.jar>`

All four stores were written through the provider's default
`engineStore(OutputStream, char[])` path, which is the password/MAC-protected
encrypted-object-store shape HG-036 supports.

## Fixtures

### `private_key_store.bcfks`

- **Contents at generation time:** private-key store — one RSA 2048 private key
  entry with a self-signed certificate (`CN=HarvestGuard BCFKS Test`)
- **Store password:** `password123`
- **Size:** 2608 bytes
- **SHA-256:**
  `3e84ea052fc6c3c987b76b16a57d2f43d256a2cbfb6357663a636fcb64b21c31`
- **Command:**

  ```
  keytool -genkeypair -alias k1 -keyalg RSA -keysize 2048 \
      -dname "CN=HarvestGuard BCFKS Test" -validity 3650 \
      -storetype BCFKS -keystore private_key_store.bcfks \
      -storepass password123 -keypass password123 \
      -providerclass org.bouncycastle.jce.provider.BouncyCastleProvider \
      -providerpath bcprov-jdk18on-1.84.jar
  ```

### `trusted_certificate_store.bcfks`

- **Contents at generation time:** trusted-certificate store — one trusted
  certificate entry, no private key
- **Store password:** `trustpass456`
- **Size:** 1219 bytes
- **SHA-256:**
  `8ba324a3d83f39182cf44f1cd32ead29013013c5a6f6ce99057d417a774bf706`
- **Command:** the certificate was first exported from `private_key_store.bcfks`
  with `keytool -exportcert -alias k1 ... -file cert.der`, then imported into a
  new store:

  ```
  keytool -importcert -noprompt -alias trusted1 -file cert.der \
      -storetype BCFKS -keystore trusted_certificate_store.bcfks \
      -storepass trustpass456 \
      -providerclass org.bouncycastle.jce.provider.BouncyCastleProvider \
      -providerpath bcprov-jdk18on-1.84.jar
  ```

### `empty_store.bcfks`

- **Contents at generation time:** empty store — no entries. This is the
  minimum valid supported encrypted-object-store fixture.
- **Store password:** `password123`
- **Size:** 410 bytes
- **SHA-256:**
  `e7de7c218d4f5dcdff68c5f063dc182f6140cde7dcfaeb7266815ecf4f0f1b27`
- **Command:** a copy of `private_key_store.bcfks` with its only entry removed,
  which rewrites the store:

  ```
  keytool -delete -alias k1 -storetype BCFKS -keystore empty_store.bcfks \
      -storepass password123 \
      -providerclass org.bouncycastle.jce.provider.BouncyCastleProvider \
      -providerpath bcprov-jdk18on-1.84.jar
  ```

### `multi_entry_store.bcfks`

- **Contents at generation time:** multiple-entry store — one EC (secp256r1)
  private key entry with a self-signed certificate
  (`CN=HarvestGuard BCFKS Multi`) plus one trusted certificate entry. Written
  with a different password, and therefore a different salt, MAC, and encrypted
  content, from every other fixture here.
- **Store password:** `aDifferentPassphrase!42`
- **Size:** 1863 bytes
- **SHA-256:**
  `8bd02dfd2dc3715864c493656eeedd51a7a6fc8c5e78ad783844bfb2034cdce4`
- **Commands:**

  ```
  keytool -genkeypair -alias mk1 -keyalg EC -groupname secp256r1 \
      -dname "CN=HarvestGuard BCFKS Multi" -validity 3650 \
      -storetype BCFKS -keystore multi_entry_store.bcfks \
      -storepass 'aDifferentPassphrase!42' -keypass 'aDifferentPassphrase!42' \
      -providerclass org.bouncycastle.jce.provider.BouncyCastleProvider \
      -providerpath bcprov-jdk18on-1.84.jar

  keytool -importcert -noprompt -alias trusted2 -file cert.der \
      -storetype BCFKS -keystore multi_entry_store.bcfks \
      -storepass 'aDifferentPassphrase!42' \
      -providerclass org.bouncycastle.jce.provider.BouncyCastleProvider \
      -providerpath bcprov-jdk18on-1.84.jar
  ```

## What these notes are, and are not

This is **test provenance only**. HarvestGuard's own output reports none of it:
no alias, no certificate subject or issuer, no key identifier, no entry count,
no entry type, no password, no salt, no MAC, no KDF parameter, no encrypted
content, and no raw ASN.1 fragment ever reaches a finding. In particular, the
"contents at generation time" line above is the one place this repository knows
whether a given store is a truststore or a keystore — the detector cannot tell,
because that distinction lives inside the encrypted store data, and HG-036 makes
no such claim.

Negative controls (truncated, corrupted, near-match, and unsupported-form
inputs) are constructed narrowly in `tests/test_bcfks_keystore_detection.py`
rather than committed here.
