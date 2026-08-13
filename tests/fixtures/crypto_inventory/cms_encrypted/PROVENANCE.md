# CMS / PKCS#7 test fixture provenance (HG-039)

Every ASN.1 payload in this directory is **real OpenSSL `cms` / `crl2pkcs7`
output**, generated for this repository's regression tests. None of it is
synthesized from a hand-written byte template: HG-039's positive detection
coverage must not rest on bytes the test itself invented.

These are disposable test artifacts. The recipient key pair and self-signed
certificate used to build the `EnvelopedData` fixtures, and the symmetric key
used to build the `EncryptedData` fixtures, were generated here for that purpose
alone and protect nothing — no production key, certificate, passphrase, or
message is involved. The plaintext encrypted into every positive fixture is the
single line `HarvestGuard CMS fixture plaintext.`.

**No private key is committed.** The recipient RSA private key
(`recipient_key.pem` in the generation directory) is deliberately *not* part of
this repository: HarvestGuard never decrypts these files, so it has no use for
one. The symmetric key used for `EncryptedData` is recorded below only so the
fixtures can be regenerated.

**No runtime OpenSSL or decryption dependency.** OpenSSL is used for fixture
*generation* only. The HG-039 detector invokes no external process, requests and
accepts no password, private key, secret key, or recipient certificate, decrypts
no content-encryption key and no payload, verifies no signature, validates no
certificate or chain, and makes no network call. It reads the outer
`ContentInfo` structure with the repository's own bounded DER reader and
reports only that a supported encrypted-content structure is present.

## Generation environment

- **Tool:** OpenSSL 3.0.13 30 Jan 2024 (Library: OpenSSL 3.0.13 30 Jan 2024)
- **Working directory:** a scratch directory; only the files listed below were
  copied into this repository.

Generation-only inputs (not committed):

```
printf 'HarvestGuard CMS fixture plaintext.\n' > plain.txt

openssl req -x509 -newkey rsa:2048 -keyout recipient_key.pem \
    -out recipient_cert.pem -days 3650 -nodes \
    -subj "/CN=HarvestGuard CMS Fixture Recipient"
```

The symmetric key used by the `EncryptedData` fixtures, referred to below as
`$SECRETKEY`, is the fixed test value:

```
000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
```

## Positive fixtures

Each of these is a complete `ContentInfo` whose `contentType` is
`id-envelopedData` or `id-encryptedData` and whose `encryptedContent` is present
and non-empty.

### `enveloped_data.der`

- **Content type:** CMS `EnvelopedData`, DER
- **Size:** 477 bytes
- **SHA-256:**
  `b57da0f3cb96141f6a39c9484a7c29532a0d72f19da30a88d48dd4eb52cc250d`
- **Command:**

  ```
  openssl cms -encrypt -binary -aes-256-cbc -in plain.txt \
      -outform DER -out enveloped_data.der recipient_cert.pem
  ```

### `enveloped_data.pem`

- **Content type:** CMS `EnvelopedData`, RFC 7468 textual encoding with the
  `CMS` label (`-----BEGIN CMS-----`), written directly by OpenSSL
- **Size:** 684 bytes
- **SHA-256:**
  `af56beb01b65bd26429f6d5d7ab833788c955bbc596d0de8d1cebf0b40a15b3d`
- **Command:**

  ```
  openssl cms -encrypt -binary -aes-256-cbc -in plain.txt \
      -outform PEM -out enveloped_data.pem recipient_cert.pem
  ```

  (Encryption is randomized, so this file's body is a separate OpenSSL run from
  `enveloped_data.der` rather than a re-encoding of it.)

### `enveloped_data_pkcs7.pem`

- **Content type:** CMS `EnvelopedData`, RFC 7468 textual encoding with the
  `PKCS7` label (`-----BEGIN PKCS7-----`)
- **Size:** 688 bytes
- **SHA-256:**
  `fab33b8b72ea330a1540a288b481327bb8317557471d04031675eb983db1b117`
- **Provenance:** OpenSSL's `cms` command emits the `CMS` label, never the
  `PKCS7` label, so the `PKCS7` textual wrapper could not be produced directly.
  **The ASN.1 payload is real OpenSSL output** — the exact bytes of
  `enveloped_data.der` above — and **only the RFC 7468 textual wrapper was
  applied**, deterministically: standard base64 of those bytes, wrapped at 64
  characters, between the exact `-----BEGIN PKCS7-----` / `-----END PKCS7-----`
  boundary lines. No ASN.1 byte was invented, edited, or reordered.
- **Command:**

  ```
  python3 -c "
  import base64, pathlib, textwrap
  der = pathlib.Path('enveloped_data.der').read_bytes()
  body = '\n'.join(textwrap.wrap(base64.b64encode(der).decode('ascii'), 64))
  pathlib.Path('enveloped_data_pkcs7.pem').write_text(
      '-----BEGIN PKCS7-----\n' + body + '\n-----END PKCS7-----\n')
  "
  ```

### `encrypted_data.der`

- **Content type:** CMS `EncryptedData`, DER (version 0, no unprotected
  attributes)
- **Size:** 114 bytes
- **SHA-256:**
  `495b5764f6d9ee88eb5350b3240c911740fe3fc8ffe9d8322ba7cea4fe6012c0`
- **Command:**

  ```
  openssl cms -EncryptedData_encrypt -binary -in plain.txt -aes-256-cbc \
      -secretkey $SECRETKEY -outform DER -out encrypted_data.der
  ```

### `encrypted_data.pem`

- **Content type:** CMS `EncryptedData`, RFC 7468 textual encoding with the
  `CMS` label, written directly by OpenSSL
- **Size:** 193 bytes
- **SHA-256:**
  `3c9494e731b64eff1a2a30d7335ab941741a1a8486deb9e6b560c92ccb8c367c`
- **Command:**

  ```
  openssl cms -EncryptedData_encrypt -binary -in plain.txt -aes-256-cbc \
      -secretkey $SECRETKEY -outform PEM -out encrypted_data.pem
  ```

## Negative fixtures

Real CMS/PKCS#7 objects that are **not** encrypted-content objects. Each must
produce no `cms:enveloped_data` and no `cms:encrypted_data` finding: this is
what proves the detector separates encrypted objects from certificate-only and
signed bundles rather than matching the CMS/PKCS#7 container itself.

### `signed_data.der`

- **Content type:** CMS `SignedData` with encapsulated content
- **Size:** 1490 bytes
- **SHA-256:**
  `bbe45e3063800445a9838e2148c3bf9fc5d0bbcaf1e6388aaf816d11427bb9be`
- **Command:**

  ```
  openssl cms -sign -binary -in plain.txt -signer recipient_cert.pem \
      -inkey recipient_key.pem -md sha256 -outform DER -out signed_data.der
  ```

### `certificates_only.p7b`

- **Content type:** PKCS#7 certificate bundle — degenerate `SignedData` with no
  signers and no encapsulated content
- **Size:** 878 bytes
- **SHA-256:**
  `ff53430d3d8917636272b2536fe00bb98af82206ad3f1cfc2029c21692b5ac91`
- **Command:**

  ```
  openssl crl2pkcs7 -nocrl -certfile recipient_cert.pem \
      -outform DER -out certificates_only.p7b
  ```

### `data.der`

- **Content type:** CMS `Data` (`id-data`) — a valid `ContentInfo` carrying
  plaintext
- **Size:** 53 bytes
- **SHA-256:**
  `404ce8bc8e68bffd9cbab1aa4daaee140407b370e63500c538ec4c11254eaf27`
- **Command:**

  ```
  openssl cms -data_create -binary -in plain.txt -outform DER -out data.der
  ```

### `digested_data.der`

- **Content type:** CMS `DigestedData` (`id-digestedData`) — a valid
  `ContentInfo` whose content OID is supported by neither HG-039 rule
- **Size:** 120 bytes
- **SHA-256:**
  `6e88abdadf92363503f89a529a6abe9f03658b3c7a3459b9b4f5bcc36c67abc9`
- **Command:**

  ```
  openssl cms -digest_create -binary -in plain.txt -md sha256 \
      -outform DER -out digested_data.der
  ```

## Negative fixtures reused from elsewhere in this tree

The remaining required negative controls are already real, provenance-documented
fixtures in this repository and are **not duplicated here**. HG-039's tests read
them from their existing locations:

- DER certificate — `tests/fixtures/crypto_inventory/rsa_cert.der`
- PKCS#12 — `tests/fixtures/crypto_inventory/bundle.p12`
- encrypted PKCS#8 — `tests/fixtures/crypto_inventory/pkcs8_encrypted/`
  (`rsa_encrypted_pkcs8.der`, `ec_encrypted_pkcs8.der`)
- BCFKS — `tests/fixtures/crypto_inventory/bcfks/`
- JCEKS — `tests/fixtures/crypto_inventory/jceks/`
- JKS — `tests/fixtures/crypto_inventory/sample.jks`

## Not included, deliberately

- **No recipient private key.** Nothing in HarvestGuard's detection path can use
  one.
- **No detached/absent-`encryptedContent` fixture.** OpenSSL's `cms` command
  does not emit one for these content types, and HG-039 treats that shape as a
  documented false negative; the case is covered by deriving it from these real
  fixtures inside the test suite rather than by committing a hand-built object.
- **No BER indefinite-length fixture.** Indefinite-length/streaming CMS is
  outside HG-039's supported definite-length subset and is a documented false
  negative; the tests cover it by deriving it from a real fixture.
