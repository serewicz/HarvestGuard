# Encrypted PKCS#8 test fixture provenance (HG-038)

Every file in this directory was written by **real, standards-conformant
tooling** — OpenSSL for the PKCS#8 and traditional PEM/DER files, OpenSSH's
`ssh-keygen` for the encrypted OpenSSH key — and generated for this
repository's regression tests. None of it is synthesized from a hand-written
DER template: HG-038's positive detection coverage must not rest on bytes the
test itself invented.

These are disposable test artifacts. The private keys inside them were
generated here, protect nothing, and are not used by anything. **No production
key material, certificate, or credential is involved.** The passphrase used
during generation is recorded below **only so the fixtures can be
regenerated**.

HarvestGuard never uses that passphrase. The `private_key:pkcs8_encrypted`
detector requires no password and accepts none: it does not prompt, does not
read the environment, does not guess, does not derive a key, does not decrypt
`encryptedData`, does not call a private-key load API, and does not invoke
`openssl`, `java`, `keytool`, or any other external process at scan time.
Detection reads the outer ASN.1 structure — a DER `SEQUENCE` at offset 0
consuming the whole file, holding exactly an `AlgorithmIdentifier` and a
non-empty primitive `OCTET STRING` — and nothing else. The encryption
algorithm, KDF, salt, IV, iteration count, and encrypted bytes are validated as
DER where required and then discarded; none of them is ever reported.

## Generation environment

- **OpenSSL:** OpenSSL 3.0.13 30 Jan 2024 (Library: OpenSSL 3.0.13 30 Jan 2024)
- **OpenSSH:** `openssh-client` 1:9.6p1-3ubuntu13.18 (Ubuntu 24.04 runner)
- **Test-only passphrase used during generation:**
  `harvestguard-fixture-not-a-real-secret`

The two private keys everything below is derived from:

```sh
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out rsa_plain.pem
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ec_plain.pem
```

`rsa_plain.pem` and `ec_plain.pem` are intermediates and are deliberately **not**
committed. In the commands below, `PASS` is the test-only passphrase above.

## Positive fixtures — encrypted PKCS#8 `EncryptedPrivateKeyInfo`

Two independently generated keys, with different underlying private-key types
*and* different encryption configurations, so a positive result cannot depend on
one algorithm choice. HarvestGuard cannot tell them apart and never claims to:
both produce the identical finding, carrying `Format: PKCS#8` and no algorithm,
KDF, or parameter detail.

### `rsa_encrypted_pkcs8.pem`

- **Purpose:** the PEM form of encrypted PKCS#8 — RFC-style
  `-----BEGIN ENCRYPTED PRIVATE KEY-----` block whose base64 body is DER
  `EncryptedPrivateKeyInfo`
- **Underlying key at generation time:** RSA 2048, PBES2 with AES-256-CBC
- **Command:**

  ```sh
  openssl pkcs8 -topk8 -in rsa_plain.pem -outform PEM -v2 aes-256-cbc \
      -passout pass:"$PASS" -out rsa_encrypted_pkcs8.pem
  ```

- **Size:** 1874 bytes
- **SHA-256:** `c4f8917bfa9e47e270fcf21d5226a0c9a29e2c0300fe6863a265024bb9952e7b`

### `rsa_encrypted_pkcs8.der`

- **Purpose:** the equivalent DER form of the same encrypted key — the binary
  `EncryptedPrivateKeyInfo` the PEM body above encodes
- **Underlying key at generation time:** RSA 2048, PBES2 with AES-256-CBC
- **Command:**

  ```sh
  openssl pkcs8 -topk8 -in rsa_plain.pem -outform DER -v2 aes-256-cbc \
      -passout pass:"$PASS" -out rsa_encrypted_pkcs8.der
  ```

- **Size:** 1329 bytes
- **SHA-256:** `2f716cdbd94095a7549ed1ca3936fcd385ae66db2b2af3468ac7397307d758a4`

### `ec_encrypted_pkcs8.pem`

- **Purpose:** a second, independently generated encrypted PKCS#8 key — a
  different private-key type and a different encryption configuration
- **Underlying key at generation time:** EC P-256, PBES2 with 3DES
- **Command:**

  ```sh
  openssl pkcs8 -topk8 -in ec_plain.pem -outform PEM -v2 des3 \
      -passout pass:"$PASS" -out ec_encrypted_pkcs8.pem
  ```

- **Size:** 387 bytes
- **SHA-256:** `db62867fede7752c2b71c0d86c4c37208ca696c8465a79940a525d1a775eb213`

### `ec_encrypted_pkcs8.der`

- **Purpose:** the DER form of that second key
- **Underlying key at generation time:** EC P-256, PBES2 with 3DES
- **Command:**

  ```sh
  openssl pkcs8 -topk8 -in ec_plain.pem -outform DER -v2 des3 \
      -passout pass:"$PASS" -out ec_encrypted_pkcs8.der
  ```

- **Size:** 230 bytes
- **SHA-256:** `6ac4c6534c5457f065c71f927d434e41ab91a701d7d8e396bffbf0e7422cf269`

## Negative controls — real tool output that must **not** be classified

Each of these is a genuine private-key file that a naive check could confuse
with encrypted PKCS#8. Their classification is asserted in
`tests/test_pkcs8_encrypted_private_key_detection.py`.

### `unencrypted_pkcs8.der`

- **Purpose:** unencrypted PKCS#8 `PrivateKeyInfo` in DER — the same outer
  encoding family, a different structure (a version `INTEGER` first, three
  elements)
- **Command:**

  ```sh
  openssl pkcs8 -topk8 -in rsa_plain.pem -outform DER -nocrypt \
      -out unencrypted_pkcs8.der
  ```

- **Size:** 1217 bytes
- **SHA-256:** `a87177eb761522f1a622d780d920da2ae7be24b77c43758c620ba48ada31dbe4`

### `unencrypted_pkcs8.pem`

- **Purpose:** unencrypted PKCS#8 in PEM, labelled `BEGIN PRIVATE KEY` — the
  label the encrypted form is one word away from
- **Command:**

  ```sh
  openssl pkcs8 -topk8 -in rsa_plain.pem -outform PEM -nocrypt \
      -out unencrypted_pkcs8.pem
  ```

- **Size:** 1704 bytes
- **SHA-256:** `06fc417505d34e09f200e60093020cbe05e879323856ff2a9d5b262f5038b21c`

### `traditional_rsa.pem`

- **Purpose:** traditional (PKCS#1) RSA private key, `BEGIN RSA PRIVATE KEY`
- **Command:**

  ```sh
  openssl rsa -in rsa_plain.pem -traditional -out traditional_rsa.pem
  ```

- **Size:** 1675 bytes
- **SHA-256:** `58c268a8b039ec4dab7282d49478041fac2ed9dc4c70e3e97c55ea121660d9ef`

### `traditional_ec.pem`

- **Purpose:** traditional SEC1 EC private key, `BEGIN EC PRIVATE KEY`
- **Command:**

  ```sh
  openssl ec -in ec_plain.pem -out traditional_ec.pem
  ```

- **Size:** 227 bytes
- **SHA-256:** `b633e1dd5f3a7c880a18a801e52e11e877afb9ad330d51966b2331ef07a413e5`

### `legacy_encrypted_rsa.pem`

- **Purpose:** an encrypted *traditional* PEM key using the legacy
  `Proc-Type: 4,ENCRYPTED` / `DEK-Info` headers — encrypted, but not PKCS#8
- **Command:**

  ```sh
  openssl rsa -in rsa_plain.pem -traditional -aes256 -passout pass:"$PASS" \
      -out legacy_encrypted_rsa.pem
  ```

- **Size:** 1766 bytes
- **SHA-256:** `35c6e10e23042f82151383e10788fc8f91a45303d9ce9d74d2edf0c9a4626a86`

### `encrypted_openssh_key`

- **Purpose:** a passphrase-protected OpenSSH private key
  (`BEGIN OPENSSH PRIVATE KEY`) — encrypted, but neither PKCS#8 nor DER
- **Command:**

  ```sh
  ssh-keygen -t ed25519 -N "$PASS" -C "harvestguard-pkcs8-fixture" -f ssh_enc
  ```

  (the private half is committed as `encrypted_openssh_key`; the `.pub` half is
  not needed and is not committed)

- **Size:** 464 bytes
- **SHA-256:** `6797d646a28430e80551a3ff8284e68fcb80be1e0e4a4286adb52b1aa3a80ffd`

## Structural negative controls

The malformed cases HG-038 must reject — truncated DER, trailing bytes, wrong
element counts, a missing OID, malformed parameters, a constructed OCTET STRING,
indefinite and non-minimal lengths, an embedded structure at a nonzero offset,
PEM with no footer, invalid base64 — are **not** committed here. They are
derived at test time from `rsa_encrypted_pkcs8.der` above by mutating exactly
one property of a real fixture, so each stays anchored to real tool output while
isolating the single rule under test. See
`tests/test_pkcs8_encrypted_private_key_detection.py`.
