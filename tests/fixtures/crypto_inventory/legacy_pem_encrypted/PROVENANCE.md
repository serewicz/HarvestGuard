# Legacy encrypted PEM test fixture provenance (HG-040)

Every encrypted private-key file in this directory was written by **real OpenSSL
tooling** using the traditional PEM encryption form (`Proc-Type: 4,ENCRYPTED` /
`DEK-Info`). None of it is synthesized from a hand-written byte template.

These are disposable test artifacts. **No production key material is involved.**
The passphrase is recorded only for regeneration. HarvestGuard never uses it:
the detector does not prompt, read the environment, guess, derive a key,
decrypt, call a private-key load API, or invoke any external process at runtime.

## Generation environment

- **OpenSSL:** OpenSSL 3.0.13 30 Jan 2024
- **Test-only passphrase:** `harvestguard-fixture-not-a-real-secret`

```sh
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out rsa_plain.pem
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ec_plain.pem
```

## Fixtures

### `rsa_encrypted_legacy.pem`

- **Purpose:** traditional RSA AES-256-CBC
- **Command / source:** `openssl rsa -in rsa_plain.pem -traditional -aes256 -passout pass:"$PASS" -out rsa_encrypted_legacy.pem`
- **Size:** 1766 bytes
- **SHA-256:** `9168c394d55a5c8e34b02604c4813f4e6b6b700518b3d812d116d2166a02cf5d`

### `ec_encrypted_legacy.pem`

- **Purpose:** traditional EC AES-256-CBC
- **Command / source:** `openssl ec -in ec_plain.pem -aes256 -passout pass:"$PASS" -out ec_encrypted_legacy.pem`
- **Size:** 314 bytes
- **SHA-256:** `2d1b33104c87fd39492bd866ad2318df4daf4f454372c3134cbb13d034781e9d`

### `rsa_encrypted_legacy_des3.pem`

- **Purpose:** traditional RSA DES-EDE3-CBC
- **Command / source:** `openssl rsa -in rsa_plain.pem -traditional -des3 -passout pass:"$PASS" -out rsa_encrypted_legacy_des3.pem`
- **Size:** 1751 bytes
- **SHA-256:** `3d2c3a84c5584c5037a302657e225fed4c9703de36a7c29627cbfad8a73af363`

### `rsa_unencrypted_traditional.pem`

- **Purpose:** unencrypted traditional RSA (negative)
- **Command / source:** `openssl rsa -in rsa_plain.pem -traditional -out rsa_unencrypted_traditional.pem`
- **Size:** 1679 bytes
- **SHA-256:** `3aa1d2cc392290a967a19a8386824e67402483c4fd8e3c15ca166bc2f87b823d`

### `pkcs8_encrypted_adjacent.pem`

- **Purpose:** encrypted PKCS#8 adjacent negative
- **Command / source:** `copy of pkcs8_encrypted/rsa_encrypted_pkcs8.pem`
- **Size:** 1874 bytes
- **SHA-256:** `c4f8917bfa9e47e270fcf21d5226a0c9a29e2c0300fe6863a265024bb9952e7b`

### `encrypted_openssh_adjacent`

- **Purpose:** encrypted OpenSSH adjacent negative
- **Command / source:** `copy of pkcs8_encrypted/encrypted_openssh_key`
- **Size:** 464 bytes
- **SHA-256:** `6797d646a28430e80551a3ff8284e68fcb80be1e0e4a4286adb52b1aa3a80ffd`

## Notes

Positive fixtures all produce the same public finding contract
(`private_key:legacy_pem_encrypted`, `Format: Legacy PEM`). Structural negatives
are constructed in `tests/test_legacy_pem_encrypted_detection.py`.
