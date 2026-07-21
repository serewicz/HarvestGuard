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
- The scanner reports observed local evidence only. It does not calculate risk
  scores, quantum exposure, or executive priority.
