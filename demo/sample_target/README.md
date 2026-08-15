# HarvestGuard demo corpus (`demo/sample_target/`)

A small, deliberately synthetic scan target so a new user can run HarvestGuard
immediately and see real, evidence-shaped output without pointing it at
production data, without credentials, and without network access.

**Everything in this directory is fake.** No file here is a real credential,
customer record, production certificate, or operational key. Nothing here was
copied from a real system, and none of this material is used anywhere else --
in this repository or outside it. Do not substitute real data into these files,
and do not reuse any key, certificate, or value from them for any purpose.

Run the corpus with the documented demo command:

```bash
harvestguard scan demo/sample_target --type all --summary
```

See [docs/CLI.md](../../docs/CLI.md#demo-walkthrough) for the full walkthrough,
the expected summary, and the one host-dependent field.

## Manifest

| File | Synthetic provenance | Expected high-level finding |
| --- | --- | --- |
| `sensitive/leaked_config.env` | Hand-written for this repository. Every value is an inert placeholder; the file's own header comment records why each one is shaped to be unmistakably non-functional. | One sensitive-data record with categories `Email`, `Generic Secret`, `Private Key`, plus one low-confidence malformed-PEM cryptographic-inventory record (the block's body is fake text, so parsing correctly fails). Category names and counts only -- never the matched values. |
| `crypto/demo_tls_certificate.pem` | Newly generated for this repository with OpenSSL 3.0.13 (`openssl req -x509 -newkey rsa:2048 -noenc -keyout <discarded> -out demo_tls_certificate.pem -days 36500 -sha256 -subj "/CN=demo.harvestguard.invalid/O=HarvestGuard Synthetic Demo Material/OU=Do Not Use"`). Self-signed, never submitted to or issued by any CA, bound to the reserved-for-testing `.invalid` TLD. The matching private key was discarded at generation time and was never committed. SHA-256 `d20667c3745988fd823f601add39f54323f15c08858e784281a24d5c500f2fb8`, 1715 bytes. | One `PEM Certificate` cryptographic-inventory record, confidence `High`, with the certificate's algorithm, key size, signature algorithm, expiration, issuer, subject, and fingerprint as technical metadata. |
| `crypto/demo_encrypted_private_key.pem` | Newly generated for this repository with OpenSSL 3.0.13 (`openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -aes-256-cbc -pass pass:harvestguard-demo -out demo_encrypted_private_key.pem`). Protects nothing, corresponds to no certificate anywhere, and is not the counterpart of the demo certificate above. Its passphrase is `harvestguard-demo`, published here deliberately so the fixture cannot be mistaken for protected material. SHA-256 `7b501837e3b47921a144e7fd896cd1cdc61dd602d865c36f417a7b86a84ebafb`, 2232 bytes. | One `Encrypted PKCS#8 Private Key` cryptographic-inventory record, confidence `High`, rule `private_key:pkcs8_encrypted`, format `PKCS#8`. The key material itself is never included in output. |
| `README.md` | This manifest. | No findings; it is scanned like any other file and contributes only to the files-scanned count. |

Both `.pem` fixtures carry a plain-text `SYNTHETIC, NON-OPERATIONAL DEMO
MATERIAL` header comment above the encoded block, so a copy that escapes this
directory still identifies itself. The header text sits outside the encoded
block and does not affect detection.

Artifact categories present: one X.509 certificate and one passphrase-encrypted
private key (both synthetic), and one hand-written configuration file with
inert placeholder values.

## What the demo does and does not show

The corpus demonstrates a few currently supported findings so the output shape
is real. It is deliberately not an exhaustive showcase: HarvestGuard supports
many more cryptographic-asset categories than the two shown here, and this
directory is not complete cryptographic coverage, evidence that any of this
material is used at runtime, proof of security, or a risk, readiness,
compliance, or remediation conclusion. Absence of a finding is not proof of
absence.

Filesystem encryption evidence for these files depends on the host: an ordinary
file with no file-level encrypted-format signature is represented by its
mount's aggregate context record, whose volume-status value and confidence
differ by platform. That field is host-dependent by design and is not asserted
as deterministic.
