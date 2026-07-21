# Crypto Inventory Fixture Expected Output

These files are synthetic test fixtures. They are not real credentials and must
not be used outside tests.

Expected finding coverage:

- `rsa_cert.pem`: PEM certificate, RSA, 2048-bit key, SHA-256 signature,
  expires in 2027.
- `ecc_cert.pem`: PEM certificate, EC P-256 key, SHA-256 signature, expires in
  2027.
- `expired_cert.pem`: PEM certificate, RSA, 2048-bit key, expired in 2024.
- `rsa_cert.der`: DER certificate, RSA, 2048-bit key.
- `valid_key.pem`: unencrypted PEM RSA private key, 2048-bit key.
- `encrypted_key.pem`: encrypted PEM private key detected without decrypting
  metadata.
- `ssh_key`: OpenSSH Ed25519 private key.
- `ssh_key.pub`: OpenSSH Ed25519 public key.
- `bundle.p12`: PKCS#12 container with certificate and private key entries.
- `sample.jks`: Java Keystore magic header detected; entry parsing is a known
  MVP limitation.
- `malformed_cert.pem`: malformed PEM certificate finding with parsing error.
- `random.bin`: ignored because it is random binary data with no supported
  crypto-asset signature.
