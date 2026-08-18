# Phase 1 generator contract

The six scripts below cover exactly the eight Phase 1 cases. Combined scripts
are intentional and keep artifacts produced by the same native tool together.

| Script | Phase 1 case(s) | Native tool |
| --- | --- | --- |
| `openssl_enc.sh` | OpenSSL `Salted__` | `openssl enc` |
| `x509_certificate.sh` | PEM certificate; DER certificate | `openssl req`, `openssl x509` |
| `private_key_pem.sh` | PEM private key | `openssl genpkey` |
| `encrypted_private_key.sh` | legacy encrypted PEM; encrypted PKCS#8 | `openssl genrsa`, `openssl pkcs8` |
| `openssh_host_identity.sh` | OpenSSH host identity | `ssh-keygen` |
| `age_encrypted.sh` | age encrypted file | `age`, `age-keygen` |

Every available generator emits native-tool artifacts plus bounded negative
controls. If `age` is unavailable, its probe produces a recorded skip reason;
the remaining generators continue. These artifacts do not prove support for
every valid variant of their formats.
