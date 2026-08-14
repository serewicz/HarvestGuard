# OpenSSH host identity test fixture provenance (HG-043)

Every private key, public key, and certificate in this directory was written
by **real OpenSSH `ssh-keygen` tooling** (private/public key generation and
certificate signing) or, for the two PKCS#8 conversions `ssh-keygen` itself
cannot produce, by the same `cryptography` library HG-043 uses at runtime,
re-serializing a real `ssh-keygen`-generated key. Nothing here is a
hand-written byte template.

These are disposable test artifacts. **No production key, certificate, or
hostname is present.** All principals and key IDs use the reserved test-only
canaries `host.example.invalid`, `HG043-CANARY-KEY-ID`, and
`HG043-PUBLIC-COMMENT-CANARY`. HarvestGuard's runtime HG-043 detectors never
invoke `ssh`, `sshd`, `ssh-keygen`, or any other external process, and never
read, decrypt, or otherwise use the private key material below beyond an
in-process, password-less structural parse.

## Generation environment

- **OS:** macOS (Darwin 25.5.0)
- **OpenSSH:** `OpenSSH_10.2p1, LibreSSL 3.3.6` (`ssh -V`)
- **cryptography:** 50.0.0 (same library and floor, `cryptography>=41.0.0`,
  HG-043 parses with at runtime)
- **Test-only encryption passphrase** (one fixture only, recorded for
  regeneration; HarvestGuard never reads it):
  `harvestguard-fixture-not-a-real-secret`

The test CA private key (`ca_key`) is a build intermediate and is **not
committed**: it exists only to sign the certificate fixtures below and can be
regenerated with the command shown. `ca_key.pub` (no secret material) is
committed for reference.

## Ordinary key pairs

```sh
ssh-keygen -t rsa -b 2048 -N "" -C "" -f ssh_host_rsa_key
ssh-keygen -t ecdsa -b 256 -N "" -C "" -f ssh_host_ecdsa_key      # nistp256
ssh-keygen -t ed25519 -N "" -C "" -f ssh_host_ed25519_key
```

Each produces the OpenSSH-format private key (`ssh_host_<algo>_key`) and its
`.pub` public-key record (`ssh_host_<algo>_key.pub`).

### PKCS#8 conversions

`ssh_host_rsa_key_pkcs8.pem` and `ssh_host_ecdsa_key_pkcs8.pem`:

```sh
cp ssh_host_rsa_key ssh_host_rsa_key_pkcs8.pem
ssh-keygen -p -m PKCS8 -f ssh_host_rsa_key_pkcs8.pem -N "" -P ""
cp ssh_host_ecdsa_key ssh_host_ecdsa_key_pkcs8.pem
ssh-keygen -p -m PKCS8 -f ssh_host_ecdsa_key_pkcs8.pem -N "" -P ""
```

`ssh_host_ed25519_key_pkcs8.pem`: this build's `ssh-keygen` has no PKCS#8
export path for Ed25519 (`-p -m PKCS8` on an Ed25519 key silently leaves it in
OpenSSH format — there is no legacy/traditional Ed25519 PEM form for it to
convert to or from). Ed25519 support for `-----BEGIN PRIVATE KEY-----` /
PKCS#8 is real and required by Issue #88 Section 7.2, so this one file is
produced instead by loading the real `ssh-keygen`-generated
`ssh_host_ed25519_key` with the same `cryptography` API HG-043 itself calls
(`serialization.load_ssh_private_key`) and re-serializing the parsed key with
`private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())`. The key
material is the same real Ed25519 private key `ssh-keygen` generated; only the
container encoding changed, and by the same library this repository already
depends on.

### Traditional PEM conversions

```sh
cp ssh_host_rsa_key ssh_host_rsa_key_traditional.pem
ssh-keygen -p -m PEM -f ssh_host_rsa_key_traditional.pem -N "" -P ""
cp ssh_host_ecdsa_key ssh_host_ecdsa_key_traditional.pem
ssh-keygen -p -m PEM -f ssh_host_ecdsa_key_traditional.pem -N "" -P ""
```

There is no traditional PEM form for Ed25519 (Issue #88 Section 19 states this
explicitly: "Traditional PEM forms are not accepted for Ed25519"), so no
`ssh_host_ed25519_key_traditional.pem` fixture exists.

### Encrypted OpenSSH private key

```sh
ssh-keygen -t rsa -b 2048 \
    -N "harvestguard-fixture-not-a-real-secret" -C "" \
    -f ssh_host_rsa_key_encrypted
```

A password-protected OpenSSH-format RSA private key, for the Section 9
"encrypted OpenSSH private key under a canonical basename" no-match test.
HG-043 calls the parser with `password=None`; the expected failure is treated
as no-match and the file falls through to the existing generic path. The
passphrase above is a disposable test fixture value, recorded only so this
file can be regenerated; HG-043 never supplies it.

## Certificates

One test CA:

```sh
ssh-keygen -t ed25519 -N "" -C "" -f ca_key
```

One HOST certificate per supported certified-key algorithm, all signed by the
same Ed25519 CA (`-h` is the OpenSSH host-certificate flag):

```sh
ssh-keygen -s ca_key -I host.example.invalid -h \
    -n host.example.invalid -V always:forever ssh_host_rsa_key.pub
ssh-keygen -s ca_key -I host.example.invalid -h \
    -n host.example.invalid -V always:forever ssh_host_ecdsa_key.pub
ssh-keygen -s ca_key -I host.example.invalid -h \
    -n host.example.invalid -V always:forever ssh_host_ed25519_key.pub
```

producing `ssh_host_rsa_key-cert.pub`, `ssh_host_ecdsa_key-cert.pub`, and
`ssh_host_ed25519_key-cert.pub` respectively. Each signs the same key material
already present as the corresponding ordinary public-key fixture above;
`ssh-keygen -s` writes a new `<name>-cert.pub` file and does not modify the
public key it certifies.

One USER certificate (no `-h`), from separate key material so it is not
mistakable for the host fixtures above, with the required key-ID and
public-key-comment canaries:

```sh
ssh-keygen -t ed25519 -N "" -C "HG043-PUBLIC-COMMENT-CANARY" -f user_key
ssh-keygen -s ca_key -I HG043-CANARY-KEY-ID \
    -n testuser -V always:forever user_key.pub
```

The USER certificate's certified key is deliberately Ed25519, not ECDSA: the
pre-existing (pre-HG-043) generic `public_key:ssh` detector's candidate
prefix check for ECDSA (`"ecdsa-sha2-"`, with no trailing space) also matches
the start of every `ecdsa-sha2-*-cert-v01@openssh.com` certificate token, so
an ECDSA-certified certificate would already reach that generic detector's
parser today and produce a non-empty "Malformed OpenSSH Public Key" finding —
not the "zero findings under current generic handling" the completed
post-HG-042 delta freeze (Issue #88 Section 26) requires this fixture to
demonstrate. RSA and Ed25519 certificate tokens do not share this collision
(`"ssh-rsa-cert-v01@openssh.com"` does not start with `"ssh-rsa "`, and
`"ssh-ed25519-cert-v01@openssh.com"` does not start with `"ssh-ed25519 "`).
This is pre-existing, unrelated-detector behavior; HG-043 does not change it,
and this fixture choice exists so the required zero-findings assertion is
actually true of the code under test rather than incidentally avoided.

### Tampered-signature HOST certificate

`ssh_host_ed25519_key-cert-tampered.pub` is derived from the real, validly
signed `ssh_host_ed25519_key-cert.pub` above (Ed25519 CA/signing key, per
Issue #88 Section 12's requirement that this specific control use an Ed25519
signer) by the exact procedure the issue specifies, performed once in
test/fixture-generation code (never at HG-043 runtime):

1. read the certificate record and base64-decode only the SSH certificate
   blob;
2. parse the blob's flat length-prefixed SSH wire fields for the
   `ssh-ed25519-cert-v01@openssh.com` layout (`pktype`, `nonce`, `pk`,
   `serial` (uint64), `type` (uint32), `key id`, `valid principals`,
   `valid after`/`valid before` (uint64), `critical options`, `extensions`,
   `reserved`, `signature key`, `signature`) to locate the final `signature`
   string field without assuming byte offsets;
3. parse that field as an SSH signature structure (`string` signature
   algorithm, `string` signature blob) and confirm the algorithm is exactly
   `ssh-ed25519`;
4. flip exactly one bit (XOR `0x01`) in the final byte of the inner raw
   64-byte Ed25519 signature payload;
5. re-encode the signature-algorithm string and mutated signature blob back
   into the same length-prefixed `string`/`string` signature structure, then
   splice that back into the certificate blob at the same offset, replacing
   only the original signature field;
6. base64-re-encode the mutated blob under the same
   `ssh-ed25519-cert-v01@openssh.com` record.

No length field, framing byte, algorithm identifier, certificate type,
certified public key, principal, or key ID changes; only the final bit of the
signature payload is flipped. Confirmed interactively against the installed
`cryptography==50.0.0`:
`serialization.load_ssh_public_identity` still returns an `SSHCertificate`
with `.type == SSHCertificateType.HOST` for the mutated record (so HG-043
still structurally matches it, the intentional accepted false positive Issue
#88 Section 12 requires), while calling `.verify_cert_signature()` on that
same parsed object raises `cryptography.exceptions.InvalidSignature`. The
mutated bytes are committed directly; regenerating them requires re-running
the procedure above against a freshly signed `ssh_host_ed25519_key-cert.pub`.

## Fixture inventory

| File | Purpose | Size (bytes) | SHA-256 |
| --- | --- | ---: | --- |
| `ssh_host_rsa_key` | RSA 2048, OpenSSH private-key format | 1799 | `4ae4ce97fc1983140ca99016ad6c16ca59b2c797d64833370c0742f1e6b74e24` |
| `ssh_host_rsa_key.pub` | matching RSA public key | 382 | `1abb0cdba7d3d9e308ac8de62bd886f0ef9acbaed230ced626aa4d7cf0a23cdb` |
| `ssh_host_rsa_key_pkcs8.pem` | same RSA key, unencrypted PKCS#8 PEM | 1704 | `2c3f3e387a54941474ffd5bf708002ac888632defd0968a13e2c3e92606a2c4d` |
| `ssh_host_rsa_key_traditional.pem` | same RSA key, traditional `RSA PRIVATE KEY` PEM | 1679 | `310dc2f762f84903e1ac0c093f5e41ebae0dc7e6ce4c1dbc1192a7ce6d859fcc` |
| `ssh_host_rsa_key_encrypted` | separate RSA 2048 key, password-encrypted OpenSSH format | 1856 | `96ebbc031bca3ee23c650fab38f05d44349c9d071f9ee6b3c91299491b7a664d` |
| `ssh_host_ecdsa_key` | ECDSA nistp256, OpenSSH private-key format | 480 | `e891dbe3029932b769cdbe986bbb468e6467520f32c78526560d0bdfd7278f11` |
| `ssh_host_ecdsa_key.pub` | matching ECDSA public key | 162 | `7f8f852b3647ffa27d2d0dfbb7fa0473fd2236090b453aceaed0c0881d3d00c3` |
| `ssh_host_ecdsa_key_pkcs8.pem` | same ECDSA key, unencrypted PKCS#8 PEM | 570 | `b2f2b722460397b0f4ab43156175f3ebeec0d9fe78e7d1802fb695fa46c6e139` |
| `ssh_host_ecdsa_key_traditional.pem` | same ECDSA key, traditional `EC PRIVATE KEY` PEM | 556 | `8fbbd093eb1344401e62cae02e0ef51b6bc291c852c17d625fd8afd44b0eb0c5` |
| `ssh_host_ed25519_key` | Ed25519, OpenSSH private-key format | 387 | `cdf263ea1ff4526179c70bf367ccfeb4ac33c44328f4439665181e995ceecff9` |
| `ssh_host_ed25519_key.pub` | matching Ed25519 public key | 82 | `49d46bc5f67e44613544076a20365a6a057c381714b221abf3c3858d8022e01c` |
| `ssh_host_ed25519_key_pkcs8.pem` | same Ed25519 key, unencrypted PKCS#8 PEM | 119 | `efb4e4941b2f0c9f9b1ab33b6f671300f6c6299157e109bce6c3de1cc8ec9f39` |
| `ssh_host_rsa_key-cert.pub` | HOST certificate, RSA certified key, Ed25519 CA | 811 | `946b111c90b6b561147bfe43e97d8189339c6711e743f97b385ef45b51c09bea` |
| `ssh_host_ecdsa_key-cert.pub` | HOST certificate, ECDSA certified key, Ed25519 CA | 593 | `eca5e7f198fcfceb43fe7f651267fb5a2da6668e12f9ef4f01d927d8c7361f25` |
| `ssh_host_ed25519_key-cert.pub` | HOST certificate, Ed25519 certified key, Ed25519 CA | 515 | `50aac8d27100b6659ec856f284f7d5ee8036f5b856ed00103b819deda06924ab` |
| `ssh_host_ed25519_key-cert-tampered.pub` | above HOST certificate, one bit flipped in the signature payload | 490 | `70173e0e19f16ca6bfae1fb0a729124a54095f5bf6f239442c3f11814024fc52` |
| `user_key` | Ed25519, unrelated ordinary key (renamed-key / no-pairing tests) | 419 | `d45dab218b47270137f995b9bb1bc0bb8c21b1dadeffbe056ca2f08ea53df68e` |
| `user_key.pub` | matching Ed25519 public key, comment = `HG043-PUBLIC-COMMENT-CANARY` | 109 | `a52fb493680fb38cb9fd3b4ded0f50884955fc43003f36da9a03edbb50f27fc4` |
| `user_key-cert.pub` | USER certificate, Ed25519 certified key, Ed25519 CA, key ID = `HG043-CANARY-KEY-ID`, principal = `testuser` | 674 | `44205b216859d89a883674a5f79b87dc23314a65b7bce0b8f528d20f87d47d16` |
| `ca_key.pub` | test CA public key (reference only; CA private key not committed) | 82 | `062509df467d25152b22c34a78ecf98da9873278c7525f06b47d9b1f057345f7` |

## Private material present

`ssh_host_rsa_key`, `ssh_host_ecdsa_key`, `ssh_host_ed25519_key`,
`ssh_host_rsa_key_pkcs8.pem`, `ssh_host_ecdsa_key_pkcs8.pem`,
`ssh_host_ed25519_key_pkcs8.pem`, `ssh_host_rsa_key_traditional.pem`,
`ssh_host_ecdsa_key_traditional.pem`, `ssh_host_rsa_key_encrypted`, and
`user_key` contain private key material. All of it is disposable, test-only,
generated solely for this fixture set, and protects nothing in production.

## Runtime statement

HG-043's detectors (`scanner/crypto_inventory.py`) never invoke `ssh`,
`sshd`, `ssh-keygen`, `ssh-keyscan`, or any other subprocess, open a network
connection, or read an environment variable. Every fixture above was produced
offline, once, by the tooling and commands recorded on this page; HG-043 only
ever reads bytes already on disk through the same in-process `cryptography`
calls documented in `scanner/crypto_inventory.py`'s own detector functions.
