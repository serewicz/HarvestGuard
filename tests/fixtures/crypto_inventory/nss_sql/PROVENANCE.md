# NSS SQL database-set fixture provenance (HG-041)

The fixture set in `valid_empty/` was produced by **real Mozilla NSS tooling**
(`certutil -N`). Its `pkcs11.txt` bytes are committed **exactly as NSS wrote
them** -- no reflowing, no reordering, no whitespace normalization, no
substitution of a synthetic "preferred" layout. That is the point of the
fixture: it proves at least one genuinely NSS-generated marker satisfies the
bounded HG-041 grammar as written.

These are disposable test artifacts. **No production credentials, certificates,
or private keys are present**, and no test certificate or key object was
generated at all: the database set is empty apart from the structures
`certutil -N` creates for a new, empty SQL database with an empty password.

## Runtime boundary

HarvestGuard's HG-041 detection **never** executes NSS tooling and **never**
opens or unlocks these databases. `certutil` (and `modutil`, `pk12util`,
`sqlite3`, and Python's `sqlite3`) were used **only here, once, to generate the
fixture**. At scan time:

- `cert9.db` and `key4.db` are presence/eligibility checked only -- they are
  never opened, read, parsed, locked, copied, or enumerated;
- `pkcs11.txt` is read as text by the scanner's existing single-read file
  context and parsed with a pure-Python line parser;
- no NSS or SQLite library, CLI, or FFI binding is loaded or invoked;
- no password is requested, accepted, read from the environment, or guessed;
- the `configdir` value is never resolved, followed, or emitted.

## Generation environment

- **Operating system / container:** Ubuntu 24.04.4 LTS (GitHub-hosted runner
  image, x86-64)
- **NSS version:** NSS 3.98 (Debian/Ubuntu package `libnss3` /
  `libnss3-tools`, version `2:3.98-1ubuntu0.2`)
- **Tool:** `certutil` from `libnss3-tools 2:3.98-1ubuntu0.2`

Exact generation commands (run in a disposable temporary directory, then copied
into this fixture tree):

```sh
mkdir -p /tmp/hg041/valid_empty
certutil -N -d sql:/tmp/hg041/valid_empty --empty-password
```

`--empty-password` is used deliberately so no passphrase exists to record, and
no key material beyond NSS's own empty-database structures is created.

Because `certutil` records its own `-d` argument in the marker, the committed
`pkcs11.txt` contains `configdir='sql:/tmp/hg041/valid_empty'`. That value is
an artifact of the generation path only. HarvestGuard treats it as opaque: it
is never resolved, compared to the scanned root, or emitted in a finding.

## Fixtures

### `valid_empty/pkcs11.txt`

- **Purpose:** the real NSS-generated internal-module marker; the
  fixture-grounded positive control for the HG-041 stanza grammar.
- **Source:** written by `certutil -N` (command above); committed byte-for-byte.
- **Size:** 433 bytes
- **SHA-256:** `6a9e85cb8ca0ab1b6b1f90377417acec1b92a3db40fc7b14d59005ef3ceb1a12`

### `valid_empty/cert9.db`

- **Purpose:** canonical supporting sibling for the aggregate set layout.
  Presence/eligibility evidence only; never opened by HarvestGuard.
- **Source:** written by `certutil -N` (command above).
- **Size:** 28672 bytes
- **SHA-256:** `e6e6ef70e28faeca5218504070dd14f8edf72b52131291523906a23a9c8ebfe0`

### `valid_empty/key4.db`

- **Purpose:** canonical supporting sibling for the aggregate set layout.
  Presence/eligibility evidence only; never opened by HarvestGuard.
- **Source:** written by `certutil -N --empty-password` (command above).
- **Size:** 36864 bytes
- **SHA-256:** `da5ecb39d75e315beeeeda8040f54b1da3c0a3dd6065b2d4a3232f6cd3208b4c`

## Generated test objects

**None.** No certificate, no private key, no symmetric key, and no PKCS #11
module was added to this database set. `key4.db` carries only the structures
NSS creates for a new database with an empty password.

## Grammar authority

The written HG-041 grammar (see `docs/CRYPTO_INVENTORY.md` and
`docs/DETECTION_CHARACTERIZATION.md`) is normative. This fixture demonstrates
that a real NSS-generated marker satisfies it; it does **not** implicitly
broaden it. A future NSS version that emits a valid marker outside the bounded
grammar is a documented false negative until an explicit follow-up issue widens
support.
