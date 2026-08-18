# HarvestGuard Phase 1 real-world validation harness (HG-045)

This operator-driven harness generates a bounded corpus with native tools,
freezes expectations before scanning, invokes the installed `harvestguard` CLI,
and reports observations for human review.

It is **not** a unit-test replacement, proof of complete format support, a
scanner implementation, or evidence that every valid variant is supported. A
generated artifact that passes validates only those bytes on that host.

## Run it

```bash
./validation/run-validation.sh --workspace /tmp/hg-validation
./validation/run-validation.sh --dry-run --workspace /tmp/hg-validation-dry-run
```

Interactive mode is the default. Each of the eight gates advances only after
the operator types exactly `continue`; `abort` stops and preserves the
workspace. Empty or unrecognized input never advances. Dry-run auto-advances
the same eight gates using mock records and never claims cryptographic
validation, scanner validation, or format support.

The harness installs nothing, invokes no package manager, uses no network by
default, and writes only inside its marked validation workspace. Stage 7 uses
only an installed `harvestguard` executable and scans only the frozen corpus.

## Eight gated stages

1. Environment inspection
2. Validation plan
3. Generate real artifacts
4. Human inspection
5. Add independent operator files
6. Freeze corpus and expectations
7. Run and review raw results
8. Compare, report, and cleanup

Generated and operator-supplied files remain separate. Operator files are never
modified. Undeclared operator files are blind observations and are never
automatically scored. Stage 6 refuses to overwrite an existing frozen manifest,
and comparison writes reports without changing the manifest. Cleanup requires
an explicit `delete`; otherwise the workspace remains intact.

## Phase 1 generator contract

Generator commands and their mapping to the eight approved format cases are in
[`generators/README.md`](generators/README.md). Missing optional tools produce a
recorded generator skip, not a whole-harness failure. `age` is optional.
Unavailable optional tools are reported as `skipped_generator`; the separate
`unsupported_generator` outcome is reserved for generator identifiers or
families that this Phase 1 harness does not implement.

No CMS, gocryptfs, Java keystore, Kubernetes TLS Secret, NSS, OpenPGP, or PKCS#12
generator is part of Phase 1.

## Safety and privacy

- Generated passphrases are disposable and passed through environment variables.
- Recorded commands redact passphrases, tokens, secrets, and secret arguments.
- Scratch plaintext and key-generation intermediates live outside the scan root.
- Generated artifacts, operator files, state, results, and scratch data all live
  beneath the validation workspace.
- The comparison checks outputs for the per-run secret marker and private-key
  block headers.
- Cleanup checks the workspace marker and requires explicit confirmation.
- Manifest freeze rejects symbolic links in the corpus before hashing, so it
  never follows a link target outside the workspace.

## Platform scope

OS-family detection is isolated in `lib/env_inspect.sh`. Per-family execution
notes live in [`environments/`](environments/); package names there are operator
guidance only, never installer logic.

Ubuntu 24.04.4 LTS on `x86_64` has been validated end to end — one complete
eight-gate run, zero discrepancies, `age` deliberately absent so the
optional-tool skip path was exercised by a genuinely missing tool. See
[`environments/ubuntu-debian.md`](environments/ubuntu-debian.md) for the
validated configuration and its limitations, and
[`reports/2026-08-18-ubuntu-24.04-phase1.md`](reports/2026-08-18-ubuntu-24.04-phase1.md)
for the sanitized report. Debian stable, other architectures, WSL, and container
execution remain unvalidated. RHEL and CentOS Stream have manual execution notes
but no recorded run.

Sanitized run reports live in [`reports/`](reports/). Archiving a run's frozen
manifest and result files is separate and described in
[`manifests/README.md`](manifests/README.md) — never archive corpus or scratch
material.

## Self-tests

Shell-based harness self-tests are intentionally outside default pytest and CI:

```bash
./validation/selftest/run.sh
```

They cover gates, abort preservation, workspace containment, redaction,
manifest immutability, comparison immutability, blind observations, cleanup
confirmation, and the bounded dry-run.
