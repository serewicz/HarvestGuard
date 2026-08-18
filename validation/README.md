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

## Platform scope

OS-family detection is isolated in `lib/env_inspect.sh`. RHEL and CentOS Stream
manual execution notes live in [`environments/`](environments/). Ubuntu/Debian
is not validated in Phase 1, but the harness does not reject it solely by OS
family. Its future package/tool mapping belongs only in
[`environments/ubuntu-debian.md`](environments/ubuntu-debian.md).

No archived RHEL/CentOS run is included yet. When one is available, archive
only the frozen manifest and result reports as described in
[`manifests/README.md`](manifests/README.md), never corpus or scratch material.

## Self-tests

Shell-based harness self-tests are intentionally outside default pytest and CI:

```bash
./validation/selftest/run.sh
```

They cover gates, abort preservation, workspace containment, redaction,
manifest immutability, comparison immutability, blind observations, cleanup
confirmation, and the bounded dry-run.
