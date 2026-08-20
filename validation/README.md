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

Two families have been validated end to end, each with one complete eight-gate
run, zero discrepancies, and `age` deliberately absent so the optional-tool skip
path was exercised by a genuinely missing tool:

- **Debian family** — Ubuntu 24.04.4 LTS on `x86_64`, a Hyper-V virtual machine.
  See [`environments/ubuntu-debian.md`](environments/ubuntu-debian.md) and
  [`reports/2026-08-18-ubuntu-24.04-phase1.md`](reports/2026-08-18-ubuntu-24.04-phase1.md).
- **RHEL family** — AlmaLinux 9.8 on `x86_64`, in a container, detected as family
  `rhel`. See [`environments/rhel.md`](environments/rhel.md) and
  [`reports/2026-08-18-almalinux-9.8-phase1.md`](reports/2026-08-18-almalinux-9.8-phase1.md).
  That run also recorded a blocking harness defect: with pandas 3.x resolved,
  stage 7 aborted before its gate, so the complete run pinned pandas below 3.0.
  The harness has since been fixed — missing rule IDs normalize to `(none)`
  whatever their shape, and a summarize failure is recorded rather than
  aborting the run — so pinning pandas is no longer operator preparation.

RHEL itself, Rocky Linux, CentOS Stream, Debian stable, non-`x86_64`
architectures, and WSL remain unvalidated, as does bare-metal or VM execution of
the RHEL family. Each validated configuration and its limitations are in the
per-family note.

For a short, non-specialist account of what this completed validation work does
and does not demonstrate, read
[`reports/executive-validation-summary.md`](reports/executive-validation-summary.md).

Sanitized run reports live in [`reports/`](reports/), and sanitized gate
transcripts in [`transcripts/`](transcripts/). Archiving a run's frozen manifest
and result files is separate and described in
[`manifests/README.md`](manifests/README.md) — never archive corpus or scratch
material.

## See what a run produces first

[`examples/README.md`](examples/README.md) indexes the committed run evidence and
is the place to start if you want to know what the harness produces before
running it. It says which artifacts are authoritative run evidence and which are
illustrative only, where to find each element of a run — environment, command,
generators run and skipped, invocation exit statuses, comparison summary,
discrepancies, limitations — how the halted and completed AlmaLinux runs relate,
and what these runs do and do not prove.

## Self-tests

Shell-based harness self-tests are intentionally outside default pytest and CI:

```bash
./validation/selftest/run.sh
```

They cover gates, abort preservation, workspace containment, redaction,
manifest immutability, comparison immutability, blind observations, missing
rule-ID normalization in the stage 7 summary, durable recording of a harness
stage failure, cleanup confirmation, and the bounded dry-run.
