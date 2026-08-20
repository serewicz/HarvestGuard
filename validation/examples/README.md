# Validation examples

This index shows what the HG-045 Phase 1 validation harness produces before you
run it. It points to sanitized evidence from completed Ubuntu and AlmaLinux
validation work; it does not create or reproduce a new validation run.

## Reports, transcripts, and illustrations

- A **report** is the operator-reviewed summary of a run: environment, tools,
  generator outcomes, scanner invocations, comparison, findings, and limits.
- A **transcript** is the sanitized stdout and stderr seen by the operator. It
  preserves the gate sequence and raw Stage 7 output. Where a report and
  transcript overlap, the transcript is the primary record.
- An **illustration** demonstrates control flow but is not run evidence. The
  abbreviated [`gate-transcript.md`](gate-transcript.md) is illustrative only.

Reports and transcripts link to existing artifacts rather than copying their
contents here. For a non-specialist summary of what this evidence does and does
not demonstrate, see the
[executive validation summary](../reports/executive-validation-summary.md).

## Available run evidence

| Environment | Evidence | Result |
| --- | --- | --- |
| Ubuntu 24.04.4 LTS, `x86_64`, Hyper-V VM; detected family `debian` | [report](../reports/2026-08-18-ubuntu-24.04-phase1.md) and [environment notes](../environments/ubuntu-debian.md) | Complete eight-gate run. No transcript is committed. |
| AlmaLinux 9.8, `x86_64`, OCI container; detected family `rhel` | [report](../reports/2026-08-18-almalinux-9.8-phase1.md), [completed transcript](../transcripts/2026-08-18-almalinux-9.8-phase1.txt), [halted transcript](../transcripts/2026-08-18-almalinux-9.8-phase1-halted-run.txt), and [environment notes](../environments/rhel.md) | One pandas 3.x run halted inside Stage 7; one operator-prepared run with pandas below 3.0 completed all eight gates. |

Both completed runs used this Stage 7 command shape, with the JSON and Markdown
variants adding their output arguments:

```text
harvestguard scan <workspace>/corpus --type crypto --max-depth 20
```

In both environments, the OpenSSL and OpenSSH generators ran. The optional
`age_encrypted` generator was skipped because `age` was unavailable. The
console, JSON, and Markdown scanner invocations returned status 0; each frozen
manifest contained 22 artifact records, the scan produced 17 findings, and the
completed comparison reported `discrepancy_count` 0. Read the reports for the
record-level categories, negative controls, and host-specific limitations.

## How to read the evidence

Start with the report for the environment you care about:

1. **Environment and native tools** identify the host, execution environment,
   versions, and unavailable optional tools.
2. **Generator outcomes** distinguish generators that ran from generators that
   were skipped and record the reason.
3. **Corpus and frozen manifest** describe what was fixed before scanning.
4. **Stage 7 invocations** record the redacted command shapes and every exit
   status.
5. **Stage 8 comparison** records the outcome categories and discrepancies.
6. **Findings and limitations** explain observed defects and the boundary of the
   run.

For AlmaLinux, use the transcripts to follow the real gate sequence and raw
output. Search for `STAGE 1 of 8`, `Running: harvestguard scan`,
`Exit status`, and `STAGE 8 of 8` rather than relying on line numbers.

## Why the AlmaLinux run halted

The halted transcript records a fresh environment that resolved pandas 3.x.
All three scanner invocations ran and returned status 0, but the harness then
raised a mixed-type sorting `TypeError` while summarizing missing `rule_id`
values represented as `NaN`. The run stopped before the Stage 7 review gate,
comparison, and cleanup prompt.

The completed transcript uses the same host and frozen corpus with pandas pinned
below 3.0 as operator preparation. That run completed all eight gates and
reported zero discrepancies. This workaround is part of the recorded
environment, not a harness fix. [Issue #140](https://github.com/serewicz/HarvestGuard/issues/140)
tracks the pandas 3.x defect separately.

## What these examples prove

For the documented hosts, tool versions, generated artifacts, and
`--type crypto` scan:

- each safety gate required explicit operator continuation;
- the manifest froze before scanning and remained unchanged by comparison;
- Stage 7 invoked the installed `harvestguard` command and recorded invocation
  statuses;
- an unavailable optional tool produced a recorded skip rather than failing the
  complete run; and
- observed results matched the expectations frozen for the completed runs.

## What these examples do not prove

They do not establish:

- complete format support, complete inventory, or complete real-world
  validation;
- production readiness, compliance, quantum readiness, remediation priority,
  runtime exposure, business risk, or absence of cryptographic material;
- behavior for formats whose generators were skipped, including `age_encrypted`;
- RHEL, Rocky Linux, CentOS Stream, or Debian stable validation;
- Windows, WSL, non-`x86_64`, or FIPS-mode validation; or
- scanner modes other than `--type crypto`.

Ubuntu was validated in a Hyper-V VM, not WSL or a container. AlmaLinux was
validated in an OCI container, not on RHEL-family bare metal or a VM. The
AlmaLinux pandas 3.x transcript proves only the documented Stage 7 failure.

## Sanitization

The committed evidence follows the substitutions and exclusions in the
[transcript sanitization guidance](../transcripts/README.md). It must not contain
private-key bodies, PEM blocks, passphrases, plaintext or decrypted material,
raw secret values, proprietary paths, confidential hostnames, or reconstructable
key material.
