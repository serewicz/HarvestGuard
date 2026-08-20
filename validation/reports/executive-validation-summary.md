# Executive validation summary — Phase 1 (2026-08-18)

A short, non-specialist summary of what HarvestGuard's completed Phase 1
validation work demonstrates, what it does not demonstrate, and what could
follow. It summarizes evidence already committed to this repository; it is not a
new validation run and produces no new observation.

Every factual statement below comes from the linked artifacts:

- [Validation examples index](../examples/README.md)
- [Ubuntu 24.04.4 LTS report](2026-08-18-ubuntu-24.04-phase1.md)
- [AlmaLinux 9.8 report](2026-08-18-almalinux-9.8-phase1.md)
- [AlmaLinux completed transcript](../transcripts/2026-08-18-almalinux-9.8-phase1.txt)
- [AlmaLinux halted transcript](../transcripts/2026-08-18-almalinux-9.8-phase1-halted-run.txt)
- [Transcript sanitization guidance](../transcripts/README.md)

## How to read this summary

Four different kinds of statement appear in validation work, and they are kept
apart here:

- **Observed fact** — a directly recorded host, tool, command, status, count, or
  output.
- **Scanner inference** — what HarvestGuard classified from the material it
  inspected.
- **Validation outcome** — whether the expectations frozen before the scan and
  the observed results matched, including discrepancies and harness failures.
- **Recommended next action** — a bounded follow-up tied to an observed result
  or a known evidence gap.

A fifth kind — **business interpretation**, meaning any organization-specific
conclusion drawn from this evidence — is deliberately absent. These artifacts do
not supply it, and this summary does not attempt it.

## 1. What was validated

*Observed fact.* One complete operator-driven harness run per environment
generated a bounded corpus of cryptographic artifacts with native tools
(`openssl`, `ssh-keygen`), froze the corpus and the expectations for it before
any scan, ran the installed `harvestguard` command-line tool against that frozen
corpus, and compared observed output against the frozen expectations. Each of
those runs advanced through eight gates, and every gate required the operator to
type `continue`. One earlier AlmaLinux run stopped part-way; section 6 covers
it.

Only the crypto scan mode was exercised, in three output forms:

```text
harvestguard scan <workspace>/corpus --type crypto --max-depth 20
```

with the JSON and Markdown runs adding their respective output arguments.

## 2. Where and how it was validated

*Observed fact.*

| Environment | Detail |
| --- | --- |
| Ubuntu 24.04.4 LTS, `x86_64` | A Hyper-V **virtual machine** — not Debian stable, not WSL, not a container. Detected OS family `debian`. Python 3.12.13, `harvestguard 0.2.0`, OpenSSL 3.0.13. |
| AlmaLinux 9.8, `x86_64` | An **OCI container** (`almalinux:9` under Docker 28.0.4) — not RHEL, Rocky Linux, or CentOS Stream, and not a bare-metal or VM install. Detected OS family `rhel`. Python 3.12.13, `harvestguard 0.2.0`, OpenSSL 3.5.5. FIPS mode was not in effect. |

AlmaLinux is a RHEL-compatible distribution, but only AlmaLinux was run. That
the same detection logic would also match RHEL, Rocky Linux, or CentOS Stream is
an inference from the detection code, not an observation.

## 3. What evidence was produced

*Observed fact.*

| Environment | Committed evidence |
| --- | --- |
| Ubuntu | An operator-reviewed [report](2026-08-18-ubuntu-24.04-phase1.md). **No transcript is committed for the Ubuntu run.** |
| AlmaLinux | A [report](2026-08-18-almalinux-9.8-phase1.md) covering two runs, plus sanitized transcripts of the [completed run](../transcripts/2026-08-18-almalinux-9.8-phase1.txt) and the [halted run](../transcripts/2026-08-18-almalinux-9.8-phase1-halted-run.txt). |

All committed evidence is sanitized under the
[documented substitutions and exclusions](../transcripts/README.md): no
private-key body, PEM block, passphrase, plaintext or decrypted material, raw
secret value, proprietary path, confidential hostname, or reconstructable key
material appears in it. Per-file SHA-256 digests are elided, so these are
reports and transcripts, not archived manifests.

## 4. What passed

*Observed fact.* In each completed run, the frozen manifest contained 22
artifact records, all three scanner invocations returned exit status 0, and the
scan produced 17 findings and inspected 22 crypto files.

*Scanner inference.* Those 17 findings were classified into 17 cryptographic
inventory records. The scan also reported per-category counts — 6 certificates,
7 private keys, 7 encrypted keys, 3 SSH keys, 2 malformed assets, 0 PKCS#12, and
0 expired certificates — which the reports print as separate category totals
rather than as a partition of the 17 records. Three findings carried
finding-level errors; all three had been declared in advance as negative
controls (a header-only encrypted legacy key, a truncated DER certificate, and a
truncated PEM certificate).

*Validation outcome.* Both completed runs reported `discrepancy_count` 0 and
zero entries needing operator attention. For the documented hosts, tool
versions, generated artifacts, and `--type crypto` scan, the runs also showed
that every safety gate required explicit operator continuation, that the
manifest froze before scanning and was unchanged by comparison, and that an
unavailable optional tool produced a recorded skip rather than a failed run.
The AlmaLinux host additionally passed all eleven harness self-tests.

## 5. What was skipped, and why

*Observed fact.* The `age_encrypted` generator was skipped in both
environments, with the reason recorded as `age is not installed`. The `age` tool
was deliberately left uninstalled so that the optional-tool skip path was
exercised by a genuinely absent tool rather than by simulation. The skip
produced one `skipped_generator` record and did not fail either run.

*Validation outcome.* Nothing is established about `age`-encrypted formats by
these runs.

The `unsupported_generator` outcome was not exercised by either run, because no
Phase-1-unimplemented generator family was requested.

## 6. What failed or halted

*Observed fact.* An earlier AlmaLinux run on the same host and the same frozen
corpus resolved pandas 3.x. All three scanner invocations ran and returned exit
status 0, but the harness then raised
`TypeError: '<' not supported between instances of 'str' and 'float'` while
summarizing observed rule IDs: findings with no rule ID arrived as `NaN`, which
the harness did not normalize before sorting. The run stopped inside Stage 7,
before the Stage 7 review gate, the Stage 8 comparison, and the cleanup prompt.

*Observed fact.* The complete AlmaLinux eight-gate run used pandas below 3.0
(2.3.3), installed as **operator preparation** before the harness started. That
pin is part of the recorded environment, not a harness fix. A fresh install
resolving pandas 3.x stops at Stage 7.

This is a harness defect, not a scanner defect: the scanner invocations
completed in both runs. It is tracked separately as
[issue #140](https://github.com/serewicz/HarvestGuard/issues/140) and is
deliberately neither fixed nor concealed here.

*Observed fact.* Both reports also record a smaller harness defect: the tool
version probe runs `ssh-keygen -V`, which is a certificate validity-interval
option rather than a version flag, so `option requires an argument -- V` was
recorded in place of an OpenSSH version.

## 7. What remains unknown or unvalidated

*Validation outcome.* Unless a source artifact explicitly says otherwise, these
runs establish nothing about:

- **Other distributions** — RHEL, Rocky Linux, CentOS Stream, and Debian stable
  were not run.
- **Other environment types** — RHEL-family bare-metal or VM installs were not
  run; Ubuntu was validated only in a Hyper-V VM.
- **Windows and WSL** — not validated, and not claimed to be supported.
- **Other architectures** — `x86_64` only; `aarch64`, `ppc64le`, and other
  builds are unvalidated.
- **FIPS mode** — off during the AlmaLinux run, and the Ubuntu report records no
  FIPS observation. FIPS-restricted behavior is unexercised.
- **Other scan modes** — only `--type crypto` was exercised.
- **Skipped generator paths** — including `age_encrypted`, and any format family
  outside the Phase 1 generator set.
- **Format support in general** — each run validates the specific bytes it
  generated, on that host, with those tool versions.

Neither run establishes complete inventory, complete format support, complete
real-world validation, production readiness, compliance, quantum readiness or
HNDL exposure, remediation priority, exploitability, runtime exposure, business
risk, or the absence of cryptographic material anywhere.

## 8. What should happen next

*Recommended next actions*, each tied to an observed result or a stated evidence
gap above, listed in no particular order and carrying no risk, compliance, or
business conclusion:

1. Resolve the pandas 3.x `NaN` / missing-`rule_id` harness defect under
   [#140](https://github.com/serewicz/HarvestGuard/issues/140), so a default
   dependency resolution can complete Stage 7 without an operator pin.
2. Correct the `ssh-keygen` version probe so the manifest records a version
   rather than a usage error.
3. Capture and commit a sanitized Ubuntu transcript, so both validated families
   have transcript-level evidence rather than a report alone.
4. Run the harness where `age` is available, so the `age_encrypted` generator
   and its expectations are exercised rather than skipped.
5. Extend validation to configurations listed as unknown above — other
   RHEL-family distributions, bare-metal or VM RHEL-family execution,
   non-`x86_64` architectures, and FIPS mode — where an operator needs evidence
   for them.
6. Exercise scan modes other than `--type crypto`.

Whether any of these matters for a given organization, and in what order, is a
business interpretation that this evidence does not supply.
