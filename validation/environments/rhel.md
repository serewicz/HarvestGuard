# RHEL family: RHEL, CentOS Stream, Rocky, AlmaLinux

Phase 1 has been run end to end on a RHEL-family host — AlmaLinux 9.8. This file
records what was actually validated there and what an operator still has to
supply. It is execution guidance, not an installer: the harness never invokes
`dnf`, `yum`, or any other package manager, and nothing here should be turned
into automation. CentOS Stream has its own note in
[`centos-stream.md`](centos-stream.md).

## Validated configuration

One complete eight-gate run, with a sanitized report in
[`../reports/2026-08-18-almalinux-9.8-phase1.md`](../reports/2026-08-18-almalinux-9.8-phase1.md)
and sanitized transcripts in [`../transcripts/`](../transcripts/).

| Item | Validated value |
| --- | --- |
| Distribution | AlmaLinux 9.8 (`ID=almalinux`, `ID_LIKE="rhel centos fedora"`) |
| Detected OS family | `rhel` |
| Architecture | `x86_64` |
| Environment | OCI container from the `almalinux:9` image — not a bare-metal or VM install |
| Shell | GNU bash 5.1.8 |
| Python | 3.12.13, from the `python3.12` AppStream package |
| HarvestGuard | `harvestguard 0.2.0`, installed CLI on `PATH` |
| Native tools present | `openssl` 3.5.5, `ssh-keygen` present (version field limitation below) |
| Native tools missing | `age` — its generator was skipped |
| FIPS mode | off |
| Discrepancies | 0 |

RHEL itself, Rocky Linux, and CentOS Stream have not been run. All of them carry
`rhel` in `ID` or `ID_LIKE`, which is what `lib/env_inspect.sh` matches, so they
are expected to detect identically — but that is an inference from the detection
code, not a validated observation.

## Operator preparation

Target RHEL 8 or 9, or an equivalent RHEL-compatible release, as an ordinary
user. Package names are for reference only; install them yourself, or don't — a
missing optional tool is a recorded skip, not a failure.

| Tool | RHEL-family package | Needed for |
| --- | --- | --- |
| `openssl` | `openssl` | four of six generators; the harness refuses to run with no generator available |
| `ssh-keygen` | `openssh-clients` | `openssh_host_identity` |
| `python3` (3.10+) | `python3.12` on RHEL 9 | `harness_tool.py` freeze, summarize, compare, and the HarvestGuard package itself |
| `age`, `age-keygen` | not in base or AppStream; an approved source for the host | `age_encrypted`, optional |

```bash
sudo dnf install -y openssl openssh-clients python3.12
harvestguard --version
```

RHEL 9's default `python3` is 3.9, below the `requires-python = ">=3.10"` floor
of the HarvestGuard package. Install and use a 3.10+ interpreter — the validated
run used `python3.12` through a virtual environment, so that the same
interpreter served both `harness_tool.py` and the installed CLI.

The Debian-family note names `openssh-client`, singular. That difference is
documentation only — no harness code branches on it.

Run from the repository checkout:

```bash
./validation/run-validation.sh --workspace "$HOME/hgval-$(date -u +%Y%m%d)"
```

Review every disclosure and type exactly `continue` or `abort`. Stage 5 accepts
independently created files under `corpus/operator-supplied`; undeclared files
remain blind observations. Missing optional tools skip only their generator.

## Behavior confirmed on this family

- OS-family detection reads `/etc/os-release` only, and mapped `ID=almalinux`
  with `ID_LIKE="rhel centos fedora"` to family `rhel`.
- No `/etc/redhat-release` file and no `rpm` query is required.
- No package manager is invoked at any stage. Generators detect their tool by
  executable availability (`command -v`) plus behavior, never by querying a
  package database.
- Missing optional tools are recorded as `skipped_generator` and remain visible
  in the frozen manifest and both reports — `age` produced exactly one such
  record and the run continued through all eight gates.
- The eight gates each require an explicit `continue`; the manifest freezes at
  stage 6 before the stage 7 scan; stage 7 invokes only the installed
  `harvestguard` executable; console, JSON, and Markdown exit statuses are
  written to `results/scan-invocations.tsv` before comparison runs.
- Comparison ran only after the stage 7 raw-output review gate, and left the
  frozen manifest unchanged.
- `generated`, `operator-supplied`, `blind`, and `skipped` categories stayed
  distinct in the comparison report.
- Cleanup required the literal word `delete`; answering `keep` retained the
  workspace.
- `--dry-run` stayed bounded: 93 ms, nine files, 4,610 bytes, no scanner and no
  cryptographic tool invoked.
- `validation/selftest/run.sh` passed all eleven checks here, including the
  symlink rejection at freeze.

## Known limitations

- **A fresh install resolving pandas 3.x could not finish stage 7 at the time
  of this run.** With pandas 3.0.5, `harvestguard scan --json` writes float
  `NaN` for findings with no rule ID; `harness_tool.py summarize` treated NaN as
  a present value and died sorting mixed `str` and `float` keys, which under
  `set -e` aborted the whole run mid-stage-7. The validated run above pinned
  pandas below 3.0 as operator preparation. Both the halted and the complete run
  are documented in the report. The harness has since been fixed: missing rule
  IDs normalize to `(none)` whether they arrive as `None`, `NaN`, an empty
  string, or an absent key, and a summarize failure is now recorded in
  `results/harness-stage-failures.tsv` and carried into the comparison instead
  of aborting before the stage 7 review gate. Pinning pandas is no longer
  required; this environment note still records what the original run observed.
- The harness probes `ssh-keygen` with `ssh-keygen -V`, but `-V` is a
  certificate validity-interval option rather than a version flag, so the
  recorded value is the usage error `option requires an argument -- V` instead
  of an OpenSSH version.
- OpenSSL 3.5.5 here produced the legacy encrypted PEM on the generator's first
  attempt (`openssl genrsa -aes128 -traditional`), so no legacy-PEM skip was
  recorded. Under FIPS policy legacy encryption may be unavailable; record that
  environment fact in the Stage 2 operator note rather than changing the
  generator. The FIPS path is unvalidated — FIPS mode was off.
- Container execution only. Privilege, volume-level, and `systemd-detect-virt`
  observations would differ on a bare-metal or VM install, and `uname` reports
  the container host's kernel.
- `x86_64` only. RHEL, Rocky, CentOS Stream, non-`x86_64` architectures, and
  RHEL 8 are all unvalidated.
- Only `--type crypto` was scanned. Other scan types were not exercised.
- The `age_encrypted` generator is unvalidated on this family, because `age` was
  absent. Installing `age` from a source approved for the host and re-running is
  the way to close that gap.
- Stage 5 promotes an operator file from `blind` to `operator-supplied` only when
  the declaration line carries a rule ID in its third tab-separated field.
- One run on one host with one set of tool versions.

After stage 8, archive only `state/manifest.json` and the two validation reports
described in `validation/manifests/README.md`. Never archive corpus or scratch
material.
