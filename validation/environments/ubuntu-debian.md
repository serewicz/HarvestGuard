# Ubuntu and Debian

Phase 1 has been run end to end on a Debian-family host. This file records what
was actually validated and what operators must supply themselves. It is
execution guidance, not an installer: the harness never invokes `apt`,
`apt-get`, or any other package manager, and nothing here should be turned into
automation.

## Validated configuration

One complete eight-gate run, with a sanitized report in
[`../reports/2026-08-18-ubuntu-24.04-phase1.md`](../reports/2026-08-18-ubuntu-24.04-phase1.md).

| Item | Validated value |
| --- | --- |
| Distribution | Ubuntu 24.04.4 LTS (`ID=ubuntu`, `ID_LIKE=debian`) |
| Detected OS family | `debian` |
| Architecture | `x86_64` |
| Environment | Hyper-V virtual machine — not a container, not WSL |
| Shell | GNU bash 5.2.21 |
| Python | 3.12.13 |
| HarvestGuard | `harvestguard 0.2.0`, installed CLI on `PATH` |
| Native tools present | `openssl` 3.0.13, `ssh-keygen` (OpenSSH 9.6p1) |
| Native tools missing | `age` — its generator was skipped |
| Discrepancies | 0 |

Debian stable itself has not been run. `ID_LIKE=debian` is what
`lib/env_inspect.sh` matches, so Debian is expected to detect identically, but
that is an inference from the detection code and not a validated observation.

## Operator preparation

Package names for reference only. Install them yourself, or don't — a missing
optional tool is a recorded skip, not a failure.

| Tool | Debian/Ubuntu package | Needed for |
| --- | --- | --- |
| `openssl` | `openssl` | four of six generators; the harness refuses to run with no generator available |
| `ssh-keygen` | `openssh-client` | `openssh_host_identity` |
| `python3` | `python3` | `harness_tool.py` freeze, summarize, compare |
| `age`, `age-keygen` | `age` (Debian 12+, Ubuntu 22.04+) | `age_encrypted`, optional |

The RHEL and CentOS Stream notes name `openssh-clients`; the Debian-family
package is `openssh-client`, singular. That difference is documentation only —
no harness code branches on it.

`age` was left uninstalled during validation on purpose, so the optional-tool
skip path was exercised by a genuinely absent tool. It produced one
`skipped_generator` record naming `age is not installed`, and the run continued
through all eight gates to a clean comparison.

## Behavior confirmed on this family

- OS-family detection reads `/etc/os-release` only, and mapped `ID=ubuntu` to
  family `debian`.
- No RHEL or CentOS path is required: no `/etc/redhat-release`, no `rpm` query,
  no `dnf`.
- No package manager is invoked at any stage. Generators detect their tool by
  executable availability (`command -v`) plus behavior (running the tool for its
  version), never by querying a package database.
- Missing optional tools are recorded as `skipped_generator` and remain visible
  in the frozen manifest and both reports.
- The eight gates each require an explicit `continue`; the manifest freezes at
  stage 6 before the stage 7 scan; stage 7 invokes only the installed
  `harvestguard` executable; console, JSON, and Markdown exit statuses are
  written to `results/scan-invocations.tsv` before comparison runs.
- `generated`, `operator-supplied`, `blind`, and `skipped` categories stayed
  distinct in the comparison report.
- Cleanup required the literal word `delete`; answering `keep` retained the
  workspace.
- `--dry-run` stayed bounded: under a second, nine files, about 4.5 KB, no
  scanner and no cryptographic tool invoked.

## Known limitations

- Debian stable, non-`x86_64` architectures, WSL, and container execution are
  all unvalidated. Under a container the volume-level and privilege observations
  in particular would differ, and `systemd-detect-virt` reporting would change.
- Only `--type crypto` was scanned. Other scan types were not exercised.
- The `age_encrypted` generator is unvalidated on this family, because `age` was
  absent. Installing `age` and re-running is the way to close that gap.
- `unsupported_generator` was not exercised by this run; only
  `validation/selftest/run.sh` covers it.
- Stage 5 promotes an operator file from `blind` to `operator-supplied` only when
  the declaration line carries a rule ID in its third tab-separated field. An
  asset-type-only declaration is silently treated as blind. Declare a rule ID if
  you want the file scored.
- One run on one host with one set of tool versions. It validates those bytes on
  that host, not the format families in general.
