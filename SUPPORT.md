# Support

How to get help with HarvestGuard, and what level of support to expect.

HarvestGuard is a pre-1.0, open-source cryptographic asset inventory and
evidence-collection tool maintained by Timothy Serewicz. It is offered as-is
under the [Apache-2.0 licence](LICENSE), which includes its warranty and
liability disclaimers.

## What support exists

| Need | Channel | Expectation |
| --- | --- | --- |
| Question about running a scan, reading output, or installing | [GitHub Issues](https://github.com/serewicz/HarvestGuard/issues) | Best effort, no response-time commitment |
| Bug report or feature proposal | [GitHub Issues](https://github.com/serewicz/HarvestGuard/issues), following [CONTRIBUTING.md](CONTRIBUTING.md) | Best effort; non-trivial work starts from an issue |
| Security vulnerability | **Private** report per [SECURITY.md](SECURITY.md) — not a public issue | Per [SECURITY.md](SECURITY.md) |
| Code contribution | Pull request per [CONTRIBUTING.md](CONTRIBUTING.md) | Reviewed against the documented product boundary |

There is **no paid support tier, service-level agreement, uptime commitment,
hosted service, or guaranteed response time** for the open-source project, and
no support promise beyond the channels in the table above.

## Which version is supported

Only `main` is supported: HarvestGuard is pre-1.0, keeps no release branches,
and has no backport policy. Fixes land on `main` and ship in the next version.
See [SECURITY.md](SECURITY.md#supported-versions) and
[docs/RELEASE.md](docs/RELEASE.md#pre-10-status-and-support).

## Before opening an issue

These usually answer it faster than an issue can:

- [README Quickstart](README.md#quickstart) — run, review, and export a scan of
  the synthetic demo target.
- [docs/examples/first-run/](docs/examples/first-run/README.md) — committed
  sample JSON and Markdown output from exactly that demo scan.
- [docs/CLI.md](docs/CLI.md) — flags, exit codes, and how to read coverage from
  an artifact.
- [docs/DETECTION_CHARACTERIZATION.md](docs/DETECTION_CHARACTERIZATION.md) —
  what each scanner detects, what it can miss, and how to read `confidence`.
  Absence of a finding is not proof of absence.
- [docs/DECISIONS/ADR-006-product-boundary.md](docs/DECISIONS/ADR-006-product-boundary.md)
  — whether something is deliberately out of scope rather than missing.

When reporting a bug, include the output of `harvestguard --version`, your
operating system and Python version, the exact command you ran, and what you
expected instead. **Do not paste real scan output**: reports can contain file
paths, bucket and object names, and other sensitive identifiers. Reproduce
against `demo/sample_target/` where you can.

## Pilot feedback for v0.2.0

`v0.2.0` is a pre-1.0 pilot release. It has been exercised against this
repository's own fixtures and demo corpus, on a small number of machines, so
reports from other environments are genuinely useful — including reports that
nothing went wrong.

Open a [GitHub Issue](https://github.com/serewicz/HarvestGuard/issues) with:

- your operating system and Python version;
- how you installed it (`pip install harvestguard`, `pip install .` from a
  clone, `pip install -e .`, or a container);
- the exact command you ran;
- what you expected and what actually happened;
- sample output **only if it is safe to share** — the demo corpus output is
  always safe; and
- which of these it is: install, scan, output, documentation, or packaging.

**Never send** real secrets, private keys, certificates from production
systems, proprietary source trees, or scan output from real systems. Scan
reports legitimately contain file paths, bucket and object names, certificate
subjects and issuers, and other sensitive identifiers, so treat them as
confidential and reproduce against `demo/sample_target/` where you can. Suspected
vulnerabilities go to the private channel in [SECURITY.md](SECURITY.md), not to
a public issue.

This is a request for reports, not a support commitment: the expectations in
the table above are unchanged, and there is no response-time guarantee.

## Advisory work

HarvestGuard is an open-source evidence collection tool. Advisory work around
cryptographic inventory, PQC planning, technology diligence, and executive
reporting is available separately from Timothy Serewicz —
**tim@serewicz.com**.

That engagement is separate from this repository: it is not a support tier for
the open-source project, it does not change what the tool detects or what its
output claims, and nothing in it is required to use HarvestGuard. The
scanners' documented capabilities and limitations
([docs/DETECTION_CHARACTERIZATION.md](docs/DETECTION_CHARACTERIZATION.md),
[docs/CLAIMS_AUDIT.md](docs/CLAIMS_AUDIT.md)) are unaffected by it.
