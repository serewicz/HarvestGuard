# HarvestGuard Release and Reproducibility (v0.1)

How a HarvestGuard release is identified, what a controlled-pilot user can
verify about an artifact, and what is deliberately deferred before 1.0.

This document covers release identity only. It adds no product capability and
makes no claim about what the scanners detect — that lives in
[DETECTION_CHARACTERIZATION.md](DETECTION_CHARACTERIZATION.md), and the
classification of every product claim lives in
[CLAIMS_AUDIT.md](CLAIMS_AUDIT.md).

Release notes for v0.1.0 are in [CHANGELOG.md](../CHANGELOG.md).

## Version identity

`0.1.0` is declared in exactly two places, which are asserted to match by
`tests/test_release_identity.py`:

| Location | Purpose |
| --- | --- |
| `pyproject.toml` `[project] version` | Package metadata; what `pip` records for an installed HarvestGuard |
| `harvestguard_version.py` `__version__` | Runtime constant; what the CLI and reports print |

Nothing else hard-codes the product version. The normalized finding schema
carries its own independent `schema_version` (`1.0.0`), and the Markdown report
carries its own generator/format version (`harvestguard-report 0.1.0`); neither
tracks the product version and neither should be read as one.

## Identifying the version that produced an artifact

| Path | Command / field | Notes |
| --- | --- | --- |
| Installed CLI | `harvestguard --version` (or `-V`) | Prints `harvestguard 0.1.0` |
| Repository checkout | `python -m harvestguard --version` | Same output without installing |
| Installed package metadata | `pip show harvestguard` | Reports the `pyproject.toml` version |
| Markdown report | *Scan Information* → `HarvestGuard Version` | Recorded in the artifact itself |
| Container image | image digest (`ghcr.io/serewicz/harvestguard@sha256:…`) and its SBOM attestation | Images are tagged by commit SHA, not by product version — see [Container artifacts](#container-artifacts) |

**JSON output carries no version field, by design.** `--json` emits a bare
array of normalized findings (the HG-007 contract); wrapping it in a report
envelope to carry release metadata would break every existing consumer, so
HG-011 deliberately did not add one. Each finding still carries its own
`schema_version` and per-scanner `provenance` (`scanner_name`,
`scanner_version`). To bind a JSON artifact to a HarvestGuard release, either
record `harvestguard --version` alongside it, or generate the Markdown report
from the same scan, which states the version in *Scan Information*.

## Pre-1.0 status and support

HarvestGuard v0.1 is a **controlled diligence pilot** release: intended for
evaluation by a small number of technically competent users on targets they are
authorized to scan, not for unattended or production-critical use.

- Only `main` is supported. There are no release branches and no backports;
  fixes land on `main` and ship in the next version. See
  [SECURITY.md](../SECURITY.md#supported-versions).
- Pre-1.0 versions may change CLI flags, Markdown report sections, and
  documentation between releases. The normalized finding schema is versioned
  separately (`schema_version`) so a JSON consumer can detect a change.
- There is no update service, telemetry, or license check. HarvestGuard never
  phones home; local scans make no outbound network calls (see
  [SECURITY.md](../SECURITY.md#container-network-posture)).
- Security reports go to the private channel in [SECURITY.md](../SECURITY.md),
  not to public issues.

## Reproducing and identifying artifacts

### Source

The repository is the release artifact for v0.1. A specific state of it is
identified by commit SHA, and a release by the annotated tag `v0.1.0` pointing
at that commit:

```bash
git clone https://github.com/serewicz/HarvestGuard.git
cd HarvestGuard
git checkout v0.1.0          # once the tag is cut, see Release readiness below
git rev-parse HEAD           # the exact commit an artifact was produced from
```

### Python package

`pip install .` (or `pip install -e .`) builds from that checkout with
setuptools; HarvestGuard is **not published to PyPI**, so there is no released
wheel or sdist to verify a hash against.

Runtime dependencies in `requirements.txt` are declared as **minimum versions**
(`>=`), not exact pins, and the repository has no lock file. Two installs on
different days can therefore resolve different dependency versions: an install
is *identified*, not bit-for-bit reproducible. To record exactly what a given
environment resolved to, capture it at install time:

```bash
pip freeze > harvestguard-environment.txt
```

Hash-pinned requirements or a lock file is deferred work (see below).

### Container artifacts

`Dockerfile` builds a distroless, non-root, read-only-compatible image that
runs the **Streamlit dashboard only** — `harvestguard.py` and `reports.py` are
deliberately not copied into it, so the CLI (and therefore `--version`) is not
available inside the image. Identify a published image by digest, not by tag.

Images published from `main` by `.github/workflows/container-build.yml` are:

- tagged with the **commit SHA** they were built from (there is no
  `:v0.1.0` or `:latest` tag);
- signed keylessly with Sigstore/cosign via GitHub Actions' OIDC token;
- accompanied by a CycloneDX SBOM generated with syft and attached as a signed
  attestation, which is what actually records the exact dependency versions
  inside a given image.

Verification commands are in
[SECURITY.md](../SECURITY.md#verifying-the-container-image). A local
`docker build` reproduces the *recipe*, not the bytes: the base images
(`python:3.11-slim`, `gcr.io/distroless/python3-debian12:nonroot`) are
tag-referenced rather than digest-pinned, and dependency resolution is
unpinned, so a rebuild is not expected to match a published digest.

## SBOM, signing, and provenance status

Classified with the same five categories as [CLAIMS_AUDIT.md](CLAIMS_AUDIT.md).

| Capability | Classification | Evidence / limitation |
| --- | --- | --- |
| Version identifier in package metadata and at runtime | Implemented and tested | `pyproject.toml`, `harvestguard_version.py`, `tests/test_release_identity.py` |
| Markdown report states the producing HarvestGuard version | Implemented and tested | *Scan Information* → `HarvestGuard Version`; `tests/test_release_identity.py` |
| Version identity in JSON output | Explicitly out of scope | Would require a report envelope, which would break the HG-007 bare-array contract |
| Container image signing (keyless cosign) | Experimental / Needs Validation | Configured in `.github/workflows/container-build.yml` and tested end to end locally, but the keyless OIDC path can only run inside GitHub Actions and had not yet produced a published, verifiable image when this was written ([CLAIMS_AUDIT.md](CLAIMS_AUDIT.md), [SECURITY.md](../SECURITY.md#verifying-the-container-image)) |
| CycloneDX SBOM for the container image | Experimental / Needs Validation | Same workflow, same limitation; SBOM covers the *image*, not a source or wheel artifact |
| SBOM for the source/Python package | Planned | No SBOM is generated for a non-container install |
| SLSA build provenance attestation | Planned | The workflow signs the image and attests an SBOM; it does not produce a SLSA provenance attestation |
| Bit-for-bit reproducible builds | Planned | Unpinned dependencies, tag-referenced base images, no lock file (see above) |
| Published release binaries, wheels, or PyPI distribution | Explicitly out of scope | v0.1 installs from a source checkout |
| Signed git tags | Planned | The v0.1.0 tag procedure below does not require a GPG-signed tag |

## Release procedure (v0.1)

Deliberately minimal and manual — v0.1 needs identifiable artifacts, not
release automation.

1. Confirm the release readiness gate below is satisfied.
2. Confirm `main` is green: `ruff check .` and `pytest -v`.
3. Confirm the version literal in `pyproject.toml` and `harvestguard_version.py`
   matches the version being released.
4. Move the version's entry in [CHANGELOG.md](../CHANGELOG.md) from candidate to
   released, with the release date.
5. Tag the release commit on `main` and push the tag:
   `git tag -a v0.1.0 -m "HarvestGuard v0.1.0" && git push origin v0.1.0`.
6. Publish a GitHub release for the tag whose notes are that changelog entry.
7. Record the commit SHA of the tag; the container image published from that
   commit is the corresponding image (identified by its digest).

Post-1.0 releases repeat this with the version bumped in both locations from
step 3.

## Release readiness gate

v0.1 is the capstone of Milestone 2, which HG-008, HG-009, HG-010, and HG-011
share. Every item is now `Complete`; the milestone is fully delivered.

| Item | Status | Source |
| --- | --- | --- |
| HG-008 End-to-end validation | Complete | [ROADMAP.md](ROADMAP.md), `tests/test_end_to_end_validation.py` |
| HG-009 Confidence and detection characterization | Complete | [DETECTION_CHARACTERIZATION.md](DETECTION_CHARACTERIZATION.md) |
| HG-010 Product claims and trust audit | Complete | [CLAIMS_AUDIT.md](CLAIMS_AUDIT.md) |
| HG-011 Release identity and reproducibility | Complete | This document + [CHANGELOG.md](../CHANGELOG.md) |

**The `v0.1.0` tag has not been created.** HG-008 through HG-011 are all
`Complete`, and the controlled-pilot implementation and closure reviews are
finished. Creating and pushing the `v0.1.0` tag, and publishing the GitHub
release for it, is a separate, deliberate human release action performed
after this post-closure documentation reconciliation is reviewed and merged
— not a sign that any roadmap dependency remains incomplete. The repository
is ready for that action once this change lands. No release tag, GitHub
Release, PyPI artifact, or version-tagged (`:v0.1.0`) container image exists
yet.
`tests/test_release_identity.py` enforces this deterministically from
repository content: it checks that HG-008 through HG-011 all read `Complete`,
and that release documentation neither claims the tag already exists nor
blames an incomplete dependency for its absence.

## Deferred work

Recorded here so a pilot user is not left inferring it from silence:

- hash-pinned requirements or a lock file, and digest-pinned container base
  images, for reproducible rather than merely identified builds;
- SBOM for source/package installs, not just the container image;
- SLSA build provenance attestation;
- signed git tags and published release artifacts (wheel/sdist, PyPI);
- version-tagged container images (`:v0.1.0`) alongside the commit-SHA tags;
- CLI availability inside the container image, which currently runs the
  dashboard only.
