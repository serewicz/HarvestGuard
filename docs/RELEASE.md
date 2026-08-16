# HarvestGuard Release and Reproducibility

How a HarvestGuard release is identified, what a controlled-pilot user can
verify about an artifact, and what is deliberately deferred before 1.0.

This document covers release identity only. It adds no product capability and
makes no claim about what the scanners detect — that lives in
[DETECTION_CHARACTERIZATION.md](DETECTION_CHARACTERIZATION.md), and the
classification of every product claim lives in
[CLAIMS_AUDIT.md](CLAIMS_AUDIT.md).

Release notes for v0.1.0 are in [CHANGELOG.md](../CHANGELOG.md). A maintainer
deciding whether to publish a release should read
[release and distribution decision](#release-and-distribution-decision-v02-preparation)
— it records the chosen path, the state of every open item, and what still
requires explicit authorization.

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
git checkout v0.1.0          # the existing annotated tag; see Release readiness below
git rev-parse HEAD           # the exact commit an artifact was produced from
```

### Python package

`pip install .` (or `pip install -e .`) builds from that checkout with
setuptools; HarvestGuard is **not published to PyPI**, so there is no released
wheel or sdist to verify a hash against. Either command installs the CLI's
runtime dependencies too — `pyproject.toml`'s `[project].dependencies` is
authoritative for an installed `harvestguard`, and `requirements.txt` is
repository-root convenience for the unpackaged Streamlit dashboard. Python 3.10+
is required (macOS's system Python 3.9 is not sufficient); see
[docs/CLI.md](CLI.md#installation).

Runtime dependencies are declared as **minimum versions** (`>=`), not exact
pins, and the repository has no lock file. Two installs on
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
6. Publish a GitHub release for the tag. Its notes are that changelog entry,
   unless the version being released has a prepared release-notes draft, in
   which case that draft is the notes — as for v0.2, at step 7 of the
   [proposed v0.2 release checklist](#proposed-v02-release-checklist).
7. Record the commit SHA of the tag and the digest of the container image built
   from that commit. An image exists for that commit only if
   `.github/workflows/container-build.yml` ran for it — its `push` trigger is
   path-filtered, so a version/changelog-only release commit needs an explicit
   `workflow_dispatch`, as at step 5 of the
   [proposed v0.2 release checklist](#proposed-v02-release-checklist).

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

**The annotated `v0.1.0` git tag exists.** HG-008 through HG-011 are all
`Complete`, and the controlled-pilot implementation and closure reviews are
finished. No GitHub Release has been published from that tag. Deciding whether
to publish one is a separate, deliberate maintainer release action — not a
sign that any roadmap dependency remains incomplete. HarvestGuard is not
published to PyPI, no released wheel or sdist exists, and neither `v0.1.0` nor
`v0.2.0` has a version-tagged container image.
`tests/test_release_identity.py` enforces this distinction deterministically
from repository documentation and local version identity, without network
access.

## v0.2 pre-1.0 release readiness audit

A bounded go/no-go evidence record for a **possible** v0.2 release. Producing it
created no `v0.2.0` tag, published no GitHub Release or PyPI/wheel/sdist
artifact, and changed no version literal;
every command in the [proposed v0.2 release checklist](#proposed-v02-release-checklist)
below is written for a later, explicitly authorized human release action and was
deliberately not executed.

This is an operational readiness check only. It is not evidence of product
completeness, cryptographic completeness, security, compliance, remediation
readiness, migration readiness, or quantum readiness, and it makes no claim
about what the scanners detect — that stays in
[DETECTION_CHARACTERIZATION.md](DETECTION_CHARACTERIZATION.md) and
[CLAIMS_AUDIT.md](CLAIMS_AUDIT.md).

### Audit basis

| Field | Value |
| --- | --- |
| Branch | `main` |
| Commit audited | `89c7bb8` |
| Declared version at that commit | `0.1.0` |
| Environment for the checks below | Linux, CPython 3.12, repository checkout run as `python -m harvestguard` (no install step) |

Every result recorded below is reproducible by running the command in its row
from the repository root. Rows that could not be verified from repository
content say so and become a maintainer action, not a passing check.

### Current state versus the proposed v0.2 release

The repository is **not** at v0.2 and does not describe itself as v0.2.

| Surface | Current state at the audited commit | What a v0.2 release would require |
| --- | --- | --- |
| `pyproject.toml` `[project] version` | `0.1.0` | a deliberate bump to `0.2.0`; not performed by this audit |
| `harvestguard_version.py` `__version__` | `0.1.0` | the same bump, in step |
| `harvestguard --version` | `harvestguard 0.1.0` | `harvestguard 0.2.0` |
| Git tags | `v0.1.0` exists — an annotated tag on commit `4598a4b`, an ancestor of the audited `main` — with no GitHub Release published from it | Given the existing `v0.1.0` tag, `v0.2.0` would be the repository's second version tag. Deleting or replacing `v0.1.0` would require a separate maintainer decision outside this audit |
| Release and package publication | No GitHub Release and no PyPI, wheel, or sdist publication exists. GHCR does contain commit-SHA container images plus signature/attestation objects, but no `v0.1.0` or `v0.2.0` version-tagged container image | out of scope for this audit; a later authorized action |
| [CHANGELOG.md](../CHANGELOG.md) | a `0.1.0` entry that accurately records the existing tag and missing GitHub Release, plus an `Unreleased` section that records no `0.2.0` entry or tag yet | a drafted `0.2.0` entry — since written, and marked unreleased, per [release and distribution decision](#release-and-distribution-decision-v02-preparation) |
| Roadmap milestones since the `0.1.0` entry | `v0.1.1 Stabilization` (HG-028…HG-032) and the `v0.2` cryptographic-inventory work (HG-033…HG-044) read `Complete` in [ROADMAP.md](ROADMAP.md) | those entries are the source material for the `0.2.0` release notes |

This audit checked tag existence directly — `git ls-remote --tags origin` and
`gh api repos/serewicz/HarvestGuard/tags` — rather than trusting prose, and
found that the annotated `v0.1.0` tag already exists. No GitHub Release or
PyPI package has been published. GHCR contains signed commit-SHA images and
signature/attestation objects, but no `v0.1.0` or `v0.2.0` version-tagged
image. Whether a `v0.1.0` GitHub Release is published from the existing tag
before or instead of a `v0.2.0` release is a maintainer decision (**B-1**
below); the factual release-surface state must be rechecked and recorded before
release action (**B-9**).

### Public-use prerequisites

The four public-use prerequisites are present in the audited commit and each
carries its own enforcing test. Running the four test files below together with
`tests/test_release_identity.py`, `tests/test_product_claims.py`, and
`tests/test_packaging_dependencies.py` passes (129 tests).

| Prerequisite | Artifact in the audited commit | Enforcing test |
| --- | --- | --- |
| Demo corpus for a safe first run | [`demo/sample_target/`](../demo/sample_target/README.md) — 4 synthetic files with a per-file manifest | `tests/test_demo_fixture.py` |
| Sample output for first-time users | [`docs/examples/first-run/`](examples/first-run/README.md) — `sample-findings.json`, `sample-report.md`, `generate_samples.py`, provenance | `tests/test_first_run_samples.py` |
| Quickstart: run, review, export | [README.md](../README.md) *Quickstart* | `tests/test_quickstart_docs.py` (including link/anchor resolution) |
| Executive-readable evidence example | [`docs/examples/executive-evidence-example.md`](examples/executive-evidence-example.md), linked from [EXECUTIVE_DELIVERABLES.md](EXECUTIVE_DELIVERABLES.md) | `tests/test_executive_evidence_example.py` |

**Limit of this evidence.** Repository content shows the four changes are
merged into `main`. It cannot show that the corresponding GitHub issues are
closed, that each merge was review-approved, or that the required checks were
green on the merged head — that state lives in the GitHub API, not in the
checkout. Confirming it is **B-5** below.

### Surface audit

| Surface | Check | Result at the audited commit |
| --- | --- | --- |
| Version identity | `python -m harvestguard --version`; `python -m pytest -v tests/test_release_identity.py` | `harvestguard 0.1.0`; the `pyproject.toml` literal and `harvestguard_version.__version__` agree and nothing else hard-codes the product version. Pass |
| Changelog | Read [CHANGELOG.md](../CHANGELOG.md) | The newest version entry is `0.1.0`, accurately records the existing tag and missing GitHub Release, and is followed by an `Unreleased` section. Work merged since it had no drafted version entry at the audited commit; one has since been drafted and marked unreleased. **B-3** |
| Installation | `python -m pytest -v tests/test_clean_install.py` (needs network; `HARVESTGUARD_SKIP_CLEAN_INSTALL_TESTS=1` skips it) | Both documented forms — `python -m pip install .` and `-e .` — install into a clean virtual environment, record their runtime dependencies, and run every local scan type from outside the checkout. Pass |
| Release documentation | `python -m pytest -v tests/test_release_identity.py` | This document covers identity, source/package/container artifacts, pre-1.0 support, procedure, and gate. It distinguishes the existing `v0.1.0` tag from the missing GitHub Release, package publications, and version-tagged images. Pass; final external state still requires the B-9 recheck |
| Supported Python | `pyproject.toml` `requires-python`; `.github/workflows/ci.yml` matrix; `scripts/check_required_ci.py` `REQUIRED_CHECKS`; README prerequisites | All four say 3.10+, tested on 3.10/3.11/3.12, with `Test (Python 3.10)`, `Test (Python 3.11)`, and `Test (Python 3.12)` as the required checks. Consistent |
| License | `LICENSE` (Apache License 2.0 full text); `pyproject.toml` `license = { text = "Apache-2.0" }`; README badge | Consistent. Pass |
| Security reporting | Read [SECURITY.md](../SECURITY.md) | Private report channel and a pre-1.0 *Supported Versions* table (`main` only) that stays accurate for v0.2. Signed commit-SHA GHCR images have been observed and verified, so its older container-signing paragraph is stale; correcting `SECURITY.md` remains a separately owned follow-up outside this audit's allowed files. **B-6** |
| Sample-output provenance | Read [`docs/examples/first-run/README.md`](examples/first-run/README.md); `python -m pytest -v tests/test_first_run_samples.py` | Input, both commands, working directory, generating version (`harvestguard 0.1.0`), repository state, and the exact normalization applied are recorded, and the committed artifacts still match live output on their host-independent lines. Pass at `0.1.0`; a version bump makes the recorded version stale. **B-4** |
| Claims | `python -m pytest -v tests/test_product_claims.py` | Passes. [CLAIMS_AUDIT.md](CLAIMS_AUDIT.md) classifies each claim and its `Needs Validation` section is scoped to v0.1; it is a maintainer input to the v0.2 go/no-go, not a blocker this audit can close. **B-7** |
| Release procedure | Read [Release procedure](#release-procedure-v01) | Present and executable, but written with literal `v0.1.0` commands. The [checklist below](#proposed-v02-release-checklist) is its v0.2 instance |
| Demo quickstart | `python -m harvestguard scan demo/sample_target --type all --summary`, then the same scan with `--json` and with `--markdown` | All three exit `0` on both a Linux and a macOS run of this audit. The summary reports `Files scanned: 4`, `Total normalized records: 5`, `Errors: 1`, `Findings with finding-level errors: 1`, `Scanner execution errors: 0`; the JSON holds 5 records; the report's `HarvestGuard Version` row reads `0.1.0`. Its `Coverage` row is host-dependent, same as the aggregate filesystem context record it derives from (see [CLI.md § What varies by host](CLI.md#what-varies-by-host)): it read `Bounded by configured scan scope` on the Linux run and `Not complete` on the macOS run, where the aggregate context finding picked up an "ACL presence could not be portably determined" limitation. Neither is wrong; README *Quickstart* does not predict one specific value. Pass |
| Lint and whitespace | `ruff check .`; `git diff --check` | Both clean |

### Open items for the v0.2 go/no-go

Blocking items must be resolved or explicitly accepted by a maintainer before a
v0.2 release action runs. None is resolved by this audit. What has since
happened to each one is recorded in
[disposition of the audit's open items](#disposition-of-the-audits-open-items);
this table stays as the audit wrote it.

| ID | Item | Blocking | Owner / action |
| --- | --- | --- | --- |
| B-1 | A `v0.1.0` tag already exists (commit `4598a4b`) but no GitHub Release has been published from it | Yes | Maintainer: decide whether to publish a `v0.1.0` GitHub Release from the existing tag before or instead of a `v0.2.0` release, and record the decision in [CHANGELOG.md](../CHANGELOG.md) |
| B-2 | Bumping `__version__` to `0.2.0` fails `tests/test_first_run_samples.py::test_json_sample_matches_the_normalized_finding_contract`, which asserts each committed sample finding's `scanner_version == __version__`. Per-scanner `ScannerIdentity` versions in `finding_adapters.py` are independent `0.1.0` literals that only coincide with the product version today, and this document states provenance `scanner_version` does not track it. Reproduce with `python -c "import finding_adapters as fa, harvestguard_version as v; print(v.__version__, fa.FILESYSTEM_SCANNER.version)"` | Yes | Maintainer: as part of the version-bump change, either bump the scanner identity literals deliberately and regenerate the samples, or decouple that assertion from `__version__`. Production code is outside this audit's scope, so neither was done here |
| B-3 | No `0.2.0` changelog entry is drafted | Yes | Maintainer: draft it from the relevant `Complete` HG-028…HG-044 entries in [ROADMAP.md](ROADMAP.md), the completed first-public-use work in Issues #115 through #118, and this #119 release-readiness audit if it belongs in the release narrative, following the `0.1.0` entry's structure |
| B-4 | The committed first-run samples and their provenance record `0.1.0` | Yes, once a bump happens | Maintainer: after the bump, run `python docs/examples/first-run/generate_samples.py` and update the generating-version and repository-state rows in `docs/examples/first-run/README.md` |
| B-5 | Prerequisite issue closure, review approval, and green required checks cannot be read from repository content | Yes | Maintainer: confirm with `gh issue view <n>` and `gh pr checks <n>` for the four public-use prerequisite issues, then record the confirmation in the release decision |
| B-6 | [SECURITY.md](../SECURITY.md) predates the observed and verified signed commit-SHA GHCR images | No — evidence accuracy, not a release gate | Maintainer: correct that paragraph and the two stale `Experimental / Needs Validation` rows in [SBOM, signing, and provenance status](#sbom-signing-and-provenance-status). `SECURITY.md` is outside this audit's allowed files; no version-tagged image has been observed |
| B-7 | [CLAIMS_AUDIT.md](CLAIMS_AUDIT.md)'s `Needs Validation` section is scoped to v0.1 | No | Maintainer: re-read it against v0.2 content and either rescope it or accept it unchanged |
| B-8 | The deferred release-engineering work above — no lock file or hash-pinned requirements, no source/package SBOM, no SLSA provenance, unsigned tags, no published wheel or version-tagged image — is unchanged for v0.2 | No, if accepted | Maintainer: accept explicitly as the pre-1.0 posture already documented in [Deferred work](#deferred-work), or move an item into v0.2 scope through its own issue |
| B-9 | Release, tag, package, and container publication state is external and may change after this audit | Yes | Maintainer: immediately before release action, recheck and record the bounded facts: the `v0.1.0` tag state, GitHub Releases, `v0.2.0` tag state, PyPI/wheel/sdist publication, and GHCR commit-SHA and version-tagged images |

### Proposed v0.2 release checklist

**None of these commands was run.** They are recorded so a later, explicitly
authorized release action is exact and reviewable rather than improvised.
Steps 1–4 are decisions and changes that go through ordinary review; steps 5–7
are the release action itself, and step 8 is an optional in-repository record
made after it.

1. Resolve or explicitly accept every blocking item — B-1 through B-5 and B-9
   — before any release action, and record B-6 through B-8 as accepted or
   scoped. Resolving B-9 requires a fresh release-surface check after the B-1
   decision and immediately before the release action.
2. In a reviewed change: bump `version` in `pyproject.toml` and `__version__` in
   `harvestguard_version.py` to `0.2.0` together, handle B-2 in the same change,
   draft the `0.2.0` changelog entry (B-3), and regenerate the first-run samples
   and their provenance (B-4).
3. Confirm the version surfaces agree:

   ```bash
   python -m harvestguard --version          # expect: harvestguard 0.2.0
   grep -n '^version' pyproject.toml         # expect: version = "0.2.0"
   ```

4. Confirm the release commit on `main` is green, locally and on GitHub:

   ```bash
   ruff check .
   python -m pytest -v                       # includes tests/test_clean_install.py; needs network
   git diff --check
   ```

   plus the required checks `Test (Python 3.10)`, `Test (Python 3.11)`, and
   `Test (Python 3.12)` (`scripts/check_required_ci.py`) succeeding on the exact
   release commit SHA.
5. Build and record the container image for the **exact release commit**, before
   the tag exists — **the first step in this checklist that changes anything
   outside the repository working tree**. `container-build.yml`'s `push` trigger
   is path-filtered to container-related paths (`Dockerfile`, `requirements.txt`,
   the scanner/classifier/dashboard packages, and the workflow itself), and the
   release commit from step 2 touches version literals, the changelog, and
   sample artifacts — none of those paths — so merging it publishes **no** image
   on its own. The workflow's `workflow_dispatch` trigger is what builds one,
   and its `publish` job runs for a dispatch exactly as it does for a push:

   ```bash
   release_sha=$(git rev-parse origin/main)   # the release commit from step 2
   echo "$release_sha"                        # record this value

   gh workflow run container-build.yml --ref main
   gh run list --workflow container-build.yml --limit 1 \
     --json databaseId,headSha,status,conclusion
   ```

   A dispatch builds whatever the dispatched ref pointed at when the run
   started, and tags the image with that commit's SHA. Confirm the run's
   `headSha` equals `$release_sha` before trusting its image — if `main` has
   advanced past the release commit, stop and settle which commit is being
   released rather than recording an image built from a different tree. Then
   wait for it to succeed and record the digest:

   ```bash
   gh run watch <databaseId>                  # expect conclusion: success
   docker buildx imagetools inspect "ghcr.io/serewicz/harvestguard:$release_sha" \
     --format '{{json .Manifest}}' | jq -r '.digest'
   ```

   Keep both recorded values — the release commit SHA and the full
   `sha256:…` digest. Step 7 substitutes them into the release notes, which is
   where the release states which image corresponds to it. This publishes a
   commit-SHA-tagged image with its cosign signature and SBOM attestation; it
   adds no `:v0.2.0` tag.
6. Create and push the annotated tag:

   ```bash
   git rev-parse HEAD                        # must equal the recorded $release_sha
   git tag -a v0.2.0 -m "HarvestGuard v0.2.0"
   git push origin v0.2.0
   ```

7. Publish the release for that tag. Its notes are the prepared draft in
   [docs/release-notes/v0.2.0-draft.md](release-notes/v0.2.0-draft.md) — paste
   that file's release text, with its preamble and maintainer-checklist sections
   deleted as that file instructs, and substitute the release commit SHA and
   image digest recorded in step 5 for its `<commit-sha>` and `<image-digest>`
   placeholders. The `0.2.0` [CHANGELOG.md](../CHANGELOG.md) entry stays the
   in-repository record and is linked from those notes rather than pasted as
   them.
8. Optional, after publishing: the tagged tree is immutable, so the changelog
   entry **at** `v0.2.0` cannot carry the release commit SHA or the image
   digest — the digest does not exist until step 5, by which point the release
   commit is already written. The published release notes from step 7 are
   therefore the authoritative record of both. To keep the same values in the
   repository, add them to the `0.2.0` changelog entry in a separate reviewed
   commit on `main` after publication, stating there that the tagged tree does
   not contain them.

Nothing in this checklist authorizes publishing to PyPI, adding a
version-tagged (`:v0.2.0`) container image, or signing the tag; those remain
[deferred work](#deferred-work).

## Release and distribution decision (v0.2 preparation)

The decision the [audit above](#v02-pre-10-release-readiness-audit) left open,
made and recorded (GitHub issue #125) so a maintainer can act without rereading
the repository. **Preparing this decision published nothing**: it created no
`v0.2.0` tag, no GitHub Release, no PyPI/wheel/sdist artifact, and no
version-tagged container image, and it changed no version literal. Every
command in this section and in the
[checklist above](#proposed-v02-release-checklist) is written for a later,
explicitly authorized human release action and was deliberately not executed.

### Decision

**Prepare a `v0.2.0` pre-1.0 GitHub Release; publish nothing yet.**

| Option considered | Outcome | Why |
| --- | --- | --- |
| A — publish a GitHub Release for the existing `v0.1.0` tag | Not chosen | Per the audit above, the `v0.1.0` tag is on commit `4598a4b`, an ancestor of `main` that predates the cryptographic-inventory epic (HG-033…HG-044) and all four first-public-use prerequisites. A release published from it would send a first-time reader to a checkout without the demo corpus, sample output, or quickstart that make a first run safe, and its notes would describe less than `main` already does |
| **B — prepare a `v0.2.0` pre-1.0 GitHub Release** | **Chosen** | `main` is where the merged work actually is, and a `0.2.0` version identity lets a shared evidence artifact name a release rather than a bare commit SHA. Preparation (decision, changelog entry, release notes, support path) is reviewable now; the release action itself stays a separate authorized step |
| C — update metadata only and defer any release | Partly adopted | Its substance — repository metadata and a support/advisory path — is done here (see below). Deferring indefinitely was not chosen: the preparation work is what a maintainer needs in order to decide, and leaving it undone would not make the decision any better informed later |

Choosing B is a choice about **release mechanics only**. It asserts nothing
about product completeness, cryptographic completeness, detection coverage,
security, compliance, remediation readiness, migration readiness, or quantum
readiness, and it changes no claim about what the scanners detect — those stay
in [DETECTION_CHARACTERIZATION.md](DETECTION_CHARACTERIZATION.md) and
[CLAIMS_AUDIT.md](CLAIMS_AUDIT.md).

Publishing remains gated: the version literals are still `0.1.0`, and a release
requires the [checklist above](#proposed-v02-release-checklist) plus explicit
maintainer authorization.

### Release-surface facts as of this preparation

Unchanged from the audit, and restated here so the decision does not rest on a
reader's memory. These are external facts that can change after this section is
written; rechecking them immediately before any release action is **B-9**, and
this section does not discharge it.

| Surface | State |
| --- | --- |
| Declared version (`pyproject.toml`, `harvestguard_version.py`) | `0.1.0` in both; `python -m harvestguard --version` prints `harvestguard 0.1.0` |
| Git tags | the annotated `v0.1.0` tag exists; no `v0.2.0` tag has been created |
| GitHub Releases | none published, from `v0.1.0` or any other tag |
| PyPI / wheel / sdist | no publication of any kind |
| Container images | commit-SHA-tagged images in GHCR with signatures and SBOM attestations; no `v0.1.0` or `v0.2.0` version-tagged image |

### Disposition of the audit's open items

The audit's [open items](#open-items-for-the-v02-gono-go) table records those
items as they stood when it was written; this table records what happened to
each. Nothing here performs a release action, so every item that requires one
stays open by design.

| ID | Disposition |
| --- | --- |
| B-1 | **Decided:** do not publish a `v0.1.0` GitHub Release. The chosen path is a `v0.2.0` release instead, for the reasons in [Decision](#decision) above. The existing `v0.1.0` tag is kept as-is — not deleted, moved, or replaced — as the historical marker of the controlled-pilot commit |
| B-2 | **Still a maintainer action, unchanged.** The `ScannerIdentity` version literals in `finding_adapters.py` are production code and are deliberately untouched here. Whoever performs the version bump must, in that same change, either bump those literals and regenerate the samples or decouple `tests/test_first_run_samples.py` from `__version__` |
| B-3 | **Resolved:** the `0.2.0` entry is drafted in [CHANGELOG.md](../CHANGELOG.md), covering HG-028…HG-044 and issues #115 through #119, and is explicitly marked as describing an unreleased draft. Draft GitHub Release notes are in [docs/release-notes/v0.2.0-draft.md](release-notes/v0.2.0-draft.md) |
| B-4 | **Still a maintainer action, unchanged.** The committed first-run samples correctly record `0.1.0`, which is what the repository still declares. They go stale only when the bump happens, and must be regenerated in that same change |
| B-5 | **Still a maintainer action.** Issue closure, review approval, and green required checks live in the GitHub API, not in the checkout, so they cannot be confirmed from repository content here |
| B-6 | **Still a maintainer action, unchanged.** Correcting `SECURITY.md`'s container-signing paragraph and the two stale `Experimental / Needs Validation` rows in [SBOM, signing, and provenance status](#sbom-signing-and-provenance-status) is evidence accuracy, not a release gate, and is outside this issue's scope |
| B-7 | **Still a maintainer action.** [CLAIMS_AUDIT.md](CLAIMS_AUDIT.md) is unchanged by this preparation; rescoping or accepting its v0.1-scoped `Needs Validation` section is a claims decision, not a release-mechanics one |
| B-8 | **Accepted for v0.2.** The deferred release-engineering posture — no lock file or hash-pinned requirements, no source/package SBOM, no SLSA provenance, unsigned tags, no published wheel, no version-tagged image — carries into v0.2 unchanged and stays documented in [Deferred work](#deferred-work). Moving any item into scope needs its own issue |
| B-9 | **Still a maintainer action by construction.** Release, tag, package, and container state is external; recheck and record it immediately before the release action |

### Distribution decisions

| Channel | Decision | Rationale |
| --- | --- | --- |
| Source checkout (`git clone` + `pip install .`) | Remains the supported way to obtain HarvestGuard | Already documented, already covered by `tests/test_clean_install.py` |
| GitHub Release | Sufficient for v0.2 | It gives an outside reader a citable version, notes, and a source archive without new packaging or publishing infrastructure |
| PyPI (wheel/sdist) | **Deferred.** Not part of this release, and not authorized by anything in this document | Publishing a package name creates a durable distribution surface and an implied upgrade path and support expectation. That belongs after the GitHub Release path and [SUPPORT.md](../SUPPORT.md) expectations have been exercised at least once, and needs its own maintainer decision |
| Version-tagged container image (`:v0.2.0`) | **Deferred.** Commit-SHA-tagged images remain the current container distribution artifact, identified by digest | Adding a version tag means committing to what that tag points at over time. The existing commit-SHA tags plus signatures and SBOM attestations already identify an image precisely, and the image runs the dashboard only, so it is not the primary way the CLI evidence path is used |
| Signed git tags, published wheels, SLSA provenance, lock files | Deferred, unchanged | [Deferred work](#deferred-work) |

Real-world validation depth (HG-045) is **future validation-depth work, not a
release blocker**: no claim in the drafted changelog entry or release notes
depends on it, and both state plainly that detection has been exercised against
the repository's own fixtures and demo corpus. It is recorded as a known
limitation rather than left to be inferred from silence.

### Repository metadata actions (maintainer, not changeable by pull request)

GitHub repository topics and the homepage URL are repository settings, not
repository content, so no change in this repository can set them. They are
recorded here as an exact, reviewable maintainer action.

```bash
# 1. Record what is currently set, before changing anything.
gh repo view serewicz/HarvestGuard --json repositoryTopics,homepageUrl

# 2. Fix the misspelled topic and add accurate ones.
gh repo edit serewicz/HarvestGuard \
  --remove-topic crypto-aglity \
  --add-topic crypto-agility \
  --add-topic cryptography-inventory \
  --add-topic post-quantum-cryptography \
  --add-topic pqc \
  --add-topic security-tools
```

- `crypto-aglity` is a typo for `crypto-agility` and should be removed, not
  kept alongside the corrected spelling.
- Every topic above describes the problem space HarvestGuard collects evidence
  for. None of them claims a capability: `pqc` and
  `post-quantum-cryptography` are subject-matter topics, and HarvestGuard makes
  no quantum-readiness or migration-readiness determination
  ([ADR-006](DECISIONS/ADR-006-product-boundary.md)).
- **Leave the homepage URL unset.** No landing page exists, and a placeholder
  page would read as an abandoned product surface. Set it only if a real,
  maintained page is published later.

### Support and advisory path

[SUPPORT.md](../SUPPORT.md) is the single place that answers "where do I ask,
and what should I expect": GitHub Issues on a best-effort basis, no
service-level agreement, no paid tier, `main` only, and security reports routed
privately through [SECURITY.md](../SECURITY.md). [README.md](../README.md) links
to it in one short section.

Advisory work available separately from the maintainer is described in
`SUPPORT.md` only, kept out of the detector documentation and away from every
technical claim, and stated there to be neither a support tier for this
repository nor a condition of using it. No detector document, report, or claims
document mentions it.

### Validation performed during this preparation

Run from a repository checkout on Linux with CPython 3.12, as
`python -m harvestguard` (no install step). No command below changes anything
outside the working tree.

| Check | Command | Result |
| --- | --- | --- |
| Version identity unchanged | `python -m harvestguard --version` | `harvestguard 0.1.0` |
| Quickstart still works | `python -m harvestguard scan demo/sample_target --type all --summary`, then the same scan with `--json` and with `--markdown` | All three exit `0`. `Files scanned: 4`, `Total normalized records: 5`, `Errors: 1`, `Findings with finding-level errors: 1`, `Scanner execution errors: 0`; the JSON holds 5 records; the report's `HarvestGuard Version` row reads `0.1.0` and its `Coverage` row `Bounded by configured scan scope` (host-dependent — see [CLI.md § What varies by host](CLI.md#what-varies-by-host)) |
| Sample output still accurate | `python -m pytest -v tests/test_first_run_samples.py` | Pass; the committed samples still match live output on their host-independent lines |
| Release identity | `python -m pytest -v tests/test_release_identity.py` | Pass |
| Claims and documentation | `python -m pytest -v tests/test_product_claims.py tests/test_quickstart_docs.py tests/test_v0_2_release_readiness.py tests/test_release_distribution_readiness.py` | Pass |
| Full suite and lint | `ruff check .`; `python -m pytest -v`; `git diff --check` | Clean |
| No accidental release action | Reviewed `git diff`; no tag, release, publication, or version-literal change | Confirmed: the version literals are untouched and no publishing command was run |

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
