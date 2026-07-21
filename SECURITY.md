# Security Policy

HarvestGuard inventories cryptographic assets and collects evidence about encryption status and sensitive-data placement across supported filesystems and cloud storage. Because it can be run against production storage and with cloud credentials, its own security posture matters as much as the evidence it reports.

## Data handling

- HarvestGuard runs entirely locally (or wherever you deploy it). It does not send scan results, file contents, file paths, or credentials to any third-party service.
- Cloud credentials are read from your local environment using each provider's standard SDK credential resolution — boto3's default chain for AWS (see `.env.example`), Application Default Credentials for GCS, and `DefaultAzureCredential` for Azure Blob. HarvestGuard does not store, log, or transmit these credentials anywhere beyond the API calls needed to perform the scan you requested.
- Scan output (dataframes, exports) stays on the machine running the app unless you explicitly export or share it.

If you find a place where this isn't true, that's a security bug — please report it privately (see below), not as a public issue.

## Container network posture

The `Dockerfile` image makes no network calls HarvestGuard itself didn't
request on your behalf — there is no telemetry and no HarvestGuard-operated
service for it to phone home to; none exists.

- **Local filesystem, PII/secrets, and crypto code analysis scans make no
  network calls** — verify yourself: `scanner/filesystem.py` and
  `classifier/scanner.py` import nothing network-related, and
  `code_analysis/scanner.py` runs Semgrep against a small vendored rule set
  (`code_analysis/rules/crypto.yaml`) rather than Semgrep's hosted registry,
  with `--metrics=off --disable-version-check` explicitly set — both
  otherwise call home regardless of where the rules come from. For
  independent verification, you can run fully network-isolated with `docker
  run --network none --read-only --tmpfs /tmp ...`, though note that also
  makes the Streamlit UI itself unreachable from the host (`--network none`
  disables container networking entirely, including published ports) — it's
  a proof mode, not the normal way to run it. All three scan types were
  re-verified against `--network none` after the code analysis scanner was
  added.
- **Cloud scans (S3/GCS/Azure) need outbound access to that provider's API
  only** — to authenticate and to list/read the bucket or container you
  pointed the scan at. Nothing else.
- The image runs as a non-root user (uid 65532) on a distroless base (no
  shell, no package manager), and is compatible with `--read-only` root
  filesystems — `/tmp` is the only path it writes to, mount it as a tmpfs.

## Verifying the container image

Every image published from `main` (`.github/workflows/container-build.yml`)
is signed **keylessly** via [Sigstore](https://www.sigstore.dev/)/cosign,
using GitHub Actions' own OIDC token — there is no private signing key for
anyone to steal, and the signature cryptographically proves the image was
built by that specific workflow run, from that specific commit, not hand-
pushed by anyone with registry credentials. A CycloneDX SBOM is generated
with [syft](https://github.com/anchore/syft) and attached as a signed
attestation on the same image, so "what's in this image" is independently
verifiable too, not just asserted here.

```bash
# Verify the image signature
cosign verify \
  --certificate-identity-regexp "^https://github.com/serewicz/HarvestGuard/\.github/workflows/container-build\.yml@refs/heads/main$" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/serewicz/harvestguard:<commit-sha>

# Pull and inspect the signed SBOM
cosign verify-attestation \
  --type cyclonedx \
  --certificate-identity-regexp "^https://github.com/serewicz/HarvestGuard/\.github/workflows/container-build\.yml@refs/heads/main$" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/serewicz/harvestguard:<commit-sha> \
  | jq -r '.payload' | base64 -d | jq '.predicate'
```

The sign/attest mechanics (image build → SBOM generation → sign → attest →
verify) were tested end-to-end locally against a local registry before this
workflow was written. The keyless OIDC signing step specifically can only be
exercised for real inside GitHub Actions, since it depends on GitHub's own
OIDC token issuer — it hasn't produced a real published, verifiable image
yet as of this commit; that happens on the first `container-build.yml` run
against `main`.

## Supported Versions

HarvestGuard is pre-1.0 and does not yet maintain parallel release branches. Security fixes land on `main`; there is no backport policy until a first stable release exists.

| Version | Supported |
| ------- | --------- |
| main    | ✅        |

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Instead, email **tim@serewicz.com** with:

- A description of the vulnerability and its potential impact
- Steps to reproduce (or a proof of concept)
- Affected version/commit

You should get an acknowledgment within a few business days. Once a fix is available, we'll coordinate on disclosure timing and credit you (if desired) in the release notes.

## Scope

In scope: the HarvestGuard codebase itself (scanner, analyzer, dashboard, main app) — credential handling, injection risks in scan targets/paths, dependency vulnerabilities, and any way scan data could leak beyond the running instance.

Out of scope: vulnerabilities in third-party dependencies that are already publicly disclosed and awaiting upstream patches (please still let us know if HarvestGuard needs a version bump to pick up the fix).
