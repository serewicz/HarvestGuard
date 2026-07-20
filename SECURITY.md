# Security Policy

HarvestGuard scans filesystems and cloud storage for encryption status and sensitive-data risk. Because it can be run against production storage and with cloud credentials, its own security posture matters as much as the risks it reports on.

## Data handling

- HarvestGuard runs entirely locally (or wherever you deploy it). It does not send scan results, file contents, file paths, or credentials to any third-party service.
- Cloud credentials are read from your local environment using each provider's standard SDK credential resolution — boto3's default chain for AWS (see `.env.example`), Application Default Credentials for GCS, and `DefaultAzureCredential` for Azure Blob. HarvestGuard does not store, log, or transmit these credentials anywhere beyond the API calls needed to perform the scan you requested.
- Scan output (dataframes, exports) stays on the machine running the app unless you explicitly export or share it.

If you find a place where this isn't true, that's a security bug — please report it privately (see below), not as a public issue.

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
