# HarvestGuard Scan Report

## Executive Summary

HarvestGuard inspected 4 regular file(s) and recorded 4 material evidence record(s): 2 cryptographic asset(s), 1 sensitive-data finding(s), 0 code-analysis finding(s), 0 cloud storage finding(s), and 0 per-file filesystem evidence finding(s). It also recorded 1 aggregate filesystem context record(s), 0 coverage limitation(s), and 0 skipped or inaccessible entry record(s), for 5 total normalized records.

The report summarizes observed evidence only. It does not infer business risk.

## Scan Information

| Field | Value |
| --- | --- |
| Scan Time | 1970-01-01T00:00:00+00:00 |
| Scan ID | 00000000-0000-0000-0000-000000000000 |
| HarvestGuard Version | 0.1.0 |
| Report Generator | harvestguard-report 0.1.0 |
| Target Path | demo/sample_target |
| Duration | 0.00 seconds |
| Files Scanned | 4 |
| Crypto Files Inspected | 4 |
| Excluded Paths | None |
| Coverage | Bounded by configured scan scope |

## Scanner Versions

| Scanner | Version | Findings |
| --- | --- | --- |
| crypto_inventory | 0.1.0 | 3 |
| filesystem | 0.1.0 | 1 |
| semgrep_crypto_rules | 0.1.0 | 0 |
| sensitive_data_classifier | 0.1.0 | 1 |

## Scope

- Target path: `demo/sample_target`
- Scan type: `all`
- Scanners run: filesystem, crypto inventory, sensitive data, code analysis
- Configured scope constraints:
  - Maximum directory depth: 3

## Record Categories

Every normalized record below is counted in exactly one category. `Files Scanned` above counts inspected regular files, not records: an ordinary readable file with no file-level evidence and no file-specific failure produces no record of its own, and is represented by its mount's aggregate filesystem context record.

| Category | Count |
| --- | ---: |
| Aggregate filesystem context records | 1 |
| Per-file filesystem evidence records | 0 |
| Coverage limitation records | 0 |
| Skipped or inaccessible entry records | 0 |
| Cryptographic inventory records | 3 |
| Sensitive-data records | 1 |
| Code-analysis records | 0 |
| Cloud storage records | 0 |
| **Material evidence records** | 4 |
| **Total normalized records** | 5 |

- Findings with finding-level errors: 1
- Scanner execution errors: 0

## Findings Summary

| Category | Count |
| --- | ---: |
| Certificates | 1 |
| Private Keys | 2 |
| Encrypted Keys | 1 |
| SSH Keys | 0 |
| PKCS#12 | 0 |
| Expired Certificates | 0 |
| Sensitive Files | 1 |
| Semgrep Findings | 0 |
| Malformed Assets | 1 |
| Errors | 1 |
| Total normalized records | 5 |

## Finding Breakdown by Type

| Finding Type | Count |
| --- | ---: |
| Encrypted PKCS#8 Private Key | 1 |
| Malformed PEM Private Key | 1 |
| PEM Certificate | 1 |
| file | 1 |
| volume | 1 |

## Detailed Findings

### Encrypted PKCS#8 Private Key

| Location | Asset Type | Scanner | Scanner Version | Observed At | Algorithm | Key Size | Expiration | Issuer | Subject | Fingerprint | Confidence | Observed Evidence | Unknowns | Limitations | Errors |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| demo/sample_target/crypto/demo_encrypted_private_key.pem | Encrypted PKCS#8 Private Key | crypto_inventory | 0.1.0 | 1970-01-01T00:00:00+00:00 |  |  |  |  |  |  | High | Encrypted PKCS#8 private-key structure detected |  |  |  |

### Malformed PEM Private Key

| Location | Asset Type | Scanner | Scanner Version | Observed At | Algorithm | Key Size | Expiration | Issuer | Subject | Fingerprint | Confidence | Observed Evidence | Unknowns | Limitations | Errors |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| demo/sample_target/sensitive/leaked_config.env | Malformed PEM Private Key | crypto_inventory | 0.1.0 | 1970-01-01T00:00:00+00:00 |  |  |  |  |  |  | Low | PEM block BEGIN RSA PRIVATE KEY detected but parsing failed |  |  | Unable to load PEM file. See https://cryptography.io/en/latest/faq/#why-can-t-i-import-my-pem-file for more details. InvalidData(Invalid symbol 45, offset 3.) |

### PEM Certificate

| Location | Asset Type | Scanner | Scanner Version | Observed At | Algorithm | Key Size | Expiration | Issuer | Subject | Fingerprint | Confidence | Observed Evidence | Unknowns | Limitations | Errors |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| demo/sample_target/crypto/demo_tls_certificate.pem | PEM Certificate | crypto_inventory | 0.1.0 | 1970-01-01T00:00:00+00:00 | RSA | 2048 | 2126-07-22T03:50:24+00:00 | OU=Do Not Use,O=HarvestGuard Synthetic Demo Material,CN=demo.harvestguard.invalid | OU=Do Not Use,O=HarvestGuard Synthetic Demo Material,CN=demo.harvestguard.invalid | fec3e00862dd82b4cde8e36c0c6703acb64945db7d4957e36e58418cb634f5cf | High | PEM Certificate parsed successfully |  |  |  |

### file

| Location | Asset Type | Scanner | Scanner Version | Observed At | Algorithm | Key Size | Expiration | Issuer | Subject | Fingerprint | Confidence | Observed Evidence | Unknowns | Limitations | Errors |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| demo/sample_target/sensitive/leaked_config.env | file | sensitive_data_classifier | 0.1.0 | 1970-01-01T00:00:00+00:00 |  |  |  |  |  |  | Medium | Sensitive data categories detected: Email, Generic Secret, Private Key; total matches: 3 |  |  |  |

### volume

| Location | Asset Type | Scanner | Scanner Version | Observed At | Algorithm | Key Size | Expiration | Issuer | Subject | Fingerprint | Confidence | Observed Evidence | Unknowns | Limitations | Errors |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| / | volume | filesystem | 0.1.0 | 1970-01-01T00:00:00+00:00 |  |  |  |  |  |  | Medium | Volume-level encryption status observed for mount /: Unencrypted (the platform reported the volume is not encrypted). 4 regular file(s) with no file-level encrypted-format signature and no file-specific failure are represented by this record rather than by individual records. | Business ownership cannot be established from filesystem metadata.; File-level encryption status cannot be established conclusively for the regular files this aggregate context represents.; Per-file ownership, permission, and ACL signals are not established by this aggregate context finding; it describes the mount, not any individual file on it. |  |  |

## Errors and Warnings

- Finding-level errors are listed in Detailed Findings.

## Known Limitations

- Findings are observed evidence, not business risk conclusions.
- No risk scores, executive priority, remediation recommendations, or ownership inference are included.
- Sensitive-data findings report categories and counts only, not matched values.
- Encrypted key containers may not expose algorithm or key-size metadata without a passphrase.
- JKS support is limited to header evidence in the current scanner.
- Every scanner has a deliberately narrow detection surface, so absence of a finding is not proof of absence. Each scanner's supported evidence, known blind spots, and confidence semantics are documented in `docs/DETECTION_CHARACTERIZATION.md`.
- Source-code analysis matches Python source text only, and an execution failure (analyzer unavailable, timed out, or unreadable output) yields no findings without appearing above; its diagnostic goes only to the scan's standard error stream.

## Appendix

- Normalized schema version: `1.0.0`
- JSON output preserves the normalized finding schema exactly.
- Scanner-specific observed values are preserved in each finding's `technical_metadata`.
