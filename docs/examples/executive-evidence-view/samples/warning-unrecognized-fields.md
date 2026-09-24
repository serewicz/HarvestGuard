# HarvestGuard Executive Evidence View

## Overview

| Field | Value |
| --- | --- |
| Scan ID | synthetic\-unrecognized\-fields\-001 |
| Scan time | 2025\-11\-04T09:30:00\+00:00 |
| Scan-time basis | recorded scan time |
| Export time | 2026\-01\-15T00:00:00\+00:00 |
| Scan type | code |
| Target | /synthetic/example\-target |
| Produced by | HarvestGuard 0.3.0 |
| Exported by | HarvestGuard 0.3.0 |
| Executive schema | 0.1.0 |
| Executive policy | 0.1.0 |
| Normalized finding schema | 1.0.0 |
| Evidence digest | 62d36beb4d8dd1b7053bc9d1f153ac97bd9bb374b0e0f28457ce5d98adaff6f0 |
| Retained snapshot occurrences | 1 |

**Evidence evaluation: WARNING**

> Evidence evaluation: WARNING. Every required check listed in this view passed for the declared scope, but at least one specifically defined exception needs attention. This does not establish source authenticity, complete environmental coverage, organizational security, regulatory compliance, or business safety.

Why this evaluation:

- EV\-RSN\-003: Every required check passed, and 1 defined exception\(s\) need attention: EV\-EXC\-003 unrecognized\_stored\_fields.
- EV\-RSN\-007: 1 check\(s\) did not apply to the declared scope: EV\-CHK\-008.

This view answers exactly three questions. It contains no risk score, no trust score, no remediation, no compliance verdict and no business judgment.

1. **What did HarvestGuard observe?** 1 normalized record(s) were retained, 1 of them material evidence records -- see [What HarvestGuard observed](#what-harvestguard-observed).
2. **What evidence supports those observations?** 1 retained snapshot occurrence(s) are listed individually under [Technical evidence detail](#technical-evidence-detail), and the identified checks over them under [Evidence checks and limitations](#evidence-checks-and-limitations).
3. **What can and cannot we conclude from that evidence?** See [Supported conclusions and limits](#supported-conclusions-and-limits), which also lists what this view could not establish.

Defined exception(s) needing attention (1): EV\-EXC\-003 unrecognized\_stored\_fields. Full statements, references and details are under [Defined exceptions](#defined-exceptions).

- EV\-EXC\-003: 1 stored snapshot occurrence\(s\) carry field\(s\) this release does not recognize, including any unrecognized direct provenance member \-\- reported as provenance.\<member\-name\> \-\- even when it is the only unrecognized field on that occurrence: experimental\_attribution, provenance.experimental\_collector\_note. They are retained in the stored payload rather than discarded, and are not interpreted by this view. Names are disclosed here and in both executive export formats. Their values are withheld from this disclosure view because an unrecognized field's content has no established privacy classification. They remain retained unchanged in the verified local evidence store, which is the technical\-traceability source, and stay covered by the existing evidence digest.

## What HarvestGuard observed

### EV\-OBS\-001 (observation)

- Statement: The run retained 1 normalized record\(s\), of which 1 are material evidence records. By category: Aggregate filesystem context records: 0; Per\-file filesystem evidence records: 0; Coverage limitation records: 0; Skipped or inaccessible entry records: 0; Cryptographic inventory records: 0; Sensitive\-data records: 0; Code\-analysis records: 1; Cloud storage records: 0; Other records: 0.
- Method: reports.count\_by\_category\(\)/summarize\_findings\(\) over the retained snapshots, in canonical stored order.
- Limitation: Category counts are record counts. Aggregate context, coverage and skipped/inaccessible records are counted separately from material evidence and are never summed into one total.

### EV\-OBS\-002 (observation)

- Statement: Scanner\(s\) recorded for this run: semgrep\_crypto\_rules 0.2.0.
- Method: Recorded scanner/version pairs from the stored scan context.
- Identified check: EV\-CHK\-003

### EV\-OBS\-003 (observation)

- Statement: Declared scope: target /synthetic/example\-target; scan type code; configured scope constraints: SYNTHETIC EXAMPLE FIXTURE: purpose\-built evidence for HarvestGuard documentation. Not a real environment, not a real scan, no customer, personal or confidential data..
- Method: Declared scope copied from the stored scan context.
- Limitation: A configured exclusion or depth limit bounds what the scan could observe. It is a disclosure, not a failure.

### Record counts

| Count | Value |
| --- | --- |
| filesystem\_context | 0 |
| filesystem\_file\_evidence | 0 |
| coverage\_limitation | 0 |
| skipped\_or\_inaccessible | 0 |
| crypto\_inventory | 0 |
| sensitive\_data | 0 |
| code\_analysis | 1 |
| cloud\_evidence | 0 |
| other\_records | 0 |
| total\_records | 1 |
| material\_evidence | 1 |
| files\_scanned | 0 |
| certificates | 0 |
| private\_keys | 0 |
| encrypted\_keys | 0 |
| ssh\_keys | 0 |
| pkcs12 | 0 |
| expired\_certificates | 0 |
| sensitive\_files | 0 |
| semgrep\_findings | 1 |
| malformed\_assets | 0 |
| errors | 0 |

### Declared scope

| Field | Value |
| --- | --- |
| Target path | /synthetic/example\-target |
| Scan type | code |
| Scanners | code analysis |
| Scanner versions | semgrep\_crypto\_rules 0.2.0 |
| Excluded paths | none |
| Scope constraints | SYNTHETIC EXAMPLE FIXTURE: purpose\-built evidence for HarvestGuard documentation. Not a real environment, not a real scan, no customer, personal or confidential data. |
| Crypto files inspected | 12 |

### Recorded scanner errors

- None recorded. An empty recorded-error list is interpreted only as far as the collection-contract check allows (EV-CHK-003, EV-CHK-004).

## Evidence checks and limitations

Each row is an explicitly identified check. Required checks are selected by the executive policy version from the declared scope before any result is examined.

| Check | Name | Required | Applicable | State |
| --- | --- | --- | --- | --- |
| EV\-CHK\-001 | evidence\_integrity | yes | yes | passed |
| EV\-CHK\-002 | supported\_evidence\_schema | yes | yes | passed |
| EV\-CHK\-003 | supported\_collection\_contract | yes | yes | passed |
| EV\-CHK\-004 | execution\_completeness | yes | yes | passed |
| EV\-CHK\-005 | reference\_consistency | yes | yes | passed |
| EV\-CHK\-006 | scan\_time\_basis | yes | yes | passed |
| EV\-CHK\-007 | scope\_observability | yes | yes | passed |
| EV\-CHK\-008 | dated\_expiration\_basis | yes | no | not\_applicable |

### EV\-CHK\-001 Stored evidence integrity

- State: passed
- Result: The stored run's recomputed digest matched the stored digest 62d36beb4d8dd1b7053bc9d1f153ac97bd9bb374b0e0f28457ce5d98adaff6f0.
- Method: evidence\_store.load\_scan\_run\(\) recomputed the stored run's SHA\-256 digest over its canonical run payload and ordered finding snapshots and compared it with the stored digest. verify\_loaded\_scan\_run\(\) rechecked the current payload with the same canonical digest definition and checked reconstruction consistency before this projection was built. A mismatch fails closed with EvidenceIntegrityError; no view is produced.
- Limitation: Internal consistency of the stored run only: not a signature, not source authenticity, and no protection against modification of both the payload and the digest.
- Source: evidence\_store.load\_scan\_run

### EV\-CHK\-002 Supported evidence interpretation

- State: passed
- Result: Every retained record uses normalized\-finding schema version 1.0.0, which this policy version interprets.
- Method: Compared the run's recorded normalized\-finding schema version, and each retained snapshot's own schema version, with the schema versions executive policy 0.1.0 is defined to interpret: 1.0.0.

### EV\-CHK\-003 Supported collection contract

- State: passed
- Result: Every scanner/version pair recorded for this run has a documented collection contract: semgrep\_crypto\_rules 0.2.0.
- Method: Matched every scanner/version pair recorded for this run against the collection contracts executive policy 0.1.0 documents an evidence basis for. A pair with no documented contract is unknown; it does not pass by default.
- Limitation: The supported\-contract mapping names scanner/version pairs whose execution\-failure semantics are documented. It says nothing about detection quality or coverage for those scanners.
- Source: Collection contract 0.2.0 propagates execution and output failures through LocalScanError into the run's recorded scanner\_errors, retaining usable partial findings \(docs/DETECTION\_CHARACTERIZATION.md, execution provenance\).

### EV\-CHK\-004 Execution completeness

- State: passed
- Result: Every recorded scanner/version pair persists execution failures into scanner\_errors, and this run recorded none.
- Method: Read the run's recorded scanner\_errors, and required every recorded scanner/version pair to have a documented collection contract \(EV\-CHK\-003\) before an empty error list could be read as successful execution.
- Limitation: An empty scanner\-error list establishes execution completeness only for scanner/version pairs whose collection contract persists execution failures. Stored integrity verification never establishes scanner success.

### EV\-CHK\-005 Evidence reference consistency

- State: passed
- Result: All 1 evidence reference\(s\) resolve to exactly one stored snapshot occurrence of run synthetic\-unrecognized\-fields\-001.
- Method: Resolved every evidence reference \(scan\_id, snapshot ordinal, finding\_id\) against the stored snapshots in canonical stored order, and compared each snapshot's recorded scan\_id and finding\_id with the run identity and the reconstructed record. Occurrences sharing a finding\_id are not deduplicated.
- Limitation: Reference consistency is an identity check over stored records. It is not a content\-integrity check and does not re\-hash stored evidence.

### EV\-CHK\-006 Recorded scan\-time basis

- State: passed
- Result: The run recorded scan time 2025\-11\-04T09:30:00\+00:00, which is the basis for every time\-based derivation in this view.
- Method: Parsed the run's recorded scan\_time as an ISO\-8601 timestamp. Time\-based derivations use that recorded time; no current\-clock value is substituted when it is missing or unreadable.
- Limitation: The recorded scan time is the collecting host's clock reading. It is not independently attested or externally timestamped.

### EV\-CHK\-007 Requested scope observability

- State: passed
- Result: No retained record shows requested scope that could not be read. Configured exclusions and depth limits are reported as scope disclosures, not as observability failures.
- Method: Classified every retained record with reports.classify\_finding\(\) and separated coverage and skipped/inaccessible records that are by design or configured \(max\_depth\_boundary, skipped\_special\_file\) from records showing requested scope that could not be read.
- Limitation: Only scope the scanners recorded is considered. Scope that was never requested, and scope no scanner can enumerate, is outside this check.

### EV\-CHK\-008 Dated certificate\-expiration basis

- State: not\_applicable
- Result: No dated certificate\-expiration derivation was attempted for this run.
- Method: Established whether the declared scope includes a scanner that records certificate validity metadata and whether a recorded scan time \(EV\-CHK\-006\) is available to date it against.
- Not applicable because: The declared scope includes no scanner that observes certificate validity metadata: semgrep\_crypto\_rules.

## Defined exceptions

Exceptions are a closed set defined by the executive policy version. An exception carries no severity, no priority and no recommendation.

### EV\-EXC\-003 unrecognized\_stored\_fields

- Statement: 1 stored snapshot occurrence\(s\) carry field\(s\) this release does not recognize, including any unrecognized direct provenance member \-\- reported as provenance.\<member\-name\> \-\- even when it is the only unrecognized field on that occurrence: experimental\_attribution, provenance.experimental\_collector\_note. They are retained in the stored payload rather than discarded, and are not interpreted by this view. Names are disclosed here and in both executive export formats. Their values are withheld from this disclosure view because an unrecognized field's content has no established privacy classification. They remain retained unchanged in the verified local evidence store, which is the technical\-traceability source, and stay covered by the existing evidence digest.
- Outcome-affecting: yes
- Detail: experimental\_attribution
- Detail: provenance.experimental\_collector\_note
- Evidence: [synthetic\-unrecognized\-fields\-001 ordinal 0 (finding ID 2adf7d326cca9a250b6785c912057fa2c6ac9421caf7ff54d791e9b3e137086f)](#evidence-synthetic-unrecognized-fields-001-0)

## Supported conclusions and limits

### EV\-CON\-001 (check\_result)

- Statement: The stored run's recomputed digest matched the stored digest 62d36beb4d8dd1b7053bc9d1f153ac97bd9bb374b0e0f28457ce5d98adaff6f0.
- Method: evidence\_store.load\_scan\_run\(\) recomputed the stored run's SHA\-256 digest over its canonical run payload and ordered finding snapshots and compared it with the stored digest. verify\_loaded\_scan\_run\(\) rechecked the current payload with the same canonical digest definition and checked reconstruction consistency before this projection was built. A mismatch fails closed with EvidenceIntegrityError; no view is produced.
- Identified check: EV\-CHK\-001
- Limitation: Internal consistency of the stored run only: not a signature, not source authenticity, and no protection against modification of both the payload and the digest.

### EV\-CON\-002 (check\_result)

- Statement: Every recorded scanner/version pair persists execution failures into scanner\_errors, and this run recorded none.
- Method: Read the run's recorded scanner\_errors, and required every recorded scanner/version pair to have a documented collection contract \(EV\-CHK\-003\) before an empty error list could be read as successful execution.
- Identified check: EV\-CHK\-004
- Identified check: EV\-CHK\-003
- Limitation: An empty scanner\-error list establishes execution completeness only for scanner/version pairs whose collection contract persists execution failures. Stored integrity verification never establishes scanner success.

### What this view could not establish

- Conflicts between records: not assessed. No conflict assessment ran for this run.

### Standing limits

- A matching stored digest establishes internal consistency of the stored run only. It is not a signature, not proof of source authenticity, and no protection against deliberate modification of both the payload and the digest by anyone who can write to the evidence database.
- This view describes retained normalized evidence from one scan run. It does not establish that a scanned asset is deployed, in use, trusted, or reachable.
- Absence of a record is not evidence of absence: each scanner has a deliberately narrow detection surface \(docs/DETECTION\_CHARACTERIZATION.md\).
- No conflict assessment ran, so conflicts between records are not assessed. This view does not state that there are no conflicts.
- Certificate expiration is a dated technical derivation against the recorded scan time. It is not a risk rating, a remediation verdict, or a statement of business impact.
- This view establishes evidence. It does not establish organizational security, regulatory compliance, quantum readiness, or business safety; those remain human judgment.

## Technical evidence detail

Every retained snapshot occurrence of this run, in canonical stored order. Occurrences that share a finding ID are separate occurrences and are listed separately; the complete reference to one occurrence is this run's scan ID plus its ordinal plus its finding ID. Recognized fields carry their exact stored values; a recognized field the stored snapshot did not carry is absent rather than defaulted.

<a id="evidence-synthetic-unrecognized-fields-001-0"></a>

### Occurrence 0

- Complete reference: scan synthetic\-unrecognized\-fields\-001, ordinal 0, finding ID 2adf7d326cca9a250b6785c912057fa2c6ac9421caf7ff54d791e9b3e137086f

| Stored field | Value |
| --- | --- |
| finding\_id | 2adf7d326cca9a250b6785c912057fa2c6ac9421caf7ff54d791e9b3e137086f |
| scan\_id | synthetic\-unrecognized\-fields\-001 |
| source\_type | code\_analysis |
| asset\_type | source\_code |
| location | /synthetic/example\-target/app/crypto\_utils.py:14 |
| asset\_name | crypto\_utils.py:14 |
| scanner\_name | semgrep\_crypto\_rules |
| scanner\_version | 0.2.0 |
| observed\_at | 2025\-11\-04T09:30:00\+00:00 |
| evidence | Semgrep rule matched: weak\-hash\-md5 |
| confidence | High |
| confidence\_rationale | null |
| collection\_method | static source\-text match |
| collection\_source | vendored semgrep rule set |
| rule\_id | weak\-hash\-md5 |
| repeatable | true |
| verification\_rationale | re\-running the same rule set reproduces the match |
| provenance.scanner\_name | semgrep\_crypto\_rules |
| provenance.scanner\_version | 0.2.0 |
| provenance.collection\_method | static source\-text match |
| provenance.source | vendored semgrep rule set |
| provenance.rule\_id | weak\-hash\-md5 |
| provenance.collected\_at | 2025\-11\-04T09:30:00\+00:00 |
| provenance.repeatable | true |
| provenance.verification\_rationale | re\-running the same rule set reproduces the match |
| identity\_key | null |
| ownership\_signals | \{\} |
| unknowns | \[\] |
| limitations | \[\] |
| errors | \[\] |
| technical\_metadata | \{"Rule": "weak\-hash\-md5"\} |
| schema\_version | 1.0.0 |

- Unrecognized stored field name(s), values withheld: `experimental_attribution`, `provenance.experimental_collector_note`
- Their values are withheld from this disclosure view because an unrecognized field's content has no established privacy classification. They remain retained unchanged in the verified local evidence store, which is the technical\-traceability source, and stay covered by the existing evidence digest.
