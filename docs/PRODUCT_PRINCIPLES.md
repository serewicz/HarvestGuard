# Product Principles

These principles prevent HarvestGuard from drifting into a generic security
product. They apply to roadmap decisions, issue scoping, implementation review,
documentation, and release claims.

1. **Crypto-first, not general-purpose security scanning.** HarvestGuard exists
   to inventory cryptographic posture, long-lived data exposure, and related
   remediation priorities. Sensitive-data discovery is included only where it
   supports crypto and diligence questions.
2. **Local-first and private by default.** First use must work without sending
   scan details, file contents, paths, object names, or credentials to a
   HarvestGuard-operated service.
3. **Defensible cryptographic evidence is the primary external value.**
   HarvestGuard inventories cryptographic assets today, providing evidence
   organizations can use to assess future migration planning as cryptographic
   standards evolve.
4. **Observed evidence is separated from inference, risk interpretation, and
   advisory judgment.** Scanner output records what was observed. Risk,
   priority, business interpretation, and advisory conclusions live in a
   separate assessment layer.
5. **HarvestGuard complements existing enterprise tooling.** It is additive to
   security, cloud, asset-management, vulnerability-management, and governance
   platforms; it should not become a replacement for them.
6. **CLI functionality precedes visual polish.** Core scanner behavior must be
   scriptable, testable, and reportable before the dashboard becomes the main
   workflow.
7. **Dashboards expose and link to technical evidence.** Visual summaries must
   make the supporting evidence reachable, not hide it behind colors or scores.
8. **Reports contribute to the Technology Due Diligence Evidence Package.**
   Reports should package cryptographic evidence for executive assessment,
   technical review, integration planning, and cryptographic modernization
   planning without overstating what the tool has observed.
9. **Mature third-party scanners are integrated where appropriate rather than
   rebuilt.** Network, code, binary, and runtime crypto analysis should rely on
   proven tools when they are better than bespoke detection.
10. **SQLite is the initial local system of record.** Local scan history and raw
   findings start in SQLite to keep first use simple and private.
11. **Prometheus stores operational and trend metrics, not detailed findings.**
   Prometheus must not receive file paths, object names, secrets, matched
   values, or full finding details.
12. **Grafana is optional and must not be required for first use.** The built-in
    CLI, local store, reports, and dashboard remain the default experience.
13. **Raw findings remain immutable; prioritization is a separate assessment
    layer.** Remediation status, ownership, notes, and priority must not rewrite
    the original evidence.
14. **Features must improve inventory, evidence quality, reporting, or
    standalone usability without expanding HarvestGuard into an adjacent
    security category.** Work that does not support technology due diligence,
    executive assessment, integration planning, cryptographic modernization, or
    advisory value belongs outside the core roadmap.
