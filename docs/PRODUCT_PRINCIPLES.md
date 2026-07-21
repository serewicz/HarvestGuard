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
3. **Observed evidence is separated from inferred risk.** Scanner output records
   what was observed. Risk, priority, and business interpretation live in a
   separate assessment layer.
4. **CLI functionality precedes visual polish.** Core scanner behavior must be
   scriptable, testable, and reportable before the dashboard becomes the main
   workflow.
5. **Dashboards expose and link to technical evidence.** Visual summaries must
   make the supporting evidence reachable, not hide it behind colors or scores.
6. **Findings support both executive and technical users.** Reports should help
   executives decide and help technical owners remediate.
7. **Mature third-party scanners are integrated where appropriate rather than
   rebuilt.** Network, code, binary, and runtime crypto analysis should rely on
   proven tools when they are better than bespoke detection.
8. **SQLite is the initial local system of record.** Local scan history and raw
   findings start in SQLite to keep first use simple and private.
9. **Prometheus stores operational and trend metrics, not detailed findings.**
   Prometheus must not receive file paths, object names, secrets, matched
   values, or full finding details.
10. **Grafana is optional and must not be required for first use.** The built-in
    CLI, local store, reports, and dashboard remain the default experience.
11. **Raw findings remain immutable; prioritization is a separate assessment
    layer.** Remediation status, ownership, notes, and priority must not rewrite
    the original evidence.
12. **Features must support diligence, ownership-period risk, remediation, or
    advisory value.** Work that does not serve one of those outcomes belongs
    outside the core roadmap.
