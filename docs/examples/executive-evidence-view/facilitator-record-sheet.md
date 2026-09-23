# Facilitator record sheet (template)

**FACILITATOR AND SCORER ONLY. Never shown to, handed to, or left within sight
of a participant, before, during or after a session.**

This sheet records one session and its scoring. The participant only ever sees
the evaluated artifact and the two participant sheets in
[`participant/`](participant/), in the order and at the times set by
[`comprehension-protocol.md`](comprehension-protocol.md) §4. Do not use this
sheet until the maintainer has approved and frozen that protocol.

Copy this sheet per participant. Record **only** the fields below: no name, no
contact details, no employer, no demographics, no recordings.

---

## Session record

| Field | Value |
| --- | --- |
| Anonymized participant ID | `P-0n` |
| Relevant nontechnical background | e.g. "operating executive, no security engineering role" |
| Evaluated artifact | `samples/<file>.md` |
| Artifact SHA-256 | from `manifest.json` |
| Repository commit SHA | |
| HarvestGuard version in the artifact | |
| Date (UTC) | |
| How the artifact was displayed | e.g. printout, locally rendered page showing only that file |
| Timing method used | e.g. stopwatch, form timestamps |
| Timing start: artifact first displayed | time |
| Timing stop: Part 1 submitted | time |
| Elapsed time for Q1–Q3 | seconds |
| Part 2 handed over after Part 1 submitted | yes / no — describe |
| Protocol deviation | none / describe |

## Answers, verbatim

Copied from the participant's Part 1 and Part 2 sheets exactly as written, or
faithfully transcribed. Never rewritten, tidied or summarized before scoring.
Keep the original sheets with this record.

**Q1. What did HarvestGuard observe?**

>

**Q2. What evidence supports those observations?**

>

**Q3. What can and cannot be concluded from that evidence?**

>

**Q4. What does "Evidence evaluation: VERIFIED" mean?** (Part 2, untimed)

>

## Scoring (completed after the session, against protocol §6 and §7)

| Question | Initial score (correct / partial / incorrect / ambiguous) | Rubric reasoning |
| --- | --- | --- |
| Q1 | | |
| Q2 | | |
| Q3 | | |
| Q4 interpretation | | Prohibited interpretation present? yes / no — which |

| Field | Value |
| --- | --- |
| Overall result (pass / fail) | |
| Maintainer decision on ambiguity | none required / decision + reason + who |
| Override of an initial score | none / what, why, who |
