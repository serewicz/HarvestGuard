# Human-comprehension evaluation protocol (issue #153)

**Status: DRAFT — NOT FROZEN, NOT APPROVED, NO PARTICIPANT TESTED.**

This protocol was drafted by automation. It becomes the frozen protocol only
when the maintainer (Tim) approves, in writing and before anyone is tested:
the evaluated artifact and its exact revision, this protocol, the questions,
the answer key, the scoring rubric, the timing method, and the participant
criteria. Until then, nothing here may be used to test a participant, and no
result may be reported.

Nothing in this repository contacts, recruits, invites, messages or schedules
a participant. Selection and contact are the maintainer's responsibility.

## 1. Evaluated artifact (proposed, pending approval)

| Field | Value |
| --- | --- |
| Proposed artifact | `docs/examples/executive-evidence-view/samples/verified.md` |
| Format shown | Rendered Markdown, read-only |
| Artifact revision | The committed file at the approved commit SHA — record the SHA and the file's SHA-256 from `manifest.json` in the results |
| HarvestGuard version | As recorded in the artifact's *Produced by* / *Exported by* rows |
| Evidence content | Synthetic; no organizational, customer or confidential evidence |

One standardized artifact is used for every participant. If the maintainer
approves a different artifact, the answer key below must be re-derived from
that artifact *before* any testing, and this file updated in the same change.

## 2. Participants (maintainer-selected)

Five real, maintainer-approved participants who represent intended
decision-making readers and are not implementing HarvestGuard — for example an
operating executive (CEO/CFO/COO), a board member or advisor, a PE operating
partner or diligence professional, a risk/compliance/legal/security leader, or
a technically literate business leader outside the project. No category is
required; the recorded anonymized backgrounds must simply show why the group is
relevant.

AI personas, simulated participants, model answers, developer guesses and AI
estimates of likely comprehension **cannot** substitute for any of the five.

Record only an anonymized participant ID and the relevant nontechnical
background. No names, contact details, employers, demographics or recordings.

## 3. Materials given to the participant

1. One sentence of framing, read verbatim: *"This is a page of output from a
   tool that inspects systems and records what it found. Read it, then answer
   three questions in your own words."*
2. The evaluated artifact.
3. The response form
   ([`participant-response-form.md`](participant-response-form.md)).

Nothing else: no README, no glossary, no explanation of HarvestGuard, no
description of what the tool is for beyond that sentence.

## 4. Questions

Asked in this order, all three shown before timing starts:

1. What did HarvestGuard observe?
2. What evidence supports those observations?
3. What can and cannot be concluded from that evidence?

Asked **separately, after** the first three answers are submitted:

4. What does "Evidence evaluation: VERIFIED" mean?

## 5. Timing method

- The timed period **starts** when the evaluated overview is first displayed to
  the participant.
- It **stops** when the participant submits their answers to the first three
  questions.
- Threshold: all three answers correct, within **30 seconds**.
- Question 4 is **outside** the 30-second timed period and is untimed.
- No coaching, hints, explanation or corrective feedback of any kind during the
  timed portion. Clarifying that an answer may be in the participant's own
  words is permitted; restating or explaining the artifact is not.
- The method actually used (stopwatch, screen recording timestamps, form
  timestamps) is recorded per participant, together with any deviation.

## 6. Answer key (derived from the proposed artifact, before testing)

A participant's answer is scored against the key by meaning, not wording
(see the rubric in §7).

**Q1 — What did HarvestGuard observe?** Correct answers convey *both*:

- a) HarvestGuard retained/recorded a small number of records (2) from a code
  analysis of the stated target, and
- b) those records are source-code locations where a rule matched a weak hash
  (MD5) — i.e. what a scanner read in a declared scope, not a judgement.

**Q2 — What evidence supports those observations?** Correct answers convey:

- a) the two individually listed retained snapshot occurrences (the technical
  evidence detail / the per-record entries), **and**
- b) the named checks run over them (integrity/digest match plus the other
  listed checks) — any recognizable reference to "the listed checks" suffices.

**Q3 — What can and cannot be concluded?** Correct answers convey *both*
directions:

- **Can:** the listed checks passed for the declared scope; the stored evidence
  is internally consistent; the records are what was observed.
- **Cannot:** at least one of — this does not establish organizational
  security, regulatory compliance, business safety, complete coverage of the
  environment, source authenticity, or that nothing else exists (absence of a
  record is not evidence of absence).

An answer giving only the "can" side, or only the "cannot" side, is **partial**
and is not correct.

**Q4 — What does "Evidence evaluation: VERIFIED" mean?** Correct: every
required check listed in the view completed and passed for the declared scope,
with nothing failed, unknown or unperformed.

**Prohibited interpretations of VERIFIED** (any one of these fails the whole
acceptance criterion, regardless of the Q1–Q3 result): organizational security;
regulatory compliance; business safety; complete environmental coverage; source
authenticity; proof that no relevant cryptographic asset exists.

## 7. Scoring rubric

- **Paraphrase handling.** Score meaning, not vocabulary. A paraphrase is
  correct if it conveys every element listed for that question in §6 and adds
  no claim the artifact does not support. Business-domain wording ("it looked
  at the code and flagged two spots using an old hashing method") is correct.
  Correct HarvestGuard jargon is *not* required, and jargon with the wrong
  meaning is *not* correct.
- **Partial answers.** An answer missing any required element for that question
  is scored **partial**, which counts as **not correct**. Partial answers are
  never silently promoted.
- **Added unsupported claims.** An answer that adds a security, compliance,
  risk, safety, completeness or authenticity claim is **not correct**, even if
  it also contains the correct elements.
- **Ambiguous answers.** The scorer must mark **ambiguous** rather than
  guessing, and record why. The maintainer decides every ambiguous answer; the
  decision, its reason and who made it are recorded.
- **AI scoring.** AI may apply this rubric to produce an *initial* score, must
  show the rubric reasoning for each answer, must preserve the original
  response verbatim, must not rewrite answers before scoring, and must flag
  ambiguity rather than resolving it in favour of passing.

## 8. Pass threshold

- At least **four of five** participants answer all of Q1–Q3 correctly within
  30 seconds.
- **No** participant interprets VERIFIED in any prohibited way (§6).
- Unavailable participants, an unmet threshold, or an unresolved ambiguous
  score leave acceptance **incomplete**.

## 9. Changes, failures and reruns

The answer key and rubric **cannot** be changed retrospectively to make results
pass. A revision after results are seen requires a transparent protocol
revision recorded here *and* a new evaluation round with new participants'
answers; the earlier attempt stays in the record. Every failed attempt, rerun
and protocol deviation is preserved in
[`comprehension-results.md`](comprehension-results.md).

## 10. Corrective work if comprehension fails

Permitted corrections are limited to wording, navigation, discoverability or
Markdown layout inside the already-approved projection/serializer architecture,
and must preserve JSON/Markdown semantic parity, evidence references, privacy
boundaries, status policy, schema compatibility, deterministic output, legacy
compatibility, and installed-package and offline operation. Any change to the
executive schema, status or check policy, evidence meaning, reference identity,
storage, verification, scanners, privacy classification, business
interpretation, recommended action or product architecture stops and returns
for separate issue and scope review.
