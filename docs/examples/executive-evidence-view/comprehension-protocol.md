# Human-comprehension evaluation protocol (issue #153)

**Status: DRAFT — NOT FROZEN, NOT APPROVED, NO PARTICIPANT TESTED.**

This protocol was drafted by automation. It becomes the frozen protocol only
when the maintainer (Tim) approves, in writing and before anyone is tested:
the evaluated artifact and its exact revision, this protocol, the questions,
the participant sheets and session sequence (§3, §4), the answer key, the
scoring rubric, the timing method, and the participant criteria. Until then, nothing here may be used to test a participant, and no
result may be reported.

Nothing in this repository contacts, recruits, invites, messages or schedules
a participant. Selection and contact are the maintainer's responsibility.

## 1. Evaluated artifact (proposed, pending approval)

| Field | Value |
| --- | --- |
| Proposed artifact | `docs/examples/executive-evidence-view/samples/verified.md` |
| Format shown | Standalone rendered Markdown in a facilitator-controlled local/read-only presentation; no repository navigation or file listing |
| Artifact revision | The exact corrected PR commit approved by Tim; record its full Git SHA before testing |
| Source artifact SHA-256 | `69b173bacfdc6dc04a9b2daf9223851d20529d376bce6eff64116b49ba15ba94` (unchanged from reviewed implementation `c934e63c8c3c0d0b7150301e1942b7e76d0439b8`) |
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

Determine eligibility before the participant sees the evaluated artifact.
Select and record the intended five-person cohort without reference to results.
The independent practitioner must not be one of these five readers in this
round. Tim decides ambiguous eligibility, recording the decision and rationale.

Every eligible started attempt remains in the acceptance record. Incorrect
answers, exceeding 30 seconds, and prohibited interpretations of VERIFIED are
not grounds for replacement. Missing required evidence cannot count as a pass.
A genuine procedural failure (such as the wrong artifact or a failed stopwatch)
may invalidate a session; Tim must record the reason and decision, retain the
attempt, and record any replacement. A withdrawal may be replaced, but retain
the withdrawal and all evidence already collected. No unfavorable attempt,
exclusion, withdrawal, invalid session, rerun or replacement may be silently
discarded. Link replacements to their original attempts, preserving the
five-person cohort accounting rather than selecting the best five results.
Tim decides ambiguous invalidation, scoring and overrides with a recorded
rationale. Disposition never erases a prohibited VERIFIED interpretation or
makes it permissible under the no-participant criterion in §8.

## 3. Materials: what the participant may and may not see

Participant-facing material is kept apart from facilitator and scoring
material, in its own directory, so that one cannot be handed over with the
other.

**The participant sees only, and only when §4 says:**

1. One sentence of framing, read aloud verbatim: *"This is a page of output
   from a tool that inspects systems and records what it found. Read it, then
   answer three questions in your own words."*
2. The evaluated artifact (§1), displayed standalone (§4, session step 3).
3. **Part 1**, [`participant/part-1-questions-1-3.md`](participant/part-1-questions-1-3.md):
   Q1–Q3 only. It does not mention or hint at Q4.
4. **Part 2**, [`participant/part-2-question-4.md`](participant/part-2-question-4.md):
   Q4 only, handed over after Part 1 has been submitted.

**The participant never sees, at any point:** this protocol, the answer key
(§6), the rubric (§7), the pass threshold (§8), the
[`facilitator-record-sheet.md`](facilitator-record-sheet.md), the results
file, any other file in this repository, a README, a glossary, or any
explanation of HarvestGuard beyond the framing sentence. This is why the
artifact is never shown through a repository browser or file listing: the
answer key and rubric sit in the same directory.

Each participant sheet is a standalone printed rendering, handed over on
paper, never as a link into this repository. Q4 stays out of sight and reach
until Part 1 has been submitted. No screen recording is used.

## 4. Questions and session sequence

The questions, in this order:

1. What did HarvestGuard observe?
2. What evidence supports those observations?
3. What can and cannot be concluded from that evidence?
4. What does "Evidence evaluation: VERIFIED" mean?

Q1–Q3 are on Part 1 and are shown before timing starts. Q4 is on Part 2 and is
shown **only after** Part 1 has been submitted.

**Before the session** (facilitator, out of the participant's sight):

1. Prepare the evaluated artifact as a standalone, read-only rendering of the
   approved revision of the file named in §1, in a facilitator-controlled
   local/read-only presentation showing only that file. Its own in-page
   section links may work; nothing may lead to any other file, repository
   navigation or file listing. Keep it closed until session step 3.
2. Prepare Part 1 and Part 2 with the anonymized participant ID written in.
   Keep Part 2 out of the participant's sight and reach.
3. Open a copy of the facilitator record sheet, kept out of the participant's
   sight for the whole session.

**The session**, in exactly this order:

1. Hand the participant Part 1. The artifact is **not** displayed yet. The
   participant may read the three questions.
2. Read the framing sentence (§3, item 1) aloud, verbatim.
3. Display the artifact. **Timing starts**: start the stopwatch at the moment
   the artifact first becomes visible.
4. The participant answers Q1–Q3 on Part 1, with the artifact in view. No
   coaching, hints, explanation or corrective feedback (§5).
5. The participant submits Part 1 by handing it back. **Timing stops**: stop
   the stopwatch at that moment. The facilitator records the start, stop and
   elapsed time on the record sheet and takes
   Part 1 out of the participant's reach; its answers cannot be revised.
6. Only now, hand over Part 2. The artifact stays displayed exactly as it was.
   Q4 is **untimed**.
7. The participant submits Part 2 by handing it back. The session ends.
8. After the participant has left, the facilitator completes the record sheet
   (verbatim answers, method, deviations) and keeps both original sheets with
   it. Scoring (§6, §7) happens afterwards, never in front of the participant.

Any departure from this sequence is a protocol deviation and is recorded.

## 5. Timing method

- The timed period **starts** when the evaluated overview — the top of the
  evaluated artifact — is first displayed to the participant (§4, session
  step 3).
- It **stops** when the participant submits Part 1, their answers to Q1–Q3
  (§4, session step 5).
- Threshold: all three answers correct, within **30 seconds**.
- Question 4 is **outside** the 30-second timed period and is untimed.
- No coaching, hints, explanation or corrective feedback of any kind during the
  timed portion. Clarifying that an answer may be in the participant's own
  words is permitted; restating or explaining the artifact is not.
- Use a stopwatch only; record elapsed seconds, start/stop events and any
  deviation per participant. Do not use screen recording or form timestamps.

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
