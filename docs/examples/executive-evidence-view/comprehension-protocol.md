# Asynchronous human-comprehension protocol (issue #153)

**Status: DRAFT — NOT FROZEN. Awaiting Tim's explicit refreeze.**
**NO PARTICIPANT HAS BEEN TESTED. Human acceptance remains INCOMPLETE.**

This is an acceptance-protocol revision, not acceptance evidence. Tim must
approve the exact revised package commit before any packet is sent. The
[protocol history](protocol-history.md) preserves the previous freeze and the
reason for revising it before any human results existed. This procedure tests
independent comprehension without coaching, not reading speed.

## 1. Evaluated artifact

Use `docs/examples/executive-evidence-view/samples/verified.md`, unchanged from
`997c4d745d4944f3e26c2bc420c753916d3992b0`, source SHA-256
`69b173bacfdc6dc04a9b2daf9223851d20529d376bce6eff64116b49ba15ba94`.
The synthetic artifact is embedded byte-for-byte in the single
[participant packet](participant/reader-packet.md). Record both the source
artifact digest and the sent packet digest and approved package Git revision.
Every reader receives the same approved content apart from their anonymous ID.

## 2. Participants and attempt disposition

Five real, maintainer-approved representative nontechnical decision-making
readers who are not implementing HarvestGuard: for example an operating
executive (CEO/CFO/COO), board member or advisor, PE operating partner or diligence
professional, risk/compliance/legal/security leader, or technically literate
business leader outside the project. No category quota is required. Record
anonymized relevant background, not names, employers or unnecessary demographics.
The independent practitioner cannot also be a reader in this round.

Tim determines eligibility before sending anything, and selects the intended
five-person cohort without reference to results. Dispatch to an eligible reader
starts a recorded attempt; no read receipt, tracking or proof of opening is
required. Every dispatch and all returned evidence remain in the ledger.

Incorrect answers or prohibited VERIFIED interpretations never justify
replacement. Missing answers, missing evidence and nonresponse cannot pass.
A participant may withdraw; retain the withdrawal and all evidence collected.
For nonresponse, Tim may send a neutral availability reminder, then document a
closure decision if no response is available. There is no response deadline or
elapsed-time pass/fail rule. Scheduling delay alone is not a failed comprehension
answer. Record dispatch/reminder/closure dates only for disposition, never for
calculating reading time. Withdrawals and closed nonresponses may be replaced;
link the replacement to the original cohort slot and attempt. Genuine procedural
failure, such as sending the wrong packet, may invalidate an attempt only with
Tim's recorded decision and reason; preserve it and any replacement.

Never silently discard unfavorable attempts, exclusions, withdrawals, invalid
attempts, late returns, reruns or replacements. Preserve late responses even
after replacement; Tim records how they affect the round and cannot select the
best five results. Any prohibited VERIFIED interpretation remains disqualifying
for this round even on a withdrawn, invalid or replaced attempt. Tim decides
ambiguous eligibility, invalidation, scoring and overrides with rationale.

## 3. Materials and administration

Send only a standalone copy of `participant/reader-packet.md`, containing neutral
instructions, the exact artifact, Q1–Q4 and answer spaces. A normal document
reader and a way to return written answers suffice; no repository access,
account, special software or hosted service is required. Tim supplies the return
channel as ordinary logistics. Do not send repository links or this protocol.

The participant must not receive the answer key, rubric, expected answers,
threshold, prohibited-interpretation list, technical-review results or
facilitator/scorer notes. Keep `facilitator-record-sheet.md` private. The artifact's
own evidence explanations remain unchanged. No implementer explanation, coaching
or corrective feedback is given before the participant's response is final.

## 4. Questions and asynchronous sequence

1. What did HarvestGuard observe?
2. What evidence supports those observations?
3. What can and cannot be concluded from that evidence?
4. What does "Evidence evaluation: VERIFIED" mean?

After eligibility and refreeze, Tim sends one packet. The reader opens it when
convenient, reads the artifact, answers Q1–Q3 then Q4 in their own words without
coaching, and returns the written answers to Tim. The artifact remains available
throughout. Returning answers submits the final response; retain it unaltered.
Any subsequent clarification or correction is a separate dated record, never
an overwrite or a coached replacement of the original.

Q4 appears after Q1–Q3 in the same packet. Its unchanged wording asks about a
label already displayed in the artifact; it supplies no definition, expected
answer, limitation or scoring hint. It can direct attention to that label, but
the revised claim is independent comprehension with the whole artifact
available, not unprimed recall. A separate reveal is therefore unnecessary.
Automated checks verify order, unchanged wording, artifact identity and absence
of added coaching; they do not establish human comprehension or prove absence
of a psychological order effect.

## 5. Completion time

There is no pass/fail completion-time requirement, live meeting, controlled
reveal or required timing measurement. Do not use timers, telemetry, recording,
form timing or message timestamps to infer reading speed. Optional approximate
self-reported duration may be retained if volunteered; it is neither required
for validity nor precise timing evidence and never affects acceptance.

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

- At least **four of five** readers correctly answer all of Q1–Q3 without
  coaching. There is no completion-time threshold.
- **No** participant result may contain a prohibited VERIFIED interpretation
  (§6); disposition cannot hide one.
- Partial answers do not count as correct. Missing evidence, an unmet threshold,
  unavailable readers or unresolved ambiguity leave acceptance **incomplete**.

## 9. Records, failures and revisions

Preserve original returned files or verbatim responses, every attempt and its
disposition in [comprehension-results.md](comprehension-results.md), using the
private [record sheet](facilitator-record-sheet.md). AI may mechanically apply
the frozen rubric and flag ambiguity; Tim owns final ambiguous decisions and
records overrides with reasons. No answer-key or rubric change after results
may make an attempt pass. Any later revision requires a transparent new round
and retention of earlier evidence. No participant contact is automated.

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
