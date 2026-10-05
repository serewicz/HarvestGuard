# Acceptance summary — Executive Evidence View (issue #153)

**Overall status: INCOMPLETE.** Automation and independent technical review
are recorded below, with qualified validation results. The asynchronous reader
revision was explicitly approved and refrozen by Tim; the previous freeze is preserved below as
history. No practitioner or reader testing has occurred. Human acceptance,
merge, #153 closure, #150 closure and release readiness remain
outstanding. Technical approval does not clear the 0.4.0 release.

Acceptance evidence is kept in four clearly separated categories. Category 1
evidence never substitutes for categories 2–4, and automated or AI-produced
work is never described here as human validation.

## Category 1 — Automated and AI-produced evidence

| Item | Status | Where |
| --- | --- | --- |
| Bounded example collection covering every required outcome | Done | [`samples/`](samples/), [`README.md`](README.md) |
| Generated through store → verified load → shared projection → both serializers | Done | [`generate_examples.py`](generate_examples.py) |
| Exact commands, producer/exporter versions, executive schema and policy versions, finding and evidence-store schema versions, scope, scanners, times, provenance, digests, artifact SHA-256 | Done | [`manifest.json`](manifest.json) |
| Deterministic regeneration with an explicit export time, without a public CLI override | Done | `tests/test_executive_evidence_examples.py::test_generation_is_deterministic` |
| Both real CLI export modes exercised end to end, from outside the checkout, on the documented no-install path | Done | `…::test_cli_reproduces_each_sample_apart_from_its_export_time` |
| The same collection regenerated, and both export modes rerun, from a **non-editable install** outside the checkout with no repository import override | Done | `…::test_a_non_editable_install_regenerates_the_committed_collection`, `…::test_installed_cli_reproduces_each_sample_apart_from_its_export_time`, `…::test_the_installed_generator_imports_the_install_not_the_checkout` |
| Generation never deletes or overwrites an existing evidence database or output file | Done | `…::test_generation_refuses_a_work_dir_holding_an_evidence_database`, `…::test_generation_refuses_every_occupied_work_dir_destination` |
| Corruption fails closed: bounded diagnostic, no report, no file | Done | [`samples/failed-integrity-corruption.stderr.txt`](samples/failed-integrity-corruption.stderr.txt) |
| Exact reference resolution, including duplicate finding IDs | Done | `…::test_every_reference_resolves_to_exactly_one_occurrence`, `…::test_duplicate_finding_ids_stay_separate_occurrences` |
| JSON/Markdown semantic parity, record by record: every check, exception, observation, conclusion, status reason and occurrence compared with its complete values | Done | `…::test_json_and_markdown_stay_semantically_parallel`, `…::test_semantic_parity_detects_values_on_the_wrong_record` |
| The CLI used during generation is the implementation the generator imported, verified, never a `harvestguard` found on `PATH` | Done | `…::test_generation_never_runs_a_harvestguard_found_on_path`, `…::test_generation_refuses_a_cli_that_would_import_other_modules`, `…::test_the_installed_generator_refuses_a_console_script_from_elsewhere` |
| Unknown-field name disclosure, value withholding, local-retention disclosure | Done | `…::test_unrecognized_fields_disclose_names_and_withhold_values` |
| Secret-canary exclusion and no identifying data in published artifacts | Done | `…::test_published_artifacts_carry_no_secret_or_identifying_values` |
| No external generation dependency (no service, account, telemetry, upload) | Done | `…::test_generation_needs_no_network` |
| Published sample commands and links match shipped behaviour | Done | `…::test_documented_export_commands_use_options_the_cli_accepts`, `…::test_readme_relative_links_resolve` |
| Clean install, packaging, outside-checkout operation | Done (pre-existing) | `tests/test_clean_install.py`, `tests/test_packaging_dependencies.py` |
| #151/#152 projection, export, CLI, evidence-store, clock-safety and legacy regressions preserved and rerun | Done (pre-existing) | `tests/test_executive_evidence.py`, `tests/test_executive_exports.py`, `tests/test_executive_serializer_clock_safety.py`, `tests/test_cli.py`, `tests/test_evidence_store.py`, `tests/test_reports.py` |
| AI-drafted protocol, questions, answer key, rubric, asynchronous sequence, participant packet, facilitator record sheet, templates | **APPROVED AND REFROZEN** by Tim (Category 4) | [`comprehension-protocol.md`](comprehension-protocol.md), [`participant/`](participant/), [`facilitator-record-sheet.md`](facilitator-record-sheet.md) |
| Single standalone reader packet, unchanged artifact and questions, no added scoring material | **APPROVED AND REFROZEN** by Tim (Category 4) | `…::test_async_packet_identity_questions_and_isolation` |

Independent validation at implementation head
`c934e63c8c3c0d0b7150301e1942b7e76d0439b8` is recorded in
[technical-traceability-review.md](technical-traceability-review.md). The complete
local suite was **3,398 passed, 2 failed, 4 setup errors, 5 skipped**, not an
unconditionally green suite. The same two failures and four setup errors
reproduce on exact main `77b52ac56833d9821008d1466683bb9969ed7641` in the
unchanged `tests/test_end_to_end_validation.py`; independent review classified
them as separate QA follow-up, not a PR #160 merge blocker or demonstrated
product/runtime defect. Release readiness still requires separate disposition.

Most tests in this collection need only a Python interpreter with
the repository's development requirements installed. The installed-package
tests have one more dependency, stated here rather than assumed away: they
install HarvestGuard *with its declared dependencies* into a fresh, isolated
virtual environment, so they need a package index — network access, or a pip
cache or configured index that can supply those dependencies. Like
`tests/test_clean_install.py`, they are skipped, and reported as skipped, when
`HARVESTGUARD_SKIP_CLEAN_INSTALL_TESTS=1` is set for offline work.

Two distinct CLI levels are reported separately, because they prove different
things. The `…::test_cli_reproduces_each_sample…` tests run the documented
no-install entry point (`python -m harvestguard`) from outside the checkout
with the repository on `PYTHONPATH`; that is the no-install path, not an
installed release. The installed-package tests build a throwaway virtual
environment *without* `--system-site-packages`, `pip install` the project into
it non-editably with its declared dependencies, and then confirm inside that
environment — before generating anything — that system site-packages are off,
`pip check` is clean, and every declared dependency resolves from the
environment itself. Only then do they regenerate the whole collection and
rerun both export modes from outside the checkout with `PYTHONPATH` removed, so
the committed samples are established as reproducible from an installed
release, with no repository import override and no reliance on packages
installed globally or in the test runner's own environment. A HarvestGuard
version change makes the committed samples stale by design, and the
regeneration tests fail until they are regenerated.

## Category 2 — Independent technical-review evidence

| Item | Status |
| --- | --- |
| Independent traceability review of the immutable artifacts | **APPROVE WITH NON-BLOCKING FOLLOW-UP** at `c934e63c8c3c0d0b7150301e1942b7e76d0439b8` — see [`technical-traceability-review.md`](technical-traceability-review.md) |

## Category 3 — Real human-comprehension evidence and real human use

| Item | Status |
| --- | --- |
| Independent practitioner completes the published use path unaided | **NOT PERFORMED** — see [`independent-use-record.md`](independent-use-record.md) |
| Five real representative nontechnical participants | **NOT TESTED** — see [`comprehension-results.md`](comprehension-results.md) |
| ≥ 4 of 5 answer all Q1–Q3 correctly without coaching | **NOT ESTABLISHED** |
| No participant interprets VERIFIED in a prohibited way | **NOT ESTABLISHED** |

Independent use and comprehension are recorded separately. No individual may
participate in both for this round. No tooling in this repository contacts, recruits,
invites, messages or schedules anyone.

## Category 4 — Maintainer decisions

### Current reader revision — APPROVED AND REFROZEN

Tim explicitly approved and refroze the asynchronous reader package on
2026-09-24 at `028836c4f5bac1b9156b6f25732848d3b40fe1b1`.
The full decision, scope, packet/artifact identities and digests are recorded in
[protocol-history.md](protocol-history.md#maintainer-refreeze--2026-09-24).
This supersedes the synchronous reader procedure for future attempts while
preserving its history. It tests independent comprehension without coaching,
not reading speed. No human result motivated the revision; no attempts occurred
under the prior procedure. The recording commit does not replace the immutable
approved package revision. Independent technical evidence and the separately
frozen practitioner procedure remain unchanged. Both human exercises remain
outstanding. No packet has been dispatched by this recording task.

### Historical revision 1 approval and freeze — 2026-09-24

The following records the original decision, not approval of the async revision.

Tim explicitly approved and froze the human acceptance package in his written
instruction in the Codex conversation, beginning: “I approve and freeze the
HarvestGuard #153 human acceptance package at PR #160 head”. This entry records
that human decision; it is not an AI approval or a human-test result.

- **Frozen package Git revision:** `997c4d745d4944f3e26c2bc420c753916d3992b0`.
- **Evaluated artifact:** `docs/examples/executive-evidence-view/samples/verified.md`.
- **Artifact SHA-256:** `69b173bacfdc6dc04a9b2daf9223851d20529d376bce6eff64116b49ba15ba94`.
- **Implementation-review ancestor:** `c934e63c8c3c0d0b7150301e1942b7e76d0439b8`.

Approval covers the comprehension protocol; Part 1 Q1–Q3; Part 2 Q4; answer
key; scoring rubric; stopwatch timing; participant eligibility; cohort
disposition/replacement rules; facilitator record procedure; and the independent
practitioner procedure, permitted documentation, `synthetic-verified-001`
input/workflow and independence requirements, exactly as documented at the
frozen revision.

Tim approved the facilitator-controlled standalone read-only presentation,
stopwatch starting when the artifact first becomes visible and stopping when
Part 1 is submitted, no screen recording, no revision of submitted Part 1,
then untimed Q4 with the artifact remaining visible. The five-reader threshold
and disposition rules and the practitioner procedure are frozen unchanged.

The approved materials are the files at the immutable revision above. Their
pre-approval draft/pending labels describe their state when authored; this
maintainer decision supersedes those labels only, not their contents or
requirements. This later recording commit does not replace the frozen package
revision. In particular, the practitioner receives the source and permitted
documents from that frozen SHA, not a moving branch or this later record.

No participant selection, contact, testing or results are recorded by this
approval. Independent-practitioner and five-reader acceptance remain
outstanding. Merge, #153/#150 closure and release decisions remain separate.

### Current decision status

| Decision | Status |
| --- | --- |
| Refreeze reader package with the unchanged evaluated artifact | **APPROVED AND REFROZEN** by Tim, 2026-09-24, revision above |
| Refreeze asynchronous protocol, packet, questions, key and rubric | **APPROVED AND REFROZEN** by Tim, 2026-09-24, revision above |
| Refreeze reader eligibility/disposition rules | **APPROVED AND REFROZEN** by Tim, 2026-09-24, revision above |
| Independent-practitioner packet and procedure | Existing freeze unchanged |
| Select and contact participants | **OUTSTANDING**; Tim’s responsibility |
| Resolve any ambiguous score; record overrides with reasons | **PENDING** (none to resolve yet) |
| Approve revised reader package exact revision | **APPROVED AND REFROZEN** by Tim, 2026-09-24, revision above |
| Final acceptance, merge, epic closure, release decisions | **PENDING** |

## Claims audit

- No recommendation, remediation, priority, business-risk, materiality,
  compliance, PQC-readiness or security verdict is introduced anywhere in this
  collection; the samples are the shipped evidence-only output.
- No paid product, consulting engagement, hosted service, proprietary account,
  telemetry, external AI service, report upload, withheld functionality or
  lead funnel is required or implied at any step.
- Unknowns, coverage limits, authenticity limits and interpretation limits stay
  visible in every sample, including the standing limits section.
- A matching digest is stated as internal consistency only — never as a
  signature, source authenticity or tamper protection.
- No release work is done here: no version change, roadmap reconciliation,
  changelog, release notes, tag, publication workflow, PyPI or GitHub Release
  state, and no announcement. Those follow #153's closure review and epic
  #150's own closure review.


## Maintainer scope amendment — 2026-10-05 (append-only)

> External human-comprehension validation is deferred beyond 0.4.0 because participant recruitment has not produced the required completed evaluations. Recruitment is insufficient; human comprehension remains unverified. This is not a failed comprehension test and does not establish a passing result. The original requirements, frozen materials, scoring rubric, prior decisions, and any participant evidence remain preserved. Automated tests and independent technical review are separate evidence categories and do not substitute for human validation.

Tim explicitly approved this decision and its implementation in the Codex conversation on 2026-10-05. Recruitment insufficiency is recorded from that instruction; no count, dispatch, response, score or outcome is inferred from it. This is a maintainer scope decision, not acceptance evidence.

External reader comprehension is no longer a 0.4.0 release requirement. Its unperformed criteria are **deferred, not passed**, to [#161 — Executive Evidence View: complete deferred external human-comprehension validation](https://github.com/serewicz/HarvestGuard/issues/161). This is deferred acceptance work, not another implementation child. Original issue text and unchecked criteria above remain historical requirements; this dated amendment controls only their release/closure applicability.

The approved asynchronous package remains `028836c4f5bac1b9156b6f25732848d3b40fe1b1`: five representative readers, at least four of five correct on all Q1–Q3 without coaching, no prohibited VERIFIED interpretation, unchanged questions/key/rubric, full unfavorable-evidence retention and maintainer scoring authority. It has no completion-time requirement. Preserve the earlier timed package `997c4d745d4944f3e26c2bc420c753916d3992b0`, original 30-second criterion and all freeze/refreeze decisions. No frozen material is regenerated or edited.

**Independent practitioner use remains required and incomplete.** It is not part of this deferral. The practitioner must complete the already-approved frozen procedure at `997c4d745d4944f3e26c2bc420c753916d3992b0` unaided; no technical/automated result substitutes for this human exercise.

For this issue, the five-reader records, four-of-five Q1–Q3 correctness and prohibited-VERIFIED-interpretation acceptance criteria move to deferred fulfillment in #161. Their response/scoring/attempt-retention obligations remain binding on any evidence and on that follow-up. The final acceptance/post-merge closure and Definition of Done requirements now exclude external reader completion only; they still require practitioner acceptance, technical review and all other nondeferred criteria. The existing restriction on release work in #153 and requirement for a separate #150 closure review remain. This amendment supersedes earlier language only insofar as it made missing reader results block #153/#150 closure or 0.4.0; it does not declare any criterion satisfied.

For this epic, the reader-comprehension acceptance criterion and reader timing/comprehension regression requirement are deferred to #161. The original under-30-seconds objective is not a validated claim. The exactly-three-implementation-children contract is unchanged; #153 must satisfy its amended contract, including practitioner acceptance, before closure. The children-merged-and-closure-reviewed criterion remains required, evaluated against the expressly amended scope. After #153 closes, #150 still requires its own closure review before roadmap reconciliation or release preparation. Technical traceability, compatibility, privacy and evidence/status semantics are unchanged.

Exact-head independent review, required CI, maintainer merge, post-merge closure review and honest QA disposition remain required. This decision authorizes no merge, closure, version change, release preparation, tag, publication or announcement. #153 and #150 remain open.

Known QA remains separate: the two host-dependent coverage assertions (#154 / PR #158) and four previously recorded installed-fixture setup errors must be fixed or explicitly dispositioned with evidence for release readiness. Green CI skips wheel/sdist install checks and does not establish 0.4.0 artifact readiness. The known blank line at EOF in the frozen reader packet is retained with an explicit narrow whitespace exception rather than changing the frozen digest. No QA fix is included in this scope amendment.

### Frozen identities and evidence limits

- Evaluated `samples/verified.md` SHA-256: `69b173bacfdc6dc04a9b2daf9223851d20529d376bce6eff64116b49ba15ba94`.
- `participant/reader-packet.md` SHA-256: `6340e20896aba669be514b8c31100fdb86c5cf5cb557d31987c0d5529ea5a86e`.
- [Protocol history](protocol-history.md), protocol, answer key, rubric, participant packet, samples, manifest and independent-use record remain unchanged. Preapproval labels in immutable materials are interpreted through the existing freeze/refreeze decisions, not edited away.
- Historical independent technical approval remains scoped to `c934e63c8c3c0d0b7150301e1942b7e76d0439b8`; subsequent changes require final-head review.
- Before this amendment, PR #160 head `08c87cb7d7a1482ff8e55a7e97565ff58734b55c` had [CI](https://github.com/serewicz/HarvestGuard/actions/runs/36042578847) reporting 3,404 passed and 2 skipped per Python 3.10/3.11/3.12, with Ruff passing. Exact main `77b52ac56833d9821008d1466683bb9969ed7641` had [CI](https://github.com/serewicz/HarvestGuard/actions/runs/35385840664) reporting 3,300 passed and 2 skipped per version. Those are automated results for those revisions, not human evidence or CI for a later commit.
- No participant response or practitioner result has been added. Earlier empty result/dispatch records are preserved as historical records, not asserted to be a current recruitment ledger. No comprehension-within-30-seconds claim is made.

### Closure and release status

Current #153 status remains INCOMPLETE: practitioner acceptance, final-head review, merge and post-merge closure review are outstanding. #150 remains open pending #153 and its own closure review. The reader study remains unverified in #161. Future release documentation must disclose the deferral and distinguish automated tests, independent technical review and real human evidence. This record is a scope amendment only, not the start of 0.4.0 release preparation; no package version, changelog, release notes or roadmap status changes accompany it.

### Verification of this documentation-only amendment

The relevant example/acceptance suite was run with
`HARVESTGUARD_SKIP_CLEAN_INSTALL_TESTS=1`: **98 passed, 5 explicitly skipped**
(installed-package checks requiring dependency provisioning). This is not a
fresh installed-package validation or a full-suite run. Frozen artifact and
packet hashes, key/rubric, protocol history, manifest, all sample files and the
practitioner procedure remain byte-identical to the pre-amendment head; the
frozen package references and added documentation links were checked.
`git diff --check` passes for this amendment. The cumulative PR diff against
main retains only the pre-existing `participant/reader-packet.md:336` blank-line
at EOF finding. That exact frozen-content exception is disclosed, not fixed or
reported as a clean cumulative whitespace check. No human result is created or
inferred. CI for the pushed amendment must be checked separately from the
historical CI runs above.
