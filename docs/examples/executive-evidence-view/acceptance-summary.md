# Acceptance summary — Executive Evidence View (issue #153)

**Overall status: INCOMPLETE.** Everything automatable has been prepared and
runs green. Every acceptance item that requires a real person — maintainer
approval, an independent practitioner, an independent technical reviewer, and
five representative nontechnical readers — is outstanding and is recorded as
outstanding. Issue #153 and epic #150 stay open until those items are done.

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
| JSON/Markdown semantic parity | Done | `…::test_json_and_markdown_stay_semantically_parallel` |
| Unknown-field name disclosure, value withholding, local-retention disclosure | Done | `…::test_unrecognized_fields_disclose_names_and_withhold_values` |
| Secret-canary exclusion and no identifying data in published artifacts | Done | `…::test_published_artifacts_carry_no_secret_or_identifying_values` |
| No external generation dependency (no service, account, telemetry, upload) | Done | `…::test_generation_needs_no_network` |
| Published sample commands and links match shipped behaviour | Done | `…::test_documented_export_commands_use_options_the_cli_accepts`, `…::test_readme_relative_links_resolve` |
| Clean install, packaging, outside-checkout operation | Done (pre-existing) | `tests/test_clean_install.py`, `tests/test_packaging_dependencies.py` |
| #151/#152 projection, export, CLI, evidence-store, clock-safety and legacy regressions preserved and rerun | Done (pre-existing) | `tests/test_executive_evidence.py`, `tests/test_executive_exports.py`, `tests/test_executive_serializer_clock_safety.py`, `tests/test_cli.py`, `tests/test_evidence_store.py`, `tests/test_reports.py` |
| AI-drafted protocol, questions, answer key, rubric, response form, templates | Drafted, **not approved** | [`comprehension-protocol.md`](comprehension-protocol.md), [`participant-response-form.md`](participant-response-form.md) |

Honest reporting of the automated run: at the time of writing the full suite
is green with two skips, both pre-existing and both in
`tests/test_release_artifacts.py`, which skip unless
`HARVESTGUARD_RUN_NETWORK_INSTALL_TESTS=1` enables networked install
validation. No test in this collection is skipped,
and none is environment-dependent beyond needing a Python interpreter, `pip`
and the repository.

Two distinct CLI levels are reported separately, because they prove different
things. The `…::test_cli_reproduces_each_sample…` tests run the documented
no-install entry point (`python -m harvestguard`) from outside the checkout
with the repository on `PYTHONPATH`; that is the no-install path, not an
installed release. The installed-package tests build a throwaway virtual
environment, `pip install --no-deps` the project into it non-editably, and then
regenerate the whole collection and rerun both export modes from outside the
checkout with `PYTHONPATH` removed — so the committed samples are established
as reproducible from an installed release, with no repository import override.
Dependency-metadata completeness is out of scope there (`--no-deps`,
`--system-site-packages`) and is covered by `tests/test_clean_install.py`
instead. A HarvestGuard version change makes the committed samples stale by
design, and the regeneration tests fail until they are regenerated.

## Category 2 — Independent technical-review evidence

| Item | Status |
| --- | --- |
| Independent traceability review of the immutable artifacts | **NOT PERFORMED** — see [`technical-traceability-review.md`](technical-traceability-review.md) |

## Category 3 — Real human-comprehension evidence and real human use

| Item | Status |
| --- | --- |
| Independent practitioner completes the published use path unaided | **NOT PERFORMED** — see [`independent-use-record.md`](independent-use-record.md) |
| Five real representative nontechnical participants | **NOT TESTED** — see [`comprehension-results.md`](comprehension-results.md) |
| ≥ 4 of 5 answer Q1–Q3 correctly within 30 seconds | **NOT ESTABLISHED** |
| No participant interprets VERIFIED in a prohibited way | **NOT ESTABLISHED** |

Independent use and comprehension are recorded separately, even if one person
is eligible for both. No tooling in this repository contacts, recruits,
invites, messages or schedules anyone.

## Category 4 — Maintainer decisions

| Decision | Status |
| --- | --- |
| Approve and freeze the evaluated artifact and its exact revision | **PENDING** |
| Approve and freeze the protocol, questions, answer key, rubric and timing method | **PENDING** |
| Approve the participant criteria; select and contact participants | **PENDING** |
| Resolve any ambiguous score; record overrides with reasons | **PENDING** (none to resolve yet) |
| Approve any corrective wording or layout change | **PENDING** (none proposed) |
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
