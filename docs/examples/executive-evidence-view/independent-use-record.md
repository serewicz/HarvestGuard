# Independent-use record (issue #153)

**Category 3 evidence: real human use.** Recorded separately from the
comprehension exercise, even if one person is eligible for both.

**Status: NO PRACTITIONER HAS COMPLETED THE EXERCISE. This acceptance item is
INCOMPLETE.**

An independent-use attempt must never be fabricated. If no suitable
practitioner is available, this item simply stays incomplete.

## What the practitioner must be able to do, unaided

A practitioner **independent of the #152 implementation**, working only from
the published instructions ([README](../../../README.md),
[docs/CLI.md](../../CLI.md),
[docs/EXECUTIVE_EVIDENCE_VIEW.md](../../EXECUTIVE_EVIDENCE_VIEW.md)) and
without consulting help or reading the source, completes all of:

1. install HarvestGuard using the published instructions;
2. create or use a local evidence store;
3. generate executive JSON;
4. generate executive Markdown;
5. identify the evaluation status and its stated limits;
6. navigate from a substantive statement to its exact evidence occurrence, or
   to the named check or derivation behind it;
7. state the artifact-sensitivity guidance in their own words.

No dashboard, paid product, consulting engagement, hosted service, proprietary
account, telemetry, external AI service or report upload may be required at
any step.

## Automated groundwork (category 1, not a substitute)

Automated checks establish as much of this path as machines can. They do
**not** prove human independent use.

| Check | Where |
| --- | --- |
| Clean installation of the packaged CLI | `tests/test_clean_install.py` |
| Operation from outside the checkout, no repository on `sys.path` | `tests/test_clean_install.py`, `tests/test_executive_evidence_examples.py` |
| No external generation dependency (no network, service or account) | `tests/test_executive_exports.py`, `tests/test_executive_evidence_examples.py` |
| Packaging declares every module the export path imports | `tests/test_packaging_dependencies.py` |
| Both CLI export modes over a stored run, end to end | `tests/test_executive_evidence_examples.py` |
| Documented sample commands match shipped behaviour | `tests/test_executive_evidence_examples.py` |

## Record (to be completed by the maintainer)

| Field | Value |
| --- | --- |
| Anonymized practitioner ID | `IU-01` |
| Independent of the #152 implementation | *(not established)* |
| Relevant technical background | |
| Exact artifact and HarvestGuard version | |
| Environment (OS, Python version, install method) | |
| Commands followed (verbatim) | |
| Were the published instructions sufficient? | |
| Obstacles and mistakes | |
| Was help requested? (any help request means the unaided criterion is not met) | |
| Final result | |
| Elapsed time (if useful) | |
| Documentation correction required | none / what |
| Also participated in the comprehension exercise? | no / yes — recorded separately in `comprehension-results.md` |
