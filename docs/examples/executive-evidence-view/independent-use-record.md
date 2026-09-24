# Independent-use record (issue #153)

**Category 3 evidence: real human use.** Recorded separately from the
comprehension exercise. The practitioner must not also be a five-reader
participant in this acceptance round.

**Status: NO PRACTITIONER HAS COMPLETED THE EXERCISE. This acceptance item is
INCOMPLETE.**

An independent-use attempt must never be fabricated. If no suitable
practitioner is available, this item simply stays incomplete.

## What the practitioner must be able to do, unaided

The practitioner did not implement **either #152 or #153**, has not been
coached through this workflow, and is not one of the five readers. Establish
and record these criteria before starting. Tim approves the packet before use.

### Exact handoff packet (pending Tim's freeze approval)

- Source: the immutable corrected PR #160 revision containing this package.
  Tim's written freeze approval must name its full Git commit SHA; provide a
  checkout/archive of that exact SHA, never a moving branch or a different
  PyPI release. Record it below before the attempt. This documentation-only
  revision retains the implementation reviewed at
  `c934e63c8c3c0d0b7150301e1942b7e76d0439b8`.
- Permitted instructions from that same revision: repository
  [README.md](../../../README.md), [docs/CLI.md](../../CLI.md),
  [docs/EXECUTIVE_EVIDENCE_VIEW.md](../../EXECUTIVE_EVIDENCE_VIEW.md), and this
  collection's [README.md](README.md). Supply those published documents and
  the source package for installation and executing the helper; no facilitator
  source-code explanations or coaching. Do not provide answer-key/scoring
  materials as practitioner instructions.
- Approved input: `synthetic-verified-001` in the local store created with the
  published `generate_examples.py --work-dir ./eev-work` workflow. Follow the
  collection README's installed CLI commands for both executive formats.
- Installation: use the published source-install instructions against the
  supplied exact revision (including its declared dependencies), then the
  published helper/workflow. Record the resolved SHA, product version,
  environment and commands. Installation may require a package source;
  runtime evidence generation remains local and offline-capable.

Complete the seven tasks below using only the permitted published instructions,
without consulting help or source-code knowledge. **Any help request means the
unaided criterion is not met for that attempt.** Retain failed attempts,
obstacles, mistakes and help requests; append reruns, never replace evidence.
There is **no practitioner time limit**; elapsed time may be recorded if useful.

1. install HarvestGuard from the approved exact source revision using the published instructions;
2. create/use the approved local synthetic store and `synthetic-verified-001`;
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
| Independent of both #152 and #153 implementation | *(not established)* |
| No prior coaching through this workflow | *(not established)* |
| Tim's packet approval / exact corrected source Git SHA | *(pending)* |
| Reviewed implementation ancestor | `c934e63c8c3c0d0b7150301e1942b7e76d0439b8` |
| Approved input and permitted document revisions | *(not yet handed over)* |
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
| Excluded from the five-reader cohort | must be confirmed before starting |
