# Executive Evidence View — reproducible examples and acceptance materials

This directory holds two things and nothing else:

1. **Reproducible examples** of the [Executive Evidence
   View](../../EXECUTIVE_EVIDENCE_VIEW.md), generated through the real
   HarvestGuard path, one sample per required evaluation outcome.
2. **Acceptance materials** for GitHub issue #153 — the frozen-protocol drafts,
   templates and result records that prove (or, where a required human step has
   not happened yet, explicitly do *not* yet prove) that this output is
   independently usable, exactly traceable and understandable.

It adds no reporting path. Every sample comes from the already-shipped
projection and serializers described in
[EXECUTIVE_EVIDENCE_VIEW.md](../../EXECUTIVE_EVIDENCE_VIEW.md) and driven by
`harvestguard evidence export` ([CLI.md](../../CLI.md#executive-evidence-exports)).
Terms used below are defined once in
[TERMINOLOGY.md](../../TERMINOLOGY.md) and are not redefined here.

## All evidence here is synthetic

Every fixture is **purpose-built synthetic evidence**, labelled as such in its
scan ID (`synthetic-…`), its target path (`/synthetic/example-target`) and its
recorded scope constraints — so the label survives into both generated formats,
not just into this README.

- No production, customer, personal or confidential data.
- No real or production-shaped credentials, secrets, keys or ciphertext.
- Nothing here is evidence about any real environment, and no sample may be
  read as a finding about one.

Historical gaps (an unreadable scan time, an unsupported collection contract or
finding schema) are modelled as purpose-built synthetic runs that *declare*
those gaps in their own stored evidence. No historical record is rewritten, and
no missing provenance is manufactured to make a sample look complete.

**Treat generated artifacts as sensitive.** The samples here are safe because
their inputs are synthetic. An executive export of *your* evidence carries the
same already-retained metadata your evidence database does — paths, object
names, certificate metadata, bounded diagnostics — so store and share it with
the same care as the database (see
[CLI.md](../../CLI.md#the-database-is-a-sensitive-evidence-artifact)). The
generated evidence database for these examples is deliberately **not
committed**.

## The path every sample came through

    labelled synthetic fixture
      → real evidence store (evidence_store.store_scan_run)
      → verified load (evidence_store.load_scan_run)
      → one shared projection (executive_evidence.build_executive_evidence_view)
      → both serializers (executive_reports.executive_json /
        format_executive_markdown)

Those are the modules an install ships, and when HarvestGuard is installed the
generator imports them from the installed distribution rather than from this
checkout. `tests/test_executive_evidence_examples.py` regenerates the whole
collection that way — from a non-editable `pip install .`, run outside the
checkout, with no repository import override — and requires the committed
bytes; it then reruns both export modes through the shipped `harvestguard`
console script. From a bare checkout, before any install, the generator falls
back to the repository root so it still runs.

## Regenerating everything

```bash
python docs/examples/executive-evidence-view/generate_examples.py
```

That rewrites `samples/` and `manifest.json` byte-for-byte; the evidence
database is built in a temporary directory and discarded. To keep the database
and drive the real CLI against it yourself — `--work-dir` has to be a new or
empty directory, because the generator never deletes or overwrites an existing
evidence database:

```bash
python docs/examples/executive-evidence-view/generate_examples.py --work-dir ./eev-work
harvestguard evidence list --evidence-db ./eev-work/example-evidence.sqlite
harvestguard evidence export synthetic-verified-001 \
    --evidence-db ./eev-work/example-evidence.sqlite --executive-json -
harvestguard evidence export synthetic-verified-001 \
    --evidence-db ./eev-work/example-evidence.sqlite --executive-markdown ./verified.md
```

`manifest.json` records, per scenario: the exact export commands, the producing
and exporting HarvestGuard versions, the executive schema and policy versions,
the normalized-finding and evidence-store schema versions, the declared scope,
the selected scanners and their versions, the recorded scan time and the
explicit export time, the collection provenance, the stored evidence digest,
and the size and SHA-256 of each committed artifact.

### Why the samples use an explicit export time

The CLI reads its own UTC clock for the export time and has **no public
override** — that is deliberate, and #153 does not change it. Committed samples
still have to be byte-stable, so the generator passes one explicit fixed
`export_time` (`2026-01-15T00:00:00+00:00`) to the same installed projection
API the CLI calls. A live CLI export of the same fixture therefore differs from
the committed sample **only** in that one value.
`tests/test_executive_evidence_examples.py` proves exactly that: it runs both
real CLI export modes — as the documented no-install `python -m harvestguard`
path *and* as the console script from a non-editable install outside the
checkout — and compares the remaining content.

## The samples

| Sample | Evidence evaluation | What it demonstrates |
| --- | --- | --- |
| [`verified`](samples/verified.md) ([JSON](samples/verified.json)) | VERIFIED | Every required check passed, no defined exception. |
| [`verified-zero-findings`](samples/verified-zero-findings.md) ([JSON](samples/verified-zero-findings.json)) | VERIFIED | A legitimate zero-finding run: a valid empty result, distinguished from output that was never produced. |
| [`warning-optional-provenance`](samples/warning-optional-provenance.md) ([JSON](samples/warning-optional-provenance.json)) | WARNING | Required checks passed, but one occurrence omits optional collection provenance — a specifically defined exception naming that occurrence. |
| [`incomplete-partial-execution`](samples/incomplete-partial-execution.md) ([JSON](samples/incomplete-partial-execution.json)) | INCOMPLETE | Matching integrity *and* incomplete execution: partial findings retained alongside a recorded scanner failure. Integrity passing does not make execution complete. |
| [`incomplete-unknown-scan-time`](samples/incomplete-unknown-scan-time.md) ([JSON](samples/incomplete-unknown-scan-time.json)) | INCOMPLETE | A missing/invalid historical scan time: time-based derivations are unknown, and no collection time is invented. |
| [`incomplete-unsupported-history`](samples/incomplete-unsupported-history.md) ([JSON](samples/incomplete-unsupported-history.json)) | INCOMPLETE | An unsupported historical collection contract and an unrecognized finding schema version. The evidence stays retained and referenced; neither gap becomes VERIFIED. |
| [`failed-reference-consistency`](samples/failed-reference-consistency.md) ([JSON](samples/failed-reference-consistency.json)) | FAILED | A required check completed and failed: a stored snapshot names a different scan than the run holding it. |
| [`duplicate-finding-ids`](samples/duplicate-finding-ids.md) ([JSON](samples/duplicate-finding-ids.json)) | VERIFIED | Two occurrences share one finding ID and stay separately referenced by ordinal. |
| [`failed-integrity-corruption`](samples/failed-integrity-corruption.stderr.txt) | *not evaluated — evidence rejected* | A snapshot modified after storage without re-digesting: the existing loader rejects the run, both export modes exit `1` with a bounded diagnostic, and **no** evidence report is produced. |

The corruption example is produced against a **disposable copy** of the
synthetic fixture database; the original fixture is untouched, and no normal
report is ever constructed from rejected evidence.

## Reading one of these samples

Both formats carry the same assertions, check results, counts, references,
exceptions and conclusions. To go from a statement to its evidence:

1. Read **Evidence evaluation: …** and the *Why this evaluation* reasons; each
   reason names the checks or exceptions it rests on (`EV-CHK-…`, `EV-EXC-…`).
2. Read the named check under **Evidence checks and limitations** for its
   state, result, method and limitation.
3. Follow the check's or exception's evidence reference — *this run's scan ID
   plus ordinal plus finding ID* — into **Technical evidence detail**, where
   every retained occurrence is listed separately. In JSON the same reference
   appears as an `evidence[]` item with the same `ordinal` and `finding_id`.
4. Where an occurrence carries a field the exporting version does not
   recognize, the sample discloses the **field name** and withholds the value;
   the value stays in the local verified store under the existing digest. The
   withheld names and that disclosure are identical in both formats.

## Acceptance materials (issue #153)

Acceptance evidence is kept in four clearly separated categories. **Automated
and AI-produced evidence cannot substitute for the human categories**, and the
files below state plainly which requirements are still outstanding.

| Category | Where | Status |
| --- | --- | --- |
| 1. Automated and AI-produced evidence | [`acceptance-summary.md`](acceptance-summary.md), `samples/`, `manifest.json`, `tests/test_executive_evidence_examples.py` | Recorded there |
| 2. Independent technical-review evidence | [`technical-traceability-review.md`](technical-traceability-review.md) | Awaiting an independent reviewer |
| 3. Real human-comprehension evidence | [`comprehension-protocol.md`](comprehension-protocol.md), participant sheets in [`participant/`](participant/) (with the evaluated artifact, the only material a participant ever sees), [`facilitator-record-sheet.md`](facilitator-record-sheet.md) (facilitator and scorer only), [`comprehension-results.md`](comprehension-results.md), [`independent-use-record.md`](independent-use-record.md) | Awaiting maintainer approval, then real participants |
| 4. Maintainer decisions | [`acceptance-summary.md`](acceptance-summary.md) | Awaiting the maintainer |

No participant is contacted, recruited, invited, messaged or scheduled by any
tooling in this repository. Participant selection and contact are the
maintainer's responsibility, and the protocol, questions, answer key, rubric,
timing method and evaluated artifact must be approved and frozen *before*
anyone is tested.

This directory contains no participant names, contact details, employers,
demographics or raw recordings, and must never contain them.
