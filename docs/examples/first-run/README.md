# First-run sample output

Real HarvestGuard output, committed so a prospective user can see the shape of
the evidence — and the boundaries of what it claims — before installing
anything or pointing a scanner at their own data.

| File | What it is |
| --- | --- |
| [`sample-findings.json`](sample-findings.json) | The `--json` artifact: the normalized finding array documented in [NORMALIZED_FINDINGS.md](../../NORMALIZED_FINDINGS.md). |
| [`sample-report.md`](sample-report.md) | The `--markdown` artifact: the evidence report, including its *Known Limitations* section. |
| [`generate_samples.py`](generate_samples.py) | The script that regenerates both files from the commands below. |

**These are illustrative sample evidence output.** They are not a
certification, an assessment, a benchmark, a risk score, a remediation plan, or
a statement of exhaustive coverage, and they are not the record of a scan of
any real system. They show what a scan of one deliberately small synthetic
fixture produced — nothing more.

## Provenance

| Field | Value |
| --- | --- |
| Input | [`demo/sample_target/`](../../../demo/sample_target/README.md) — the repository's synthetic demo corpus (4 files) |
| Command (JSON) | `harvestguard scan demo/sample_target --type all --quiet --json sample-findings.json` |
| Command (Markdown) | `harvestguard scan demo/sample_target --type all --quiet --markdown sample-report.md` |
| Working directory | the repository root |
| Generating version | `harvestguard 0.3.0` (what `harvestguard --version` prints, and what the report's *Scan Information* table records) |
| Repository state | regenerated on the `v0.3.0` release-preparation change, which changes release identity, samples, documentation, and tests — no scanner, report-generator, schema, or evidence-store behavior was changed to produce them |
| Credentials / network | none required; the demo corpus is local and offline |

`--json` and `--markdown` are mutually exclusive on the CLI, so the two
artifacts come from two runs of the same scan. Both commands are the ones
documented in the [CLI demo walkthrough](../../CLI.md#demo-walkthrough).

To regenerate, from the repository root:

```bash
python docs/examples/first-run/generate_samples.py
```

The script runs the same CLI (as `python -m harvestguard`, so no install is
required) into a temporary file, applies the normalization below, and writes
the two files here. Running the commands in the table yourself produces the
same artifacts with your own scan id, timestamps, duration, and path.

## Normalization applied

Nothing in either file is hand-authored, and no finding was rewritten,
reordered, or removed. The generation step replaces exactly these *volatile*
values — a per-run identifier, collection timestamps, a wall-clock duration,
and this checkout's absolute path — so that regenerating the samples does not
churn the committed files and so that no user-specific path is published:

| Value | Replaced with | Why it is volatile |
| --- | --- | --- |
| `scan_id` (JSON), `Scan ID` (Markdown) | `00000000-0000-0000-0000-000000000000` | A fresh UUID per scan. |
| `observed_at`, `provenance.collected_at` (JSON), `Scan Time` and every `Observed At` cell (Markdown) | `1970-01-01T00:00:00+00:00` | When the sample scan ran. |
| `technical_metadata.Modified` on the sensitive-data finding (JSON) | `1970-01-01T00:00:00+00:00` | The demo file's modification time, which git does not preserve across checkouts. |
| `Duration` (Markdown) | `0.00 seconds` | Wall-clock time on the generating machine. |
| The absolute checkout path inside `collection_source` / `provenance.source` | `<checkout>` | Machine-specific, and a real user's path would be user-specific data. |

Apart from those substitutions the files are byte-for-byte what the CLI wrote:
the JSON keeps the emitter's own key order and 2-space indentation, and the
Markdown keeps every section the report generator produced, in order.

Every other value is exactly what the scanners reported — including the parsed
certificate `Expiration` (`2126-07-22T…`), which is evidence about the fixture
and is deliberately *not* normalized.

## What varies by host

One record in each sample is host-dependent and was **retained truthfully**
rather than normalized: the aggregate `filesystem_context` record for the mount
the demo corpus sits on. **These samples were generated on Linux**, where the
platform reported the volume as `Unencrypted` at confidence `Medium`
(`rule_id: volume_status:unencrypted`, `Mount Point: /`). On another supported
host — macOS with FileVault, for example, or a machine where the status cannot
be determined at all — that one record's evidence text, value, confidence, and
rule id legitimately differ. This is documented behavior, not a defect; see
[CLI.md § What varies by host](../../CLI.md#what-varies-by-host). Everything
else in both samples depends only on the fixture's fixed content.

On a supported macOS host in particular, volume-level encryption status can
come back `Unknown` rather than a concrete `Encrypted`/`Unencrypted` value.
When that happens, the aggregate context finding also gains a recorded
limitation, and that single fact deterministically changes several places in
the *Markdown* report beyond the one record above:

- the `Coverage` field in *Scan Information* reads `Not complete` instead of
  `Bounded by configured scan scope`;
- a `Coverage was not complete: …` paragraph appears before *Scan Information*;
- *Errors and Warnings* gains a `finding(s) record limitations…` bullet and a
  nested `` `volume_status:unknown` `` count line.

None of this is a fixture or detector regression — it is the report generator
truthfully describing what that host observed. It is also why the committed
Markdown sample here is not asserted byte-for-byte against a freshly generated
one: `tests/test_first_run_samples.py`'s regeneration check normalizes away
exactly this cluster of host-dependent text (the aggregate record's own row,
the `Coverage` field, the paragraph, and the limitation bullets) before
comparing, so the same demo scan reproduces the same *stable* evidence and
report structure on every supported platform, without hiding or asserting
away the platform-dependent text itself, and without ever claiming the two are
identical. See that test's `_host_independent_lines` for the exact, named list
of what is excluded and why.

## Privacy and evidence boundaries

- Nothing scanned here is real. Every input is synthetic material generated or
  hand-written for this repository and documented in the
  [demo corpus manifest](../../../demo/sample_target/README.md).
- The samples contain no secret values, no private-key material, and no
  passphrase — by design, not by redaction. Sensitive-data findings report
  category names and counts only, and an encrypted key is reported as present
  and encrypted, never opened.
- The five records here come from three scanners against four files. Two
  supported cryptographic asset categories appear; HarvestGuard supports more
  (see [SCAN_COVERAGE.md](../../SCAN_COVERAGE.md)). **Absence of a finding is
  not proof of absence** — each scanner's detection surface is deliberately
  narrow and is enumerated in
  [DETECTION_CHARACTERIZATION.md](../../DETECTION_CHARACTERIZATION.md).
- Everything in both files is observed evidence. Neither artifact contains a
  risk score, HNDL exposure rating, business interpretation, compliance or
  readiness conclusion, or remediation recommendation; see
  [TERMINOLOGY.md](../../TERMINOLOGY.md) for how HarvestGuard separates
  observed evidence from inferred fields.

`tests/test_first_run_samples.py` regenerates both artifacts and checks that
the committed files still parse, still match the host-independent portions of
live output, and still carry none of the above.
