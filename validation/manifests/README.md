# Archived validation runs

One row per archived run of `validation/run-validation.sh`. Archive only these
three files per run, copied out of the workspace after stage 8:

- `<prefix>-manifest.json` — the frozen manifest (`state/manifest.json`)
- `<prefix>-result.json` — the comparison report (`results/validation-report.json`)
- `<prefix>-report.md` — the human-readable report (`results/validation-report.md`)

Never archive `<workspace>/corpus` or `<workspace>/scratch`: they hold generated
key material. The three files above are safe by construction — the manifest and
report contracts forbid passphrases, private-key contents, plaintext, decrypted
material, and raw secret values.

| Run | OS / arch | HarvestGuard | Tool versions | FIPS | Discrepancies | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| _(none archived yet)_ | | | | | | |

The reference observation from the repository CI host is summarized in
[`../README.md`](../README.md) rather than archived here, because it was not run
on RHEL or CentOS Stream. The first RHEL or CentOS Stream archive is an operator
task; see [`../environments/rhel.md`](../environments/rhel.md).
