# Sanitized gate transcripts

Verbatim stdout and stderr of a real `validation/run-validation.sh` run, kept so
a reader can see the eight gates, the disclosures, and the raw stage 7 output
exactly as the operator saw them. A transcript is evidence of what the harness
printed; the reviewed summary of a run is its report in
[`../reports/`](../reports/).

Every transcript here is sanitized before it is committed. The substitutions are
mechanical and lossless apart from the elisions:

| Original | Replacement |
| --- | --- |
| the validation workspace path | `<workspace>` |
| the repository checkout path | `<checkout>` |
| the operator's home and its subdirectories | `<home>`, `<venv-bin>`, `<operator-inputs>`, `<operator-scratch>` |
| the operator's account name | `<operator>` |
| the run ID | `<run-id>` |
| any 64-character hex digest | `<sha256-elided>` |

Per-file SHA-256 digests are elided because a transcript is not an archived
manifest and must carry no digest of generated key material. Passphrases never
reach a transcript in the first place: the harness redacts secret command
arguments, and generated passphrases carry the per-run marker so stage 8 can
prove no secret leaked into an output file.

Never add a transcript that contains a private-key body, a plaintext, a decrypted
artifact, or a raw secret value. Never add corpus or scratch material.

| Transcript | Run |
| --- | --- |
| [`2026-08-18-almalinux-9.8-phase1.txt`](2026-08-18-almalinux-9.8-phase1.txt) | AlmaLinux 9.8, complete eight-gate run ([report](../reports/2026-08-18-almalinux-9.8-phase1.md)) |
| [`2026-08-18-almalinux-9.8-phase1-halted-run.txt`](2026-08-18-almalinux-9.8-phase1-halted-run.txt) | AlmaLinux 9.8, earlier run halted inside stage 7 by the pandas 3.x defect described in the same report |

The curated [validation examples index](../examples/README.md) explains how to
read these transcripts alongside the Ubuntu and AlmaLinux reports. No transcript
is committed for the Ubuntu run.
