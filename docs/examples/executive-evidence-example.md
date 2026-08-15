# Executive-readable evidence example

One finding from the committed [first-run sample output](first-run/) written the
way it could be presented to an executive reader — with the evidence, any
scanner inference, the human business interpretation, and the human action
request kept in four visibly separate layers.

**This is fictional sample material.** The scanned input is the repository's
synthetic [demo corpus](../../demo/sample_target/README.md), where every file is
fake by construction; the diligence scenario in the *Business interpretation*
layer below is likewise invented for this example and is attributed as such
where it appears. No real company, system, certificate, key, or sensitive value
is described here, and nothing here is a risk score, compliance result,
readiness determination, or remediation recommendation from HarvestGuard.

The finding used is the `PEM Certificate` record in
[`sample-findings.json`](first-run/sample-findings.json) (finding id
`487b32de02b9c6c99c5c504604848195346df5a7c2e33e511bc1baf1a8519fff`), which also
appears as the *PEM Certificate* row under *Detailed Findings* in
[`sample-report.md`](first-run/sample-report.md).

---

## Layer 1 — Observed fact

Everything in this layer is copied from the committed sample record. It answers
the first three reader questions.

**What was found?** A PEM-encoded X.509 certificate that the scanner parsed
successfully. HarvestGuard recorded it as asset type `PEM Certificate` with
observed evidence `PEM Certificate parsed successfully` at confidence `High`.

**Where was it found?** At `demo/sample_target/crypto/demo_tls_certificate.pem`
— a path inside the scanned target, recorded as the finding's `location`.

**How was it found?** The `crypto_inventory` scanner (version `0.1.0`) read the
file during a scan of `demo/sample_target` and parsed the certificate structure
out of its content. The command that produced this record is documented in the
[sample provenance table](first-run/README.md#provenance).

| Field (as recorded) | Value |
| --- | --- |
| `location` | `demo/sample_target/crypto/demo_tls_certificate.pem` |
| `asset_type` | `PEM Certificate` |
| `evidence` | `PEM Certificate parsed successfully` |
| `confidence` | `High` |
| `scanner_name` / `scanner_version` | `crypto_inventory` / `0.1.0` |
| `rule_id` | `null` (this record carries no rule id) |
| `technical_metadata.Algorithm` | `RSA` |
| `technical_metadata.Key Size` | `2048` |
| `technical_metadata.Signature Algorithm` | `sha256` |
| `technical_metadata.Expiration` | `2126-07-22T03:50:24+00:00` |
| `technical_metadata.Issuer` | `OU=Do Not Use,O=HarvestGuard Synthetic Demo Material,CN=demo.harvestguard.invalid` |
| `technical_metadata.Subject` | `OU=Do Not Use,O=HarvestGuard Synthetic Demo Material,CN=demo.harvestguard.invalid` |
| `technical_metadata.Fingerprint` | `fec3e00862dd82b4cde8e36c0c6703acb64945db7d4957e36e58418cb634f5cf` |
| `unknowns` / `limitations` / `errors` | empty on this record |
| `schema_version` | `1.0.0` |

**What `High` confidence means here:** the certificate was fully parsed and its
properties read directly out of the file, so the observation itself is reliable.
Confidence describes evidence quality only — never business severity, exposure,
or urgency ([TERMINOLOGY.md](../TERMINOLOGY.md#evidence-layer-terms)).

**Limitations that still apply.** This record's own `limitations` list is empty,
which is not a statement that nothing limits it. The scan-level limitations in
[`sample-report.md`](first-run/sample-report.md) still hold: findings are
observed evidence rather than business conclusions, each scanner's detection
surface is deliberately narrow
([DETECTION_CHARACTERIZATION.md](../DETECTION_CHARACTERIZATION.md)), and absence
of a finding is not proof of absence. The scan also observed the file on disk
only; it did not observe any system using it.

## Layer 2 — Scanner inference

**None.**

HarvestGuard produced no inference for this finding. The evidence layer that
emits these records carries no exposure state, risk score, HNDL bucket,
priority, or ownership conclusion, so there is nothing in this layer to report
and nothing is invented to fill it. The certificate's fields above are read
values, not derived ones.

## Layer 3 — Business interpretation *(human reviewer — not HarvestGuard)*

*The scenario in this layer is invented for this example: treat the demo corpus
as a repository handed over during a fictional diligence review. The reasoning
below is a reviewer's, written conditionally, and is not produced by the
scanner.*

**Why might it matter?** A reviewer might note that *if* a certificate with this
profile were confirmed to be in real use somewhere, its recorded key size
(`2048`), signature algorithm (`sha256`), and validity window (an expiration in
`2126`, roughly a century out) would be relevant inputs to a conversation about
certificate lifecycle practice and future cryptographic migration planning. A
reviewer might also note that the issuer and subject are identical, which is
what a self-signed certificate looks like, and that a certificate file sitting
in a repository says nothing on its own about where — or whether — it is
deployed.

Each of those is conditional on facts this scan did not establish. HarvestGuard
observed a file and its parsed fields; it did not observe deployment, runtime
use, trust configuration, ownership, or business importance, and this example
asserts no impact, no exposure, and no compliance or readiness conclusion.

## Layer 4 — Recommended human action *(human reviewer — not HarvestGuard)*

**What should happen next?** Bounded verification and context gathering by
qualified people, to convert the conditionals above into answered questions:

1. Ask the system owners whether this certificate file corresponds to anything
   deployed, and if so where — the scan cannot answer this.
2. Confirm whether the matching private key exists anywhere in scope; this scan
   observed the certificate only, and the corpus manifest records that no
   counterpart key was committed.
3. Confirm how certificates of this kind are issued and rotated, given that the
   observed issuer and subject match and the observed validity window is long.
4. Re-run or widen the scan if the reviewer needs coverage this one did not
   have, since the detection surface is narrow by design.

These are follow-up requests for people, not actions HarvestGuard takes or
recommends. Any decision that follows belongs to qualified reviewers with the
business, contractual, and operational context the scanner cannot observe.

---

## Traceability

| Layer | Source |
| --- | --- |
| Observed fact | [`sample-findings.json`](first-run/sample-findings.json), [`sample-report.md`](first-run/sample-report.md), [demo corpus manifest](../../demo/sample_target/README.md) |
| Scanner inference | None produced; see [TERMINOLOGY.md](../TERMINOLOGY.md#inference-and-assessment-layer-terms) for what would have to be labeled if any were |
| Business interpretation | Human reviewer, in the fictional scenario stated in that layer |
| Recommended human action | Human reviewer |

Only the first row comes from HarvestGuard. Layers 3 and 4 are attributed
human work and are separated here so a reader can never mistake them for
scanner output; see
[PRODUCT_PRINCIPLES.md](../PRODUCT_PRINCIPLES.md) and
[ADR-005: Evidence versus inference](../DECISIONS/ADR-005-evidence-versus-inference.md).
