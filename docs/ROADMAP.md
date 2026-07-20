# HarvestGuard Roadmap

This roadmap orients the project around its actual buyer: M&A, PE/VC, and law
firm teams doing technical due diligence, who need fast, trustworthy visibility
into a target company's data risk — and who often don't know what "good"
looks like yet. The open-source scanner is the diagnostic; it should be good
enough, and trustworthy enough, to stand on its own, while naturally
surfacing where a paid engagement (remediation planning, ongoing monitoring)
adds value.

Two things follow from that:

- **Coverage must span crypto posture *and* sensitive-data discovery.**
  Buyers ask "where is the customer data and is it protected?" — not just
  "is encryption strong?" Scope has been broadened accordingly (see Pillar 1).
- **The container story is the trust story.** This audience is handling
  someone else's confidential data on day one of a deal. "Runs locally in a
  container, never phones home, never persists what it scans" is not a
  packaging detail — it's the reason they're allowed to run this at all.

Current state (as of this writing): local filesystem, AWS S3, GCS, and Azure
Blob scanning all do real encryption-status detection; the PII/secrets
classifier and a Semgrep-based crypto code analysis scanner each ship as
their own scan type. Pillar 2 (containers) is done except the k8s manifest —
signed, keylessly-attested images with an SBOM ship from CI. No CBOM/PDF
export yet, no network-level crypto detection (TLS/cipher-suite scanning).

---

## Quantum risk taxonomy

Due-diligence quantum risk breaks down into seven categories, roughly ordered
by immediacy and financial impact. This is the taxonomy the rest of the
roadmap is organized around — each row says where that risk lives, or why it
deliberately doesn't live in the engineering backlog at all.

1. **Harvest Now, Decrypt Later (HNDL)** — done. Pillar 1's encryption
   detection + HNDL exposure scoring.
2. **Cryptographic inventory blind spots** — partially done. Pillar 1's
   "Future scan surfaces" section covers this; code & binary crypto usage
   analysis now ships (`code_analysis/`), network/cipher detection doesn't
   yet — most companies have no map of what algorithms/key
   lengths/libraries they're running, which is exactly what this section
   targets.
3. **PQC migration debt / crypto-agility** — the code/binary analysis
   prerequisite now exists, but assessing crypto-agility itself (can a
   system swap algorithms without a rewrite) remains unsolved — no clear
   detection approach yet beyond "does the code use a crypto-agility
   abstraction," itself a further code-analysis question. See the Quantum
   Risk Engine section below.
4. **Data ownership & classification gaps** — primarily an advisory/services
   deliverable, not a tool feature. See "Advisory backlog" below.
5. **Supply chain & third-party exposure (incl. shadow AI)** — explicitly out
   of scope for now; see bottom of this doc.
6. **Valuation & integration impact** — Pillar 3's dollarized-risk and
   partner-ready-summary items. Related existing work:
   [technology-leadership-portfolio](https://github.com/serewicz/technology-leadership-portfolio).
7. **Talent & governance gaps** — not scannable; advisory-only, with one
   small tool-buildable nicety (see "Advisory backlog" below).

---

## Pillar 1 — Scanning engine: coverage

- [x] **Real local encryption detection** (`scanner/filesystem.py`) — file
      signature checks for common encrypted formats (OpenSSL, PGP/GPG, age,
      LUKS containers, encrypted ZIP), falling back to volume-level status
      (FileVault / LUKS / BitLocker) per scan root. Replaces the `"Unknown"`
      placeholder. Next: expand signature coverage (encrypted Office/PDF,
      VeraCrypt) and add APFS/dm-crypt detail beyond the on/off check.
- [x] **Sensitive-data classification module** (`classifier/` package) —
      regex-based detection for email, SSN, phone, payment card (Luhn-
      validated), and secrets/credentials (AWS keys, private keys, GitHub/
      Slack tokens, generic assignment-style secrets). Findings report
      category + count only, never the matched values, so scan results
      can't themselves leak the sensitive data they found. Wired into the
      dashboard as its own scan type. Next: expand beyond regex (NER for
      names/addresses), tune false-positive rate on real-world corpora.
- [x] **GCS scanner** (`scanner/gcs.py`) — per-blob encryption status via
      the GCS API: CMEK (Low risk) vs. Google-managed default (Medium risk).
      GCS encrypts everything at rest, so unlike S3 there's no "unencrypted"
      state to detect -- the signal is customer key control vs. platform
      default. Auth failures (`DefaultCredentialsError`, raised eagerly by
      `storage.Client()` construction) are caught explicitly -- this was
      found live, not in review: an early version only caught
      `GoogleAPIError` and crashed the whole Streamlit app on missing
      credentials, since `DefaultCredentialsError` comes from `google.auth`,
      a separate exception hierarchy.
- [x] **Azure Blob scanner** (`scanner/azure_blob.py`, named to avoid
      shadowing the `azure` package) — per-blob encryption status via the
      Azure SDK: customer-managed encryption scope (Low risk) vs.
      Microsoft-managed default (Medium risk), same rationale as GCS. Uses
      `DefaultAzureCredential` for auth, consistent with AWS/GCP's automatic
      credential-chain resolution.
- [ ] **Common `ScanResult` interface** — normalize local/AWS/GCP/Azure/
      classifier output into one schema so the analyzer, dashboard, and
      exporters don't special-case each source. Deliberately deferred until
      a second cloud backend existed, to avoid speculative abstraction —
      that condition is now met (S3 + GCS + Azure all ship). Ready to pick
      up.

### Quantum Risk Engine (`analyzer/risk.py`)

Today `analyzer/risk.py` is a simple heuristic (base score + fixed
adjustments). Formalizing it into a real rules engine is risk #3 above and
depends on the code/binary analysis work landing first:

- [ ] **Algorithm/key-length vulnerability check** — flag known-vulnerable
      algorithms and key sizes (RSA/ECC under safe thresholds) explicitly,
      rather than only inferring HNDL risk from encryption presence/absence
      as today. Depends on the "Code & binary analysis" item below for its
      input signal.
- [ ] **HNDL lifetime modeling** — Mosca inequality-style calculation (data
      lifetime vs. quantum timeline) to turn "this is at risk" into "this is
      at risk starting in ~N years." This is the project's namesake and
      currently the least literally-implemented part of the roadmap.
- [ ] **Hybrid PQC-readiness checks** — once a library like `liboqs` is
      integrated as a reference. Crypto-agility assessment itself (can this
      system swap algorithms without a rewrite) is a genuinely hard,
      not-yet-solved problem here — no clear detection approach exists yet
      beyond "does the code use a crypto-agility layer/abstraction," which
      is itself a code-analysis question.
- Note: a "migration effort estimator" was also proposed for this layer, but
  that's the same thing as Pillar 3's **Dollarized risk output** below —
  intentionally not duplicated as a separate item.

### Future scan surfaces — tooling landscape

Most of Pillar 1 above covers data at rest (filesystem, object storage).
Matching market-quality crypto/data-safety tooling means also covering data
in transit and crypto usage in code — and, for all of these, leaning on
proven OSS tools rather than re-implementing detection logic from scratch.
This section is risk #2 above (cryptographic inventory blind spots); code &
binary analysis is now done, network/cipher detection is the remaining gap
and the natural next pick.

- [ ] **Network traffic / cipher detection** (data in transit — nothing
      today covers this). Candidates: **Zeek** (best-in-class OSS network
      analyzer — cipher suites, TLS versions, certs, straight from a pcap
      or live capture), **sslyze** (fast, scriptable TLS config scanner),
      **testssl.sh** (comprehensive TLS/SSL test script), **nmap**
      (`--script ssl-enum-ciphers` for a quick enumeration pass).
- [x] **Code & binary analysis** (`code_analysis/` package) — crypto
      *library usage* in source, a different axis from `classifier/`'s
      content-pattern matching, and the prerequisite for the Quantum Risk
      Engine's algorithm/key-length check and for any real crypto-agility
      assessment. Uses **Semgrep** against a small vendored rule set
      (`code_analysis/rules/crypto.yaml`) rather than Semgrep's hosted
      registry — registry configs need network access, and local scans must
      not, per Pillar 2's guarantee. This also covers the bulk of
      "Restricted/weak-algorithm scanning" below (MD5/SHA1, DES/3DES/RC4,
      ECB mode, sub-2048-bit RSA). Getting this working in the container
      took three real fixes found only by running the built image (broken
      cross-stage shebang, semgrep's core `execvp`-ing `pysemgrep` off PATH,
      and a settings-file write failing under `--read-only`) — see
      `CLAUDE.md` for details. Re-verified the network-isolation guarantee
      still holds with this scan type included. Next: CodeQL/SonarQube for
      deeper analysis, more languages, more rules.
- [ ] **Restricted/weak-algorithm scanning** — the vendored Semgrep rules
      above (`code_analysis/`) already cover the known-weak-algorithm half
      of this (modeled after Wind River's **crypto-detector** approach).
      Remaining: **entropy analysis** as a cheap heuristic for
      encrypted-blob detection, a useful complement to
      `scanner/filesystem.py`'s signature checks for files that don't match
      a known format.
- [ ] **Runtime analysis via eBPF** (`bpftrace`, `BCC`) to hook crypto
      library calls (OpenSSL, etc.) directly. Deepest visibility of any
      option here, also the most invasive to run — a later-stage item, not
      a starting point.
- [ ] **Cloud metadata as the reliable baseline** — not a gap, a validation:
      the provider-API approach `scanner/cloud.py` / `scanner/gcs.py` /
      `scanner/azure_blob.py` already use (reading `ServerSideEncryption`,
      `kms_key_name`, `encryption_scope` directly) is the same approach
      called out here as most reliable for cloud storage. Current design
      direction is correct; no change needed.

## Pillar 2 — Containers: the trust boundary

- [x] **Minimal scan-runner image** (`Dockerfile`) — distroless
      `python3-debian12:nonroot` base (no shell, no package manager), runs
      as uid 65532, read-only-root-fs compatible (`/tmp` is the only
      writable path). Building and running it for real, not just writing it,
      surfaced a real bug: an unpinned `streamlit` floor let a fresh install
      pull a version that auto-detects "dev mode" under `pip install
      --target=` and serves the frontend on the wrong port, 404ing every
      page. Pinned to a verified-working range.
- [x] **No default outbound network access** (`SECURITY.md`) — verified,
      not just asserted: `scanner/filesystem.py` and `classifier/scanner.py`
      have no network-related imports, and `docker run --network none` was
      actually exercised (with the honestly-documented caveat that it also
      blocks the UI's published port, so it's a verification mode, not the
      normal way to run the container). This is also why a hosted AI-
      integration API (see Pillar 3) is not planned as a default-on feature.
- [x] **Read-only IAM policy templates** per cloud (`deploy/iam/`) —
      AWS/GCP/Azure least-privilege scan roles, scoped to exactly the API
      calls each scanner module makes.
- [x] **Signed images + SBOM** (`.github/workflows/container-build.yml`) —
      keyless cosign signing via GitHub Actions' OIDC token (no private key
      to manage or leak), plus a syft-generated CycloneDX SBOM attached as a
      signed attestation on the same image — one format across the project,
      matching the CBOM export target and doubling as input for the
      Compliance section's technical documentation dossier. The full
      build→SBOM→sign→attest→verify flow was tested end-to-end locally
      against a throwaway registry before writing the workflow; the keyless
      OIDC step itself can only be exercised for real inside GitHub Actions,
      so it's unverified against a real published image as of this commit
      (see `SECURITY.md` for the honest caveat and how to verify it once it
      has run).
- [ ] **k8s Job manifest / Helm chart** for larger in-cluster or in-VPC scans
      where the target environment is already containerized.

## Pillar 3 — Reporting: where deal value gets argued (Output Layer)

- [ ] **CBOM JSON export** — promised in the README, not yet built. Target
      the **CycloneDX 1.6+** CBOM format specifically rather than a bespoke
      shape — standardized output is what makes this interoperable with
      other tools a due-diligence team might already run, and doubles as a
      safe, zero-new-engineering way for a client's internal AI/RAG tooling
      to consume scan results (a plain file export, not a hosted API — see
      the API note below).
- [ ] **Markdown + PDF report export** — `weasyprint` is already a
      dependency and unused; wire it up. Structure both as an executive
      summary (for a partner/GC) plus a technical appendix (for whoever
      does the remediation work) — Markdown as the lighter-weight,
      easier-to-diff/embed format, PDF as the polished deliverable.
- [ ] **Dollarized risk output** — translate findings into estimated
      remediation cost/effort ("this dataset requires ~$Y to remediate"),
      which is what makes the README's valuation-impact claim real instead
      of aspirational. (This is also what covers the "migration effort
      estimator" idea from the Quantum Risk Engine section — one item, not
      two.)
- [ ] **Partner-ready findings summary** — a report clean enough to hand to
      a partner or GC directly, with a low-key pointer to services for firms
      that want help acting on it. This is the actual lead-gen mechanism for
      the consulting side — keep it understated in the OSS tool itself.

**Explicitly deferred, not committed — hosted AI-integration API.** A file
export (above) is AI-consumable for free. A live API endpoint that a
client's internal AI/RAG system calls is a different thing architecturally:
it's in direct tension with Pillar 2's "never phones home, no default
outbound network access" trust guarantee, which is the reason this audience
is allowed to run the tool at all. If this gets built, it should be a
local-only, explicitly opt-in endpoint — never a hosted default — and is a
later-stage evaluation, not a current commitment.

## Pillar 4 — Project hygiene

- [ ] **Test coverage for cloud scanners** — only `analyzer/risk.py` and
      `scanner/filesystem.py` have tests today; `scanner/cloud.py` has none.
- [ ] **CI: build + scan the container image** (e.g. Trivy) once Pillar 2
      lands.
- [ ] **"Good first issue" labeling** once the above stabilizes, to invite
      outside contributors — a visibly active OSS project is itself a trust
      signal for the target audience.

---

## Compliance & regulatory (EU Cyber Resilience Act)

Not legal advice — flagging here so it isn't lost, and so engineering effort
only gets spent where it's actually actionable. The CRA has a carve-out for
FOSS not developed "in the course of a commercial activity," which may not
apply once the services business is live; get real counsel before relying on
it.

- [ ] **Technical documentation dossier (Annex VII)** — buildable now, no
      legal gate. Architecture description, threat model, essential-
      requirements-to-solution mapping, vulnerability-handling process
      description. Mostly overlaps with Pillar 2's SBOM/signing work and
      `SECURITY.md`'s existing disclosure policy — this is largely writing
      up what's already being built, not new engineering.
- **Blocked on a legal decision, not on engineering effort — CE marking /
  formal conformity assessment.** Requires (1) a product classification call
  (default vs. "Important Class I" — a credential-reading, sensitive-data-
  scanning tool plausibly resembles the identity/access-management and
  security-monitoring categories CRA's Annex III calls out as "important,"
  which may rule out simple self-assessment) and (2) appointing an EU-based
  Authorized Representative, since the manufacturer isn't EU-established.
  Do not attempt to self-certify without resolving both first.
- **Deferred to long-term — ENISA incident/vulnerability reporting
  pipeline.** The 24-hour early-warning / 72-hour full-report / 14-day
  final-report obligations for actively exploited vulnerabilities and severe
  incidents. Only relevant once there's real commercial EU distribution;
  revisit alongside the CE marking decision above, not before.

## Advisory backlog (not tool-buildable)

Captured so these don't get lost, and so they're not mistaken for
engineering work — these are due-diligence risk categories where the tool's
job is to surface a signal, not close the whole gap.

- **Data ownership & classification gaps** (risk #4) — the strongest
  advisor/professional-services angle of the seven. The classifier already
  surfaces *what* sensitive data exists and roughly *where*; mapping that to
  who legally owns it, how long it must stay confidential, and third-party/
  backup residency is a consulting deliverable built on top of scan output,
  not a scannable fact in itself.
- **Talent & governance gaps** (risk #7) — not scannable at all (no
  filesystem/cloud signal indicates whether a target's leadership
  understands quantum risk). One small tool-buildable nicety: include a
  boilerplate "board discussion questions" section in the generated report
  (Pillar 3), authored once, not derived from scan data.
- **Valuation & integration impact** (risk #6) — the engineering side of
  this is Pillar 3's dollarized-risk and partner-ready-summary items above;
  the framing/content side has existing related work at
  [technology-leadership-portfolio](https://github.com/serewicz/technology-leadership-portfolio)
  worth reviewing as an input, not yet reviewed in depth here.

---

## Explicitly out of scope for now

- Packaging as an installable PyPI library (`pyproject.toml` already notes
  this; revisit once there's a CLI consumer, not before).
- Microservices split / Prometheus+Grafana (mentioned in the README's "Future
  Roadmap") — premature before the core scanning coverage above exists.
- **Supply chain & third-party exposure, including shadow AI detection**
  (risk #5) — likely too large a scope for this tool as currently conceived;
  shadow-AI/shadow-IT discovery is closer to a CASB product category than a
  crypto/data-safety scanner. Not committed; revisit only if a specific
  engagement makes the gap unavoidable.
