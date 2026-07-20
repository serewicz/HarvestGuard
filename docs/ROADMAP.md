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

Current state (as of this writing): Streamlit POC. Local filesystem scan is a
stub (`Encryption` is hardcoded `"Unknown"`). AWS S3 scan is real (checks
`ServerSideEncryption` per object). No GCP, no Azure, no containers, no PII/
secrets detection — risk scoring is a simple heuristic on top of the crypto
status alone.

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
      exporters don't special-case each source. Do this once a second cloud
      backend exists, not before (avoid speculative abstraction).

### Future scan surfaces — tooling landscape

Everything above covers data at rest (filesystem, object storage). Matching
market-quality crypto/data-safety tooling means also covering data in
transit and crypto usage in code — and, for all of these, leaning on
proven OSS tools rather than re-implementing detection logic from scratch.
This is a survey to pull individual items from, not a commitment to build
all of it; sequencing depends on which gap a real due-diligence engagement
hits first.

- [ ] **Network traffic / cipher detection** (data in transit — nothing
      today covers this). Candidates: **Zeek** (best-in-class OSS network
      analyzer — cipher suites, TLS versions, certs, straight from a pcap
      or live capture), **sslyze** (fast, scriptable TLS config scanner),
      **testssl.sh** (comprehensive TLS/SSL test script), **nmap**
      (`--script ssl-enum-ciphers` for a quick enumeration pass).
- [ ] **Code & binary analysis** (crypto *library usage* in source — a
      different axis from `classifier/`'s content-pattern matching).
      Candidates: **CodeQL** (static analysis queries purpose-built for
      crypto API usage), **Semgrep** (lightweight, fast pattern rules —
      likely the easiest first integration given the project is already
      Python-centric tooling), **SonarQube** + community crypto rulesets.
- [ ] **Restricted/weak-algorithm scanning** — Wind River's
      **crypto-detector** as reference for flagging known-weak algorithms
      in code; **entropy analysis** as a cheap heuristic for encrypted-blob
      detection, potentially a useful complement to `scanner/filesystem.py`'s
      signature checks for files that don't match a known format.
- [ ] **Runtime analysis via eBPF** (`bpftrace`, `BCC`) to hook crypto
      library calls (OpenSSL, etc.) directly. Deepest visibility of any
      option here, also the most invasive to run — a later-stage item, not
      a starting point.
- [ ] **Quantum-specific checks** — flag known-vulnerable algorithms/key
      sizes (RSA/ECC under safe thresholds) explicitly rather than only
      inferring HNDL risk from encryption presence/absence as today; Mosca
      inequality-style modeling (data lifetime vs. quantum timeline) to
      turn "this is at risk" into "this is at risk starting in ~N years";
      hybrid PQC-readiness checks once a library like `liboqs` is
      integrated. This is the project's namesake (Harvest-Now-Decrypt-Later)
      and currently the least literally-implemented part of the roadmap.
- [ ] **Cloud metadata as the reliable baseline** — not a gap, a validation:
      the provider-API approach `scanner/cloud.py` / `scanner/gcs.py` /
      `scanner/azure_blob.py` already use (reading `ServerSideEncryption`,
      `kms_key_name`, `encryption_scope` directly) is the same approach
      called out here as most reliable for cloud storage. Current design
      direction is correct; no change needed.

## Pillar 2 — Containers: the trust boundary

- [ ] **Minimal scan-runner image** — distroless or scratch base, non-root,
      read-only root filesystem. This is what a firm's IT/security team will
      actually inspect before approving use on deal data.
- [ ] **No default outbound network access** — scan results stay on the
      machine/volume unless the user explicitly exports them. Document this
      as an explicit guarantee, not just an implementation detail.
- [ ] **Read-only IAM policy templates** per cloud (AWS/GCP/Azure
      least-privilege scan roles) — small to build, and one of the highest
      trust-per-effort items on this list; a security-conscious buyer will
      ask for exactly this.
- [ ] **Signed images + SBOM** (cosign, syft) for the scanner itself —
      supply-chain provenance, and a natural dogfood of the project's own
      crypto-inventory premise.
- [ ] **k8s Job manifest / Helm chart** for larger in-cluster or in-VPC scans
      where the target environment is already containerized.

## Pillar 3 — Reporting: where deal value gets argued

- [ ] **CBOM JSON export** — promised in the README, not yet built. Target
      the **CycloneDX 1.6+** CBOM format specifically rather than a bespoke
      shape — standardized output is what makes this interoperable with
      other tools a due-diligence team might already run.
- [ ] **PDF report export** — `weasyprint` is already a dependency and
      unused; wire it up.
- [ ] **Dollarized risk output** — translate findings into estimated
      remediation cost/effort ("this dataset requires ~$Y to remediate"),
      which is what makes the README's valuation-impact claim real instead
      of aspirational.
- [ ] **Partner-ready findings summary** — a report clean enough to hand to
      a partner or GC directly, with a low-key pointer to services for firms
      that want help acting on it. This is the actual lead-gen mechanism for
      the consulting side — keep it understated in the OSS tool itself.

## Pillar 4 — Project hygiene

- [ ] **Test coverage for cloud scanners** — only `analyzer/risk.py` and
      `scanner/filesystem.py` have tests today; `scanner/cloud.py` has none.
- [ ] **CI: build + scan the container image** (e.g. Trivy) once Pillar 2
      lands.
- [ ] **"Good first issue" labeling** once the above stabilizes, to invite
      outside contributors — a visibly active OSS project is itself a trust
      signal for the target audience.

---

## Explicitly out of scope for now

- Packaging as an installable PyPI library (`pyproject.toml` already notes
  this; revisit once there's a CLI consumer, not before).
- Microservices split / Prometheus+Grafana (mentioned in the README's "Future
  Roadmap") — premature before the core scanning coverage above exists.
