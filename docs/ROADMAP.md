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
- [ ] **Sensitive-data classification module** (new `classifier/` package) —
      PII (names, SSNs, emails, phone numbers), payment card patterns, and
      secrets/API keys/credentials, scanned alongside crypto status. This is
      the "customer data safety" pillar, distinct from HNDL/crypto risk, and
      is what most directly matches what this audience actually asks for.
- [ ] **GCS scanner** (`scanner/gcs.py`) — mirror `scanner/cloud.py`:
      per-object encryption status via the GCS API (CMEK vs. Google-managed
      vs. none).
- [ ] **Azure Blob scanner** (`scanner/azure.py`) — per-blob encryption
      status via the Azure SDK (customer-managed vs. Microsoft-managed keys).
- [ ] **Common `ScanResult` interface** — normalize local/AWS/GCP/Azure/
      classifier output into one schema so the analyzer, dashboard, and
      exporters don't special-case each source. Do this once a second cloud
      backend exists, not before (avoid speculative abstraction).

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

- [ ] **CBOM JSON export** — promised in the README, not yet built.
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
