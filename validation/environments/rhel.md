# Manual Phase 1 execution on RHEL

Target RHEL 8 or 9 as an ordinary user. The harness invokes no package manager;
prepare an installed `harvestguard` CLI, Python 3, OpenSSL, and OpenSSH tooling
before the run. `age` is optional and is recorded as skipped when unavailable.

Example operator preparation, performed separately from the harness:

```bash
sudo dnf install -y openssl openssh-clients python3
# Optional through an approved source for the host: age and age-keygen.
harvestguard --version
```

Run from the repository checkout:

```bash
./validation/run-validation.sh --workspace "$HOME/hgval-$(date -u +%Y%m%d)"
```

Review every disclosure and type exactly `continue` or `abort`. Stage 5 accepts
independently created files under `corpus/operator-supplied`; undeclared files
remain blind observations. Missing optional tools skip only their generator.

RHEL 9 OpenSSL 3 generally needs `openssl genrsa -traditional` for legacy
encrypted PEM. The generator tries the compatible forms and records a skip if
the native tool cannot produce that Phase 1 case. FIPS policy may likewise make
legacy encryption unavailable; record that environment fact in the Stage 2
operator note rather than changing the generator.

After Stage 8, archive only `state/manifest.json` and the two validation reports
described in `validation/manifests/README.md`. Never archive corpus or scratch
material. No manual RHEL execution is claimed by this Phase 1 change; the first
run must be performed and reviewed by an operator on that platform.
