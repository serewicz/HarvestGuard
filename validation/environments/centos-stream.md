# Manual Phase 1 execution on CentOS Stream

Target CentOS Stream 9 or 10 as an ordinary user. Follow the RHEL-family
procedure in [`rhel.md`](rhel.md), which now records a complete eight-gate run on
AlmaLinux 9.8 — a RHEL-compatible distribution — including the operator
preparation, the confirmed behavior, and the known limitations that apply to this
family.

CentOS Stream itself has **not** been run. It carries `centos` in `ID` or
`ID_LIKE`, which is what `lib/env_inspect.sh` matches to family `rhel`, so it is
expected to detect identically to the validated AlmaLinux host; that is an
inference from the detection code, not an observation.

The harness never invokes `dnf`; operator preparation is separate and may use:

```bash
sudo dnf install -y openssl openssh-clients python3.12
# Optional through an approved source for the host: age and age-keygen.
```

CentOS Stream 9's default `python3` is 3.9, below the HarvestGuard package's
`requires-python = ">=3.10"` floor, so install a 3.10+ interpreter as
`rhel.md` describes.

CentOS Stream tool versions move between snapshots, so retain the exact versions
recorded by Stage 1 — the AlmaLinux run's OpenSSL 3.5.5 and its successful
`openssl genrsa -aes128 -traditional` legacy-PEM generation are that host's
observations, not a guarantee for a different snapshot. Absence of `age` is a
generator skip, not a harness failure. The harness does not block the host solely
because of OS family.

Archive only the frozen manifest and result reports with a
`centos-stream-<date>-` prefix. The first CentOS Stream run remains an operator
task.
