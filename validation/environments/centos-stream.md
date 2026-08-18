# Manual Phase 1 execution on CentOS Stream

Target CentOS Stream 9 or 10 as an ordinary user. Follow the RHEL procedure in
[`rhel.md`](rhel.md). The harness never invokes `dnf`; operator preparation is
separate and may use:

```bash
sudo dnf install -y openssl openssh-clients python3
# Optional through an approved source for the host: age and age-keygen.
```

CentOS Stream tool versions move between snapshots, so retain the exact versions
recorded by Stage 1. Absence of `age` is a generator skip, not a harness failure.
The harness does not block the host solely because of OS family.

Archive only the frozen manifest and result reports with a
`centos-stream-<date>-` prefix. No manual CentOS Stream execution is claimed by
this Phase 1 change; the first run remains an operator task.
