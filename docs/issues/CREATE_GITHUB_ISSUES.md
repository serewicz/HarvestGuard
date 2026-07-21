# Create GitHub Issues

`gh` is the intended path for creating the first seven MVP issues from these
specifications. Authenticate first:

```bash
gh auth login -h github.com
```

Create recommended labels if they do not already exist:

```bash
gh label create mvp --color 0E8A16 --description "Milestone 1 MVP work" --repo serewicz/HarvestGuard
gh label create priority:p1 --color D93F0B --description "High-priority roadmap work" --repo serewicz/HarvestGuard
gh label create work:scanner --color 1D76DB --description "Scanner and adapter work" --repo serewicz/HarvestGuard
gh label create work:documentation --color 5319E7 --description "Documentation work" --repo serewicz/HarvestGuard
gh label create work:schema --color 006B75 --description "Schema and data model work" --repo serewicz/HarvestGuard
gh label create work:cli --color FBCA04 --description "CLI work" --repo serewicz/HarvestGuard
gh label create work:reporting --color C5DEF5 --description "Report and export work" --repo serewicz/HarvestGuard
gh label create work:tests --color BFDADC --description "Test coverage work" --repo serewicz/HarvestGuard
```

Before creating issues, check for duplicates:

```bash
gh issue list --repo serewicz/HarvestGuard --search "HG-001 in:title"
gh issue list --repo serewicz/HarvestGuard --search "HG-002 in:title"
gh issue list --repo serewicz/HarvestGuard --search "HG-003 in:title"
gh issue list --repo serewicz/HarvestGuard --search "HG-004 in:title"
gh issue list --repo serewicz/HarvestGuard --search "HG-005 in:title"
gh issue list --repo serewicz/HarvestGuard --search "HG-006 in:title"
gh issue list --repo serewicz/HarvestGuard --search "HG-007 in:title"
```

Create the first seven MVP issues:

```bash
gh issue create --repo serewicz/HarvestGuard --title "HG-001: Cryptographic Asset Inventory" --body-file docs/issues/HG-001-cryptographic-asset-inventory.md --label mvp --label priority:p1 --label work:scanner --label work:schema
gh issue create --repo serewicz/HarvestGuard --title "HG-002: Defensible Risk Terminology" --body-file docs/issues/HG-002-risk-terminology.md --label mvp --label priority:p1 --label work:documentation
gh issue create --repo serewicz/HarvestGuard --title "HG-003: Normalized Finding Schema" --body-file docs/issues/HG-003-normalized-finding-schema.md --label mvp --label priority:p1 --label work:schema
gh issue create --repo serewicz/HarvestGuard --title "HG-004: CLI" --body-file docs/issues/HG-004-cli.md --label mvp --label priority:p1 --label work:cli --label work:tests
gh issue create --repo serewicz/HarvestGuard --title "HG-005: Scale, Pagination, and Safety" --body-file docs/issues/HG-005-scale-and-safety.md --label mvp --label priority:p1 --label work:scanner --label work:tests
gh issue create --repo serewicz/HarvestGuard --title "HG-006: Demo Target" --body-file docs/issues/HG-006-demo-target.md --label mvp --label priority:p1 --label work:tests --label work:documentation
gh issue create --repo serewicz/HarvestGuard --title "HG-007: JSON and Markdown Reports" --body-file docs/issues/HG-007-json-markdown-reports.md --label mvp --label priority:p1 --label work:reporting --label work:cli
```
