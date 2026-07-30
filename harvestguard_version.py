"""The single source of truth for the HarvestGuard version.

Kept in its own module so both the CLI (`harvestguard.py`) and the report
writer (`reports.py`) can read it without importing each other -- the CLI
already imports `reports`, so the constant cannot live there.

The module is named for the distribution rather than the shorter `version`
because the repository uses a flat layout: every module listed in
`pyproject.toml`'s `py-modules` installs at the top level of site-packages,
where a name like `version` would be an obvious collision.

`pyproject.toml` carries this same version literal (setuptools reads it
statically at build time); `tests/test_release_identity.py` asserts the two
never drift apart.
"""

from __future__ import annotations

__version__ = "0.1.0"

# What `harvestguard --version` prints, and what a report records as the tool
# that produced it.
PROGRAM_NAME = "harvestguard"


def version_string() -> str:
    """Human-readable program identity, e.g. ``harvestguard 0.1.0``."""
    return f"{PROGRAM_NAME} {__version__}"
