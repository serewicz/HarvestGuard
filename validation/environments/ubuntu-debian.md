# Ubuntu and Debian status

Ubuntu and Debian are **not validated in Phase 1**. The harness detects the OS
family and may run there when required tools are already installed, but that is
an observation rather than a supported-platform claim.

A future phase may document Ubuntu/Debian package and tool mappings in this
file. They do not belong in the orchestrator, and the harness never invokes
`apt` or another package manager.
