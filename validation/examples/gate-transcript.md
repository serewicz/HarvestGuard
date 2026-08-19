# Example interactive gate transcript

This abbreviated transcript demonstrates control flow only. It is **illustrative,
not run evidence**: it was hand-trimmed to show how a gate accepts input, it
records no observed result, and no host produced it. Verbatim output from real
runs is in [`../transcripts/`](../transcripts/), indexed with the reports in
[`README.md`](README.md).

```text
GATE 1 of 8 — Environment inspection
...
Type continue or abort:
WARNING: enter exactly 'continue' or 'abort'; the gate remains closed
Type continue or abort: continue
Confirmed. Continuing.

GATE 2 of 8 — Validation plan
...
Type continue or abort: abort
Stopped at gate 2 (Validation plan) by operator request.
Workspace retained for inspection: /tmp/hg-validation-example
```

Empty input does not advance. `abort` preserves the workspace. Later gates use
the same exact words; Stage 8 separately requires an explicit `delete` before
cleanup removes the marked workspace.
