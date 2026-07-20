from __future__ import annotations

import json
import os
import subprocess

import pandas as pd

_RULES_PATH = os.path.join(os.path.dirname(__file__), "rules", "crypto.yaml")
_TIMEOUT_SECONDS = 120

_SEVERITY_TO_RISK = {
    "ERROR": "High",
    "WARNING": "Medium",
    "INFO": "Low",
}


def scan_source_for_crypto_usage(path: str) -> pd.DataFrame:
    """Scan a source tree for weak/legacy crypto library usage via Semgrep.

    Uses a small vendored rule set (code_analysis/rules/crypto.yaml) instead
    of Semgrep's hosted registry, and explicitly disables metrics and the
    version-update check -- both otherwise make a network call regardless of
    where the rules come from, which would break the "local scans make no
    network calls" guarantee documented in SECURITY.md. Verified by manually
    confirming the "new version available" network check disappears with
    these flags set, not by assuming the docs are accurate.

    Runs the plain `semgrep` command off PATH. The container's Dockerfile
    has to do real work to make that command actually functional there --
    `pip install --target=` bakes the builder image's interpreter path into
    the installed console-script's shebang, which breaks in the distroless
    runtime image, and semgrep's compiled core separately execvp()s the
    literal command "pysemgrep" off PATH internally. Both were found by
    actually running the built image, not by inspecting the Dockerfile; see
    the Dockerfile's builder stage for the fix.
    """
    results = []

    try:
        completed = subprocess.run(
            [
                "semgrep",
                "--config", _RULES_PATH,
                "--json",
                "--quiet",
                "--metrics=off",
                "--disable-version-check",
                path,
            ],
            capture_output=True,
            text=True,
            timeout=_TIMEOUT_SECONDS,
            check=False,
        )
    except FileNotFoundError:
        print("Error running code analysis: semgrep is not installed", flush=True)
        return pd.DataFrame(results)
    except subprocess.TimeoutExpired:
        print(
            f"Error running code analysis: semgrep timed out after {_TIMEOUT_SECONDS}s",
            flush=True,
        )
        return pd.DataFrame(results)

    # With --quiet, semgrep exits 0 whether or not it found anything -- a
    # non-zero exit (e.g. semgrep not installed: "No module named semgrep")
    # means the scan itself failed, not that the code is clean. print(...,
    # flush=True) throughout this function because otherwise these
    # diagnostics can silently sit in Python's stdout buffer and never
    # reach `docker logs` for a long-running process -- found by actually
    # hitting a real failure and watching the error not show up anywhere.
    if completed.returncode != 0:
        print(
            f"Error running code analysis (exit {completed.returncode}): "
            f"{completed.stderr.strip()}",
            flush=True,
        )
        return pd.DataFrame(results)

    try:
        payload = json.loads(completed.stdout or "{}")
    except json.JSONDecodeError:
        print(
            f"Error running code analysis: could not parse semgrep output: {completed.stderr}",
            flush=True,
        )
        return pd.DataFrame(results)

    for finding in payload.get("results", []):
        extra = finding.get("extra", {})
        severity = extra.get("severity", "INFO")
        results.append({
            "Location": f"{finding['path']}:{finding['start']['line']}",
            "Rule": finding["check_id"].rsplit(".", 1)[-1],
            "Message": extra.get("message", "").strip(),
            "Risk": _SEVERITY_TO_RISK.get(severity, "Low"),
        })

    return pd.DataFrame(results)
