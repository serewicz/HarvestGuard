from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import certifi
import pandas as pd

from finding_adapters import normalize_code_analysis_df
from findings import NormalizedFinding
from scanner.errors import LocalScanError

_RULES_PATH = os.path.join(os.path.dirname(__file__), "rules", "crypto.yaml")
_TIMEOUT_SECONDS = 120

_SEVERITY_TO_RISK = {
    "ERROR": "High",
    "WARNING": "Medium",
    "INFO": "Low",
}


def _semgrep_command() -> str:
    return shutil.which("semgrep") or str(Path(sys.executable).parent / "semgrep")


def _semgrep_env() -> dict[str, str]:
    env = os.environ.copy()
    semgrep_home = Path(tempfile.gettempdir()) / "harvestguard-semgrep"
    semgrep_home.mkdir(parents=True, exist_ok=True)
    env.update({
        "HOME": str(semgrep_home),
        "OTEL_SDK_DISABLED": "true",
        "SEMGREP_ENABLE_VERSION_CHECK": "0",
        "SEMGREP_SEND_METRICS": "off",
        "SEMGREP_SETTINGS_FILE": str(semgrep_home / "settings.yml"),
        "REQUESTS_CA_BUNDLE": certifi.where(),
        "SSL_CERT_FILE": certifi.where(),
    })
    return env


def scan_source_for_crypto_usage(
    path: str, errors: list[str] | None = None
) -> pd.DataFrame:
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

    def diagnose(message: str) -> None:
        # Messages are fixed categories and bounded numeric values only. Never
        # interpolate analyzer stderr, error objects, source text or exceptions.
        if errors is not None:
            errors.append(message)
        else:
            print(message, file=sys.stderr, flush=True)

    def fail(message: str) -> pd.DataFrame:
        diagnose(message)
        return pd.DataFrame(results)

    try:
        completed = subprocess.run(
            [
                _semgrep_command(),
                "--config", _RULES_PATH,
                "--json",
                "--quiet",
                "--metrics=off",
                "--disable-version-check",
                path,
            ],
            capture_output=True,
            env=_semgrep_env(),
            text=True,
            timeout=_TIMEOUT_SECONDS,
            check=False,
        )
    except FileNotFoundError:
        return fail("Error running code analysis: semgrep is not installed")
    except subprocess.TimeoutExpired:
        return fail(
            f"Error running code analysis: semgrep timed out after {_TIMEOUT_SECONDS}s"
        )
    except (OSError, UnicodeError):
        return fail("Error running code analysis: analyzer execution or decoding failed")

    # A nonzero exit can accompany a complete structured response with usable
    # matches. Keep independently valid matches, but never erase the failure.
    if completed.returncode != 0:
        diagnose("Error running code analysis: analyzer exited nonzero (exit "
                 f"{max(-999, min(999, completed.returncode))})")
    if not completed.stdout or not completed.stdout.strip():
        return fail("Error running code analysis: missing analyzer output")
    try:
        payload = json.loads(completed.stdout)
    except (ValueError, RecursionError):
        return fail("Error running code analysis: could not parse semgrep output")
    if not isinstance(payload, dict) or not isinstance(payload.get("results"), list):
        return fail("Error running code analysis: invalid or missing results array")
    if not isinstance(payload.get("errors"), list):
        diagnose("Error running code analysis: invalid or missing errors array")
    elif payload["errors"]:
        diagnose("Error running code analysis: analyzer reported errors")

    invalid_result = False
    for finding in payload["results"]:
        try:
            if not isinstance(finding, dict):
                raise ValueError
            path = finding["path"]
            rule = finding["check_id"]
            line = finding["start"]["line"]
            extra = finding["extra"]
            message = extra["message"]
            severity = extra["severity"]
            if (not isinstance(path, str) or not path.strip()
                    or not isinstance(rule, str) or not rule.strip()
                    or type(line) is not int or line < 1
                    or not isinstance(message, str)
                    or not isinstance(severity, str) or severity not in _SEVERITY_TO_RISK):
                raise ValueError
        except (KeyError, TypeError, ValueError):
            invalid_result = True
            continue
        results.append({
            "Location": f"{path}:{line}",
            "Rule": rule.rsplit(".", 1)[-1],
            "Message": message.strip(),
            "Risk": _SEVERITY_TO_RISK[severity],
        })
    if invalid_result:
        diagnose("Error running code analysis: malformed result entries omitted")

    return pd.DataFrame(results)


def scan_source_for_crypto_usage_findings(
    path: str, scan_id: str | None = None
) -> list[NormalizedFinding]:
    # Collection time for the scan (observed_at), stamped explicitly rather
    # than left unset so code-analysis records carry a scan time like every
    # other adapter.
    collected_at = datetime.now(timezone.utc)
    errors: list[str] = []
    findings = normalize_code_analysis_df(
        scan_source_for_crypto_usage(path, errors=errors),
        scan_id=scan_id,
        observed_at=collected_at,
    )
    if errors:
        raise LocalScanError("; ".join(errors), partial_findings=findings)
    return findings
