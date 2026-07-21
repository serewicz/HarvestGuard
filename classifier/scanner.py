from __future__ import annotations

import os
from datetime import datetime

import pandas as pd

from classifier.patterns import CATEGORY_PATTERNS, SEVERE_CATEGORIES, is_valid_credit_card
from finding_adapters import normalize_sensitive_data_df
from findings import NormalizedFinding

# Lightweight classification scan, not full-text indexing -- files above
# this size are skipped rather than partially read.
_MAX_FILE_BYTES = 2_000_000


def _read_text(full_path: str, max_bytes: int = _MAX_FILE_BYTES) -> str | None:
    """Best-effort text read; returns None for binary or oversized files.

    Content is only ever held in memory transiently to run regex matches
    against it -- classify_text() below returns category counts, never the
    matched values, so raw PII/secrets don't end up sitting in scan results.
    """
    try:
        if os.path.getsize(full_path) > max_bytes:
            return None
        with open(full_path, "rb") as fh:
            raw = fh.read(max_bytes)
    except (OSError, PermissionError):
        return None

    if b"\x00" in raw:  # crude binary heuristic
        return None

    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        try:
            return raw.decode("latin-1")
        except UnicodeDecodeError:
            return None


def classify_text(text: str) -> dict[str, int]:
    """Count regex matches per sensitive-data category in a text blob."""
    counts: dict[str, int] = {}
    for category, pattern in CATEGORY_PATTERNS.items():
        matches = pattern.findall(text)
        if category == "Credit Card":
            matches = [m for m in matches if is_valid_credit_card(m)]
        if matches:
            counts[category] = len(matches)
    return counts


def classify_file(full_path: str) -> dict[str, int]:
    text = _read_text(full_path)
    if text is None:
        return {}
    return classify_text(text)


def _risk_for_categories(categories: dict[str, int]) -> str:
    return "High" if SEVERE_CATEGORIES & categories.keys() else "Medium"


def scan_filesystem_for_sensitive_data(path: str, max_depth: int = 3) -> pd.DataFrame:
    """Walk a path and classify each file's contents for PII/secrets.

    Kept as a separate pass from scanner.filesystem's metadata/encryption
    walk so a crypto-only scan never has to read file contents it doesn't
    need. Only files with at least one match are included -- this is a
    findings report, not a full inventory.
    """
    results = []

    for root, dirs, files in os.walk(path):
        depth = root.count(os.sep) - path.count(os.sep)
        if depth > max_depth:
            continue

        for f in files:
            full_path = os.path.join(root, f)
            try:
                st = os.stat(full_path)
                categories = classify_file(full_path)
            except Exception:
                continue

            if not categories:
                continue

            results.append({
                "Location": full_path,
                "Size": st.st_size,
                "Modified": datetime.fromtimestamp(st.st_mtime),
                "Categories": ", ".join(sorted(categories)),
                "Total Matches": sum(categories.values()),
                "Risk": _risk_for_categories(categories),
            })

    return pd.DataFrame(results)


def scan_filesystem_for_sensitive_data_findings(
    path: str, max_depth: int = 3, scan_id: str | None = None
) -> list[NormalizedFinding]:
    return normalize_sensitive_data_df(
        scan_filesystem_for_sensitive_data(path, max_depth=max_depth), scan_id=scan_id
    )
