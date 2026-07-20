import os
from datetime import datetime

import pandas as pd


def scan_filesystem(path: str, max_depth: int = 3):
    """Simple filesystem scanner for POC."""
    results = []

    for root, dirs, files in os.walk(path):
        depth = root.count(os.sep) - path.count(os.sep)
        if depth > max_depth:
            continue

        for f in files:
            full_path = os.path.join(root, f)
            try:
                st = os.stat(full_path)
                is_encrypted = "Unknown"  # POC placeholder - real detection next
                results.append({
                    "Location": full_path,
                    "Size": st.st_size,
                    "Modified": datetime.fromtimestamp(st.st_mtime),
                    "Encryption": is_encrypted,
                    "Owner": st.st_uid,
                    "Risk": "Medium"
                })
            except Exception:
                pass  # Skip permission issues

    return pd.DataFrame(results)
