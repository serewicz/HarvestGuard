from __future__ import annotations

import os
import platform
import shutil
import subprocess
from datetime import datetime
from functools import lru_cache

import pandas as pd

# Leading-byte signatures for common encrypted file formats. Checked before
# falling back to volume-level status, since a single encrypted file can sit
# on an otherwise unencrypted volume (and vice versa).
_FILE_SIGNATURES = [
    (b"Salted__", "File-level (OpenSSL)"),
    (b"-----BEGIN PGP", "File-level (PGP/GPG)"),
    (b"\x85\x01", "File-level (PGP/GPG)"),
    (b"\x85\x02", "File-level (PGP/GPG)"),
    (b"age-encryption.org/v1", "File-level (age)"),
    (b"LUKS\xba\xbe", "File-level (LUKS container)"),
]

_HEADER_READ_BYTES = 32


def _detect_file_signature(full_path: str) -> str | None:
    """Best-effort check of a file's leading bytes against known encrypted formats."""
    try:
        with open(full_path, "rb") as fh:
            header = fh.read(_HEADER_READ_BYTES)
    except (OSError, PermissionError):
        return None

    for signature, label in _FILE_SIGNATURES:
        if header.startswith(signature):
            return label

    # Encrypted ZIP: general-purpose bit flag, bit 0, in the local file header.
    if header[:4] == b"PK\x03\x04" and len(header) >= 8 and header[6] & 0x01:
        return "File-level (Encrypted ZIP)"

    return None


@lru_cache(maxsize=None)
def _detect_volume_encryption(mount_point: str) -> str:
    """Best-effort volume/filesystem-level encryption status for a mount point.

    Falls back to "Unknown" on unsupported platforms or when the relevant
    tooling isn't available/permitted rather than assuming unencrypted.
    """
    system = platform.system()
    try:
        if system == "Darwin":
            out = subprocess.run(
                ["fdesetup", "status"], capture_output=True, text=True, timeout=5
            ).stdout
            if "FileVault is On" in out:
                return "Volume-level (FileVault)"
            if "FileVault is Off" in out:
                return "Unencrypted"
        elif system == "Linux" and shutil.which("lsblk"):
            out = subprocess.run(
                ["lsblk", "-no", "TYPE"], capture_output=True, text=True, timeout=5
            ).stdout
            if "crypt" in out.split():
                return "Volume-level (LUKS)"
            return "Unencrypted"
        elif system == "Windows" and shutil.which("manage-bde"):
            drive = os.path.splitdrive(mount_point)[0] or "C:"
            out = subprocess.run(
                ["manage-bde", "-status", drive], capture_output=True, text=True, timeout=5
            ).stdout
            if "Protection On" in out:
                return "Volume-level (BitLocker)"
            if "Protection Off" in out:
                return "Unencrypted"
    except (subprocess.SubprocessError, OSError):
        pass

    return "Unknown"


def _volume_root(path: str) -> str:
    """Walk up to the nearest mount point so volume checks can be cached per-volume."""
    current = os.path.abspath(path)
    while not os.path.ismount(current):
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent
    return current


def _risk_for_encryption(encryption: str) -> str:
    if encryption.startswith("File-level") or encryption.startswith("Volume-level"):
        return "Low"
    if encryption == "Unencrypted":
        return "High"
    return "Medium"  # Unknown / undetermined


def scan_filesystem(path: str, max_depth: int = 3):
    """Filesystem scanner with real encryption detection.

    Each file is checked against known encrypted-file signatures; if none
    match, it inherits the encryption status of the volume it lives on
    (FileVault / LUKS / BitLocker), computed once per scan root.
    """
    results = []
    volume_status = _detect_volume_encryption(_volume_root(path))

    for root, dirs, files in os.walk(path):
        depth = root.count(os.sep) - path.count(os.sep)
        if depth > max_depth:
            continue

        for f in files:
            full_path = os.path.join(root, f)
            try:
                st = os.stat(full_path)
                encryption = _detect_file_signature(full_path) or volume_status
                results.append({
                    "Location": full_path,
                    "Size": st.st_size,
                    "Modified": datetime.fromtimestamp(st.st_mtime),
                    "Encryption": encryption,
                    "Owner": st.st_uid,
                    "Risk": _risk_for_encryption(encryption),
                })
            except Exception:
                pass  # Skip permission issues

    return pd.DataFrame(results)
