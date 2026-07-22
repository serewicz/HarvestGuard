from __future__ import annotations

import os
import platform
import re
import shutil
import stat
import subprocess
from datetime import datetime, timezone
from functools import lru_cache

import pandas as pd

from finding_adapters import normalize_filesystem_df
from findings import NormalizedFinding

try:
    import grp
    import pwd
except ImportError:  # Windows has neither module
    grp = None  # type: ignore[assignment]
    pwd = None  # type: ignore[assignment]

SCANNER_VERSION = "0.1.0"
_COLLECTION_METHOD = "stat + leading-byte signature scan with volume-level fallback"

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


def scan_filesystem_findings(
    path: str, max_depth: int = 3, scan_id: str | None = None
) -> list[NormalizedFinding]:
    return normalize_filesystem_df(
        scan_filesystem_evidence(path, max_depth=max_depth), scan_id=scan_id
    )


# --- Reference implementation: local filesystem -> NormalizedFinding -------
#
# This path is independent of scan_filesystem() above (which stays exactly as
# it was for the Streamlit dashboard's DataFrame contract) because it treats
# the scan target as untrusted: it does not follow symlinks, does not open
# FIFOs/sockets/device files (which can block indefinitely), uses O_NOFOLLOW
# to close a symlink-swap TOCTOU window, and never silently turns a read
# failure into "no finding" -- degraded observations still produce a Finding
# with a limitation attached.


def _detect_file_signature_safe(full_path: str) -> tuple[str | None, str | None]:
    """Like _detect_file_signature, but distinguishes "no known signature
    matched" (both None) from "could not read the file to check"
    (limitation text returned as the second element). The plain
    _detect_file_signature() silently conflates these two cases, which is
    fine for the best-effort dashboard path but not for evidence that must
    be defensible.
    """
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(full_path, flags)
    except PermissionError:
        return None, f"Permission denied reading file header: {full_path}"
    except FileNotFoundError:
        return None, (
            "File became inaccessible before its header could be read "
            "(removed or replaced during inspection)."
        )
    except OSError as exc:
        return None, f"Unable to open file for header inspection: {exc}"

    try:
        with os.fdopen(fd, "rb") as fh:
            header = fh.read(_HEADER_READ_BYTES)
    except OSError as exc:
        return None, f"Unable to read file header: {exc}"

    for signature, label in _FILE_SIGNATURES:
        if header.startswith(signature):
            return label, None

    if header[:4] == b"PK\x03\x04" and len(header) >= 8 and header[6] & 0x01:
        return "File-level (Encrypted ZIP)", None

    return None, None


def _owner_name(uid: int) -> str | None:
    if pwd is None:
        return None
    try:
        return pwd.getpwuid(uid).pw_name
    except (KeyError, OverflowError):
        return None


def _group_name(gid: int) -> str | None:
    if grp is None:
        return None
    try:
        return grp.getgrgid(gid).gr_name
    except (KeyError, OverflowError):
        return None


def _detect_acl_presence(full_path: str) -> bool | None:
    """Best-effort, portable ACL-presence check.

    POSIX ACLs are exposed as a Linux extended attribute
    (system.posix_acl_access), checkable with stdlib os.listxattr alone.
    macOS ACLs are not exposed through xattrs or any other stdlib API, and
    Windows ACLs are a different model entirely -- both would need a new
    dependency to check portably, which is out of scope here. Returns None
    (recorded as a limitation by the caller) rather than guessing.
    """
    if platform.system() != "Linux" or not hasattr(os, "listxattr"):
        return None
    try:
        return "system.posix_acl_access" in os.listxattr(full_path, follow_symlinks=False)
    except OSError:
        return None


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")


def _observe_regular_file(
    full_path: str,
    lst: os.stat_result,
    volume_status: str,
    collected_at: datetime,
    collection_source: str,
) -> dict:
    unknowns = ["Business ownership cannot be established from filesystem metadata."]
    limitations: list[str] = []

    signature, read_limitation = _detect_file_signature_safe(full_path)
    if read_limitation is not None:
        limitations.append(read_limitation)
        encryption = volume_status
        rule_id = f"volume_status:{_slug(volume_status)}"
        verification_rationale = (
            "File header could not be read for signature detection; "
            "volume-level encryption status was used instead."
        )
        confidence = "Low"
        confidence_rationale = (
            "File-level encryption status could not be verified because the "
            "file's content could not be read; confidence reflects the "
            "unverified volume-level fallback."
        )
        unknowns.append("File-level encryption status cannot be established conclusively.")
        repeatable = False
    elif signature is not None:
        encryption = signature
        rule_id = f"file_signature:{_slug(signature)}"
        verification_rationale = (
            f"Leading file bytes matched a known encrypted-format signature ({signature})."
        )
        confidence = "High"
        confidence_rationale = (
            "Signature-based detection directly inspects file content, "
            "independent of filesystem or volume state."
        )
        repeatable = True
    else:
        encryption = volume_status
        rule_id = f"volume_status:{_slug(volume_status)}"
        unknowns.append("File-level encryption status cannot be established conclusively.")
        if volume_status == "Unknown":
            verification_rationale = (
                "No known file-level signature matched, and volume-level "
                "encryption status could not be determined on this platform."
            )
            confidence = "Low"
            confidence_rationale = (
                "Neither file-level nor volume-level encryption status could be established."
            )
            repeatable = False
        else:
            verification_rationale = (
                "No known file-level signature matched; volume-level "
                "encryption status was used because file-level status could "
                "not be independently determined."
            )
            confidence = "Medium"
            confidence_rationale = (
                "Volume-level status describes the entire volume rather than "
                "this specific file, so file-level status remains unverified."
            )
            repeatable = True

    owner_name = _owner_name(lst.st_uid)
    if owner_name is None:
        limitations.append(
            "Owner name resolution is unavailable on this platform."
            if pwd is None
            else f"No passwd entry found for uid {lst.st_uid}; owner name is unknown."
        )

    group_name = _group_name(lst.st_gid)
    if group_name is None:
        limitations.append(
            "Group name resolution is unavailable on this platform."
            if grp is None
            else f"No group entry found for gid {lst.st_gid}; group name is unknown."
        )

    acl_present = _detect_acl_presence(full_path)
    if acl_present is None:
        limitations.append("ACL presence could not be portably determined on this platform.")

    return {
        "Asset Type": "file",
        "Location": full_path,
        "Size": lst.st_size,
        "Modified": datetime.fromtimestamp(lst.st_mtime, tz=timezone.utc),
        "Encryption": encryption,
        "Evidence": f"Encryption status observed: {encryption}",
        "Rule ID": rule_id,
        "Verification Rationale": verification_rationale,
        "Confidence": confidence,
        "Confidence Rationale": confidence_rationale,
        "Repeatable": repeatable,
        "UID": lst.st_uid,
        "Owner Name": owner_name,
        "GID": lst.st_gid,
        "Group Name": group_name,
        "Mode Octal": format(stat.S_IMODE(lst.st_mode), "04o"),
        "Permissions": stat.filemode(lst.st_mode),
        "ACL Present": acl_present,
        "Unknowns": unknowns,
        "Limitations": limitations,
        "Collection Method": _COLLECTION_METHOD,
        "Collection Source": collection_source,
        "Collected At": collected_at,
    }


def _degraded_record(
    full_path: str, collected_at: datetime, collection_source: str, limitation: str
) -> dict:
    """A Finding for an entry that could not be inspected at all (e.g.
    permission denied on the entry itself, or it vanished before it could be
    stat'd). Never silently drop the entry -- record what happened instead.
    """
    return {
        "Asset Type": "file",
        "Location": full_path,
        "Size": None,
        "Modified": None,
        "Encryption": "Unknown",
        "Evidence": "Encryption status could not be observed; file metadata was inaccessible.",
        "Rule ID": "metadata_unavailable",
        "Verification Rationale": (
            "File metadata could not be read, so encryption status could not be observed."
        ),
        "Confidence": "Low",
        "Confidence Rationale": (
            "No observation could be made because the file's metadata was inaccessible."
        ),
        "Repeatable": False,
        "UID": None,
        "Owner Name": None,
        "GID": None,
        "Group Name": None,
        "Mode Octal": None,
        "Permissions": None,
        "ACL Present": None,
        "Unknowns": [
            "Business ownership cannot be established from filesystem metadata.",
            "File-level encryption status cannot be established conclusively.",
            "Technical ownership signals could not be captured because file "
            "metadata could not be read.",
        ],
        "Limitations": [limitation],
        "Collection Method": _COLLECTION_METHOD,
        "Collection Source": collection_source,
        "Collected At": collected_at,
    }


def _directory_traversal_error_record(
    dir_path: str, collected_at: datetime, collection_source: str, exc: OSError
) -> dict:
    """A Finding for a directory os.walk could not list at all (e.g.
    permission denied). Coverage gaps are reported explicitly rather than
    silently treated as "no findings beneath this directory" -- no file-level
    observations are fabricated for whatever the directory might contain.
    """
    return {
        "Asset Type": "directory",
        "Location": dir_path,
        "Size": None,
        "Modified": None,
        "Encryption": None,
        "Evidence": "Directory could not be traversed; its contents were not inspected.",
        "Rule ID": "directory_traversal_error",
        "Verification Rationale": f"os.walk reported {type(exc).__name__} listing this directory.",
        "Confidence": "High",
        "Confidence Rationale": (
            "The traversal failure itself was directly observed; this is not "
            "an inference about the directory's contents."
        ),
        "Repeatable": False,
        "UID": None,
        "Owner Name": None,
        "GID": None,
        "Group Name": None,
        "Mode Octal": None,
        "Permissions": None,
        "ACL Present": None,
        "Unknowns": [
            "Encryption status of files beneath this directory cannot be "
            "established because the directory could not be traversed.",
        ],
        "Limitations": [f"{type(exc).__name__}: {exc.strerror or exc}"],
        "Collection Method": _COLLECTION_METHOD,
        "Collection Source": collection_source,
        "Collected At": collected_at,
    }


def _max_depth_limitation_record(
    dir_path: str, collected_at: datetime, collection_source: str, max_depth: int
) -> dict:
    """A Finding marking a directory that exists but was not descended into
    because it is beyond the configured scan depth boundary. Distinct from
    _directory_traversal_error_record: this is an intentional, deterministic
    configuration boundary, not a scanner error.
    """
    return {
        "Asset Type": "directory",
        "Location": dir_path,
        "Size": None,
        "Modified": None,
        "Encryption": None,
        "Evidence": (
            f"Directory was not inspected because it exceeds the configured "
            f"scan depth boundary (max_depth={max_depth})."
        ),
        "Rule ID": "max_depth_boundary",
        "Verification Rationale": (
            f"This directory's depth exceeds the configured max_depth={max_depth}."
        ),
        "Confidence": "High",
        "Confidence Rationale": (
            "The depth boundary is a configured scan parameter, directly "
            "known rather than inferred."
        ),
        "Repeatable": True,
        "UID": None,
        "Owner Name": None,
        "GID": None,
        "Group Name": None,
        "Mode Octal": None,
        "Permissions": None,
        "ACL Present": None,
        "Unknowns": [
            "Encryption status of files beneath this directory cannot be "
            "established because it was outside the configured scan depth boundary.",
        ],
        "Limitations": [
            f"Not inspected: scan depth boundary (max_depth={max_depth}) reached.",
        ],
        "Collection Method": _COLLECTION_METHOD,
        "Collection Source": collection_source,
        "Collected At": collected_at,
    }


def scan_filesystem_evidence(path: str, max_depth: int = 3) -> pd.DataFrame:
    """Hardened filesystem scan producing the full evidence record behind a
    trustworthy normalized Finding: provenance, confidence rationale,
    technical ownership signals, and unknowns distinct from limitations.

    Only regular files are inspected. Symlinks (including broken ones),
    FIFOs, sockets, and device files are skipped by design, not opened --
    opening a FIFO with no writer blocks indefinitely, and following a
    symlink can read data outside the intended scan root. A permission
    failure or a file that disappears mid-scan still produces a Finding with
    a limitation, rather than silently vanishing from the results.

    Coverage gaps are also reported explicitly rather than silently treated
    as "no findings": a directory os.walk cannot list at all produces a
    directory-level Finding with a limitation (see
    _directory_traversal_error_record), and a directory that exists but sits
    beyond max_depth produces a distinct directory-level Finding noting the
    configured boundary (see _max_depth_limitation_record). Neither
    fabricates file-level observations for what might be underneath.
    """
    records: list[dict] = []
    volume_status = _detect_volume_encryption(_volume_root(path))
    # Describes the scanned target, not the machine running the scan --
    # collection_source must not leak workstation identity, and the same
    # target scanned from two different machines should be recognizable as
    # the same source.
    collection_source = os.path.abspath(path)

    def _on_walk_error(exc: OSError) -> None:
        records.append(
            _directory_traversal_error_record(
                exc.filename or path, datetime.now(timezone.utc), collection_source, exc
            )
        )

    for root, dirs, files in os.walk(path, onerror=_on_walk_error, followlinks=False):
        depth = root.count(os.sep) - path.count(os.sep)

        if depth >= max_depth and dirs:
            for subdir in dirs:
                records.append(
                    _max_depth_limitation_record(
                        os.path.join(root, subdir),
                        datetime.now(timezone.utc),
                        collection_source,
                        max_depth,
                    )
                )
        if depth >= max_depth:
            dirs[:] = []
        if depth > max_depth:
            continue

        for name in files:
            full_path = os.path.join(root, name)
            collected_at = datetime.now(timezone.utc)
            try:
                lst = os.lstat(full_path)
            except PermissionError:
                records.append(
                    _degraded_record(
                        full_path,
                        collected_at,
                        collection_source,
                        f"Permission denied: unable to read metadata for {full_path}.",
                    )
                )
                continue
            except FileNotFoundError:
                records.append(
                    _degraded_record(
                        full_path,
                        collected_at,
                        collection_source,
                        "File became inaccessible before it could be inspected "
                        "(removed or replaced during the scan).",
                    )
                )
                continue
            except OSError as exc:
                records.append(
                    _degraded_record(
                        full_path,
                        collected_at,
                        collection_source,
                        f"Unable to read file metadata: {exc}",
                    )
                )
                continue

            if not stat.S_ISREG(lst.st_mode):
                # Symlink / FIFO / socket / device: not inspected by design.
                continue

            records.append(
                _observe_regular_file(
                    full_path, lst, volume_status, collected_at, collection_source
                )
            )

    return pd.DataFrame(records)
