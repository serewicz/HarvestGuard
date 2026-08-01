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

from finding_adapters import (
    FILESYSTEM_CONTEXT_ASSET_TYPE,
    FILESYSTEM_FILES_INSPECTED_KEY,
    FILESYSTEM_FILES_REPRESENTED_KEY,
    FILESYSTEM_FILES_WITH_FINDINGS_KEY,
    normalize_filesystem_df,
)
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
    # Only the MESSAGE armor, not a bare "-----BEGIN PGP" prefix: a PGP
    # SIGNATURE, SIGNED MESSAGE, PUBLIC KEY BLOCK, or PRIVATE KEY BLOCK is
    # not encrypted data, and reporting a fully readable signed cleartext
    # file as "File-level (PGP/GPG)" with High confidence claimed protection
    # that isn't there. See docs/DETECTION_CHARACTERIZATION.md -- MESSAGE
    # armor is also used for signed-only/compressed-only messages, so a
    # narrower residual false positive remains and is documented there.
    (b"-----BEGIN PGP MESSAGE", "File-level (PGP/GPG)"),
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


def _acl_support_unavailable() -> bool:
    """Whether ACL presence cannot be determined at all on this platform.

    A platform-wide fact, deliberately separate from _detect_acl_presence()'s
    per-file answer: it is recorded once on the aggregate mount context (see
    _volume_context_record) instead of being repeated as a limitation on every
    ordinary file, which is what made large scans unreadable.
    """
    return platform.system() != "Linux" or not hasattr(os, "listxattr")


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
) -> dict | None:
    """Evidence record for one regular file, or None when the file has nothing
    file-specific to report.

    None means: the file was readable, no known encrypted-format signature
    matched, and nothing about this specific file failed. Its only evidence
    would be the volume/filesystem/platform context it shares with every other
    such file on the same mount, which is recorded once per mount instead (see
    _volume_context_record). Emitting one record per ordinary file made a
    20,000-file scan report ~20,000 "findings" that were all the same
    volume-level context statement.
    """
    signature, read_limitation = _detect_file_signature_safe(full_path)
    if signature is None and read_limitation is None:
        # Ordinary readable file, no file-level evidence, no file-specific
        # failure: represented by its mount's aggregate context record. The
        # owner/group/ACL lookups below are skipped entirely, not just
        # discarded.
        return None

    unknowns = ["Business ownership cannot be established from filesystem metadata."]
    limitations: list[str] = []

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
    else:
        # signature is not None: the only other way to reach this point.
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


def _volume_context_record(
    mount_point: str,
    volume_status: str,
    files_inspected: int,
    files_represented: int,
    files_with_findings: int,
    collected_at: datetime,
    collection_source: str,
) -> dict:
    """One aggregate record for the filesystem/volume/platform context shared
    by every ordinary regular file inspected on a single mount.

    This is what ordinary per-file records are replaced by, not a summary
    layered on top of them: the context is observed once per mount, so it is
    recorded once per mount. Identity comes from the mount point path alone --
    never a timestamp, hostname, process id, scan duration, or any per-file
    ownership/ACL value -- so the same mount yields the same identity across
    runs and hosts, while two mounts scanned in one run stay distinct.

    "Unknown" and "Unencrypted" volume status are deliberately kept apart
    here: the first means the platform/tooling could not determine the status,
    the second means it determined the volume is not encrypted. They carry
    different rule_ids, different evidence text, and different confidence, and
    are never presented under one label.
    """
    unknowns = [
        "Business ownership cannot be established from filesystem metadata.",
        "File-level encryption status cannot be established conclusively for the "
        "regular files this aggregate context represents.",
        "Per-file ownership, permission, and ACL signals are not established by "
        "this aggregate context finding; it describes the mount, not any "
        "individual file on it.",
    ]
    # Platform-wide gaps, recorded once here rather than once per ordinary
    # file. Genuinely per-file failures still produce their own record.
    limitations: list[str] = []
    if pwd is None:
        limitations.append("Owner name resolution is unavailable on this platform.")
    if grp is None:
        limitations.append("Group name resolution is unavailable on this platform.")
    if _acl_support_unavailable():
        limitations.append("ACL presence could not be portably determined on this platform.")

    represented = (
        f"{files_represented} regular file(s) with no file-level encrypted-format "
        "signature and no file-specific failure are represented by this record "
        "rather than by individual records"
    )
    if volume_status == "Unknown":
        evidence = (
            f"Volume-level encryption status could not be determined for mount "
            f"{mount_point}; it is recorded as Unknown, which is not an observation "
            f"that the volume is unencrypted. {represented}."
        )
        verification_rationale = (
            "Volume-level encryption status could not be determined on this "
            "platform (unsupported platform, or the required tool was "
            "unavailable, failed, or timed out), so no volume-level status was "
            "observed for this mount."
        )
        confidence = "Low"
        confidence_rationale = (
            "Neither file-level nor volume-level encryption status could be "
            "established for the files this context represents."
        )
        repeatable = False
    else:
        observed = (
            "the platform reported the volume is not encrypted"
            if volume_status == "Unencrypted"
            else "the platform reported volume-level encryption"
        )
        evidence = (
            f"Volume-level encryption status observed for mount {mount_point}: "
            f"{volume_status} ({observed}). {represented}."
        )
        verification_rationale = (
            f"Volume-level encryption status was determined once for mount "
            f"{mount_point} and applies to every regular file inspected on it; "
            "no file-level signature matched for the files it represents."
        )
        confidence = "Medium"
        confidence_rationale = (
            "Volume-level status describes the mount as a whole rather than any "
            "individual file on it, so file-level status remains unverified for "
            "the files this context represents."
        )
        repeatable = True

    return {
        "Asset Type": FILESYSTEM_CONTEXT_ASSET_TYPE,
        "Location": mount_point,
        "Encryption": volume_status,
        "Evidence": evidence,
        "Rule ID": f"volume_status:{_slug(volume_status)}",
        "Verification Rationale": verification_rationale,
        "Confidence": confidence,
        "Confidence Rationale": confidence_rationale,
        "Repeatable": repeatable,
        "Unknowns": unknowns,
        "Limitations": limitations,
        "Collection Method": _COLLECTION_METHOD,
        "Collection Source": collection_source,
        "Collected At": collected_at,
        # Identity of the mount this context describes, deliberately derived
        # from the mount point alone (see this function's docstring).
        "Identity Key": f"mount:{mount_point}",
        "Mount Point": mount_point,
        "Platform": platform.system(),
        FILESYSTEM_FILES_INSPECTED_KEY: files_inspected,
        FILESYSTEM_FILES_REPRESENTED_KEY: files_represented,
        FILESYSTEM_FILES_WITH_FINDINGS_KEY: files_with_findings,
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


def _special_entry_kind(mode: int) -> str:
    """Human-readable kind for a non-regular directory entry."""
    if stat.S_ISLNK(mode):
        return "symbolic link"
    if stat.S_ISDIR(mode):
        return "directory"
    if stat.S_ISFIFO(mode):
        return "FIFO (named pipe)"
    if stat.S_ISSOCK(mode):
        return "socket"
    if stat.S_ISBLK(mode):
        return "block device"
    if stat.S_ISCHR(mode):
        return "character device"
    return "special file"


def _skipped_special_file_record(
    full_path: str, kind: str, collected_at: datetime, collection_source: str
) -> dict:
    """A Finding for a directory entry that exists but was intentionally not
    followed or opened: a symlink, FIFO, socket, or device file.

    These are skipped for safety (see scan_filesystem_evidence), but skipping
    them silently would make an inspected-and-clean asset indistinguishable
    from one that was never looked at. The entry is therefore reported as an
    explicit skipped-asset limitation with no file-content evidence attached.
    """
    return {
        "Asset Type": "special_file",
        "Location": full_path,
        "Size": None,
        "Modified": None,
        "Encryption": None,
        "Evidence": (
            f"Entry was identified as a {kind} and was not followed or opened, "
            "so its encryption status was not inspected."
        ),
        "Rule ID": "skipped_special_file",
        "Verification Rationale": (
            f"os.lstat identified this entry as a {kind} rather than a regular file."
        ),
        "Confidence": "High",
        "Confidence Rationale": (
            "The entry type was directly observed via lstat; the skip is a "
            "deterministic safety rule, not an inference about content."
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
            "Encryption status of this entry, and of whatever it refers to, "
            "cannot be established because it was not followed or opened.",
        ],
        "Limitations": [
            f"Not inspected: {kind} skipped for safety by the normalized "
            "filesystem evidence path.",
        ],
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
    symlink can read data outside the intended scan root. They are still
    reported, as explicit skipped-asset limitation Findings (see
    _skipped_special_file_record), so "not inspected" is never presented as
    "inspected and nothing found". A permission failure or a file that
    disappears mid-scan likewise still produces a Finding with a limitation,
    rather than silently vanishing from the results.

    Coverage gaps are also reported explicitly rather than silently treated
    as "no findings": a directory os.walk cannot list at all produces a
    directory-level Finding with a limitation (see
    _directory_traversal_error_record), and a directory that exists but sits
    beyond max_depth produces a distinct directory-level Finding noting the
    configured boundary (see _max_depth_limitation_record). Neither
    fabricates file-level observations for what might be underneath.

    An ordinary readable regular file with no file-level signature match and
    no file-specific failure produces no record of its own. The only evidence
    such a file has is the volume/filesystem/platform context it shares with
    every other ordinary file on the same mount, so that context is recorded
    once per mount as an aggregate record instead (see
    _volume_context_record). Mount points are resolved per directory, so two
    mounts reached in one scan produce two distinct aggregate records rather
    than one blurred together.

    Depth semantics: the scan root is depth 0, a direct child directory of
    the root is depth 1, and ``max_depth=N`` inspects files in directories up
    to and including depth N. Child directories below depth N are pruned
    before descent, so nothing beneath them is opened or stat'd.
    """
    records: list[dict] = []
    # Per-mount tally driving the aggregate context records emitted at the end
    # of the scan: mount point -> volume status and inspected-file counts.
    contexts: dict[str, dict] = {}
    mounts: dict[str, str] = {}

    def _context_for(directory: str) -> dict:
        mount = mounts.get(directory)
        if mount is None:
            mount = _volume_root(directory)
            mounts[directory] = mount
        context = contexts.get(mount)
        if context is None:
            context = {
                "volume_status": _detect_volume_encryption(mount),
                "inspected": 0,
                "represented": 0,
                "with_findings": 0,
            }
            contexts[mount] = context
        return context

    # Depth is measured against the *normalized* root so that a trailing
    # separator ("/data/" vs "/data") cannot shift every depth by one and
    # silently scan a level deeper or shallower than requested.
    root_separators = os.path.normpath(path).count(os.sep)
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
        depth = os.path.normpath(root).count(os.sep) - root_separators

        # Symlinked directories are never descended into (followlinks=False)
        # regardless of depth, and are always reported as skipped special
        # files -- checked before the max-depth branch below so a symlinked
        # directory's classification can never be shadowed by max-depth
        # boundary logic, even when it sits exactly at or beyond the
        # boundary. Each is reported exactly once, here.
        symlinked_dirs = {
            subdir for subdir in dirs if os.path.islink(os.path.join(root, subdir))
        }
        for subdir in symlinked_dirs:
            records.append(
                _skipped_special_file_record(
                    os.path.join(root, subdir),
                    "symbolic link to a directory",
                    datetime.now(timezone.utc),
                    collection_source,
                )
            )

        if depth >= max_depth:
            # Pruned before descent: os.walk consults `dirs` in place, so
            # clearing it here means nothing beneath the boundary is listed,
            # stat'd, or opened at all. The boundary itself is reported per
            # non-symlink child directory so the un-inspected scope stays
            # visible; symlinked directories were already reported above and
            # must not also get a max_depth_boundary finding.
            for subdir in dirs:
                if subdir in symlinked_dirs:
                    continue
                records.append(
                    _max_depth_limitation_record(
                        os.path.join(root, subdir),
                        datetime.now(timezone.utc),
                        collection_source,
                        max_depth,
                    )
                )
            dirs[:] = []
        elif symlinked_dirs:
            dirs[:] = [subdir for subdir in dirs if subdir not in symlinked_dirs]

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
                # Symlink / FIFO / socket / device: not followed or opened by
                # design, but still reported as an explicit skipped asset so
                # the gap in coverage stays visible.
                records.append(
                    _skipped_special_file_record(
                        full_path,
                        _special_entry_kind(lst.st_mode),
                        collected_at,
                        collection_source,
                    )
                )
                continue

            context = _context_for(root)
            context["inspected"] += 1
            record = _observe_regular_file(
                full_path, lst, context["volume_status"], collected_at, collection_source
            )
            if record is None:
                # Ordinary file: its mount's aggregate context record stands
                # for it, so no per-file record is emitted at all.
                context["represented"] += 1
            else:
                context["with_findings"] += 1
                records.append(record)

    # One aggregate context record per mount that actually had ordinary files
    # to represent. A mount whose every inspected file produced its own record
    # has nothing left for an aggregate to stand in for, so none is emitted.
    for mount_point, context in sorted(contexts.items()):
        if not context["represented"]:
            continue
        records.append(
            _volume_context_record(
                mount_point,
                context["volume_status"],
                context["inspected"],
                context["represented"],
                context["with_findings"],
                datetime.now(timezone.utc),
                collection_source,
            )
        )

    return pd.DataFrame(records)
