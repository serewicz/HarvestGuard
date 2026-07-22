"""Tests for the filesystem -> NormalizedFinding reference implementation.

scan_filesystem_evidence()/scan_filesystem_findings() are a separate, hardened
path from the legacy scan_filesystem() DataFrame used by the Streamlit
dashboard (tests/test_filesystem.py covers that path and is unaffected here).
"""

from __future__ import annotations

import json
import os
import stat
import sys

import pytest

import scanner.filesystem as fs_module
from findings import NormalizedFinding
from scanner.filesystem import scan_filesystem, scan_filesystem_evidence, scan_filesystem_findings

POSIX_ONLY = pytest.mark.skipif(sys.platform == "win32", reason="POSIX-specific behavior")
NOT_ROOT = pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0,
    reason="permission checks are bypassed when running as root",
)


@pytest.fixture(autouse=True)
def _stable_volume_status(monkeypatch):
    # Isolate these tests from the real machine's FileVault/LUKS/BitLocker
    # status so assertions don't depend on how the test host is configured.
    monkeypatch.setattr(fs_module, "_detect_volume_encryption", lambda mount: "Unencrypted")


# 1. A normal file produces a normalized Finding.
def test_normal_file_produces_finding(tmp_path):
    (tmp_path / "a.txt").write_text("hello")

    findings = scan_filesystem_findings(str(tmp_path))

    assert len(findings) == 1
    payload = findings[0].to_dict()
    assert payload["source_type"] == "local_filesystem"
    assert payload["asset_type"] == "file"
    assert payload["location"].endswith("a.txt")


# 2. Provenance is populated correctly.
def test_provenance_populated(tmp_path):
    (tmp_path / "a.txt").write_text("hello")

    payload = scan_filesystem_findings(str(tmp_path))[0].to_dict()

    assert payload["scanner_name"] == "filesystem"
    assert payload["scanner_version"]
    assert payload["collection_method"]
    assert payload["collection_source"]
    assert payload["rule_id"] in {
        "volume_status:unencrypted",
    } or payload["rule_id"].startswith("file_signature:")
    assert payload["repeatable"] in (True, False)
    assert payload["verification_rationale"]
    assert payload["observed_at"]  # collection timestamp, distinct from file mtime


# 3. Confidence has an evidence-quality rationale.
def test_confidence_has_rationale(tmp_path):
    (tmp_path / "a.txt").write_text("hello")

    payload = scan_filesystem_findings(str(tmp_path))[0].to_dict()

    assert payload["confidence"] in {"High", "Medium", "Low"}
    assert payload["confidence_rationale"]
    # Confidence must never smuggle in severity/priority/business language.
    for banned in ("priority", "remediat", "business", "severity"):
        assert banned not in payload["confidence_rationale"].lower()


# 4. UID/GID/owner/group/mode are captured where supported.
@POSIX_ONLY
def test_ownership_signals_captured(tmp_path):
    target = tmp_path / "a.txt"
    target.write_text("hello")
    st = os.stat(target)

    payload = scan_filesystem_findings(str(tmp_path))[0].to_dict()
    signals = payload["ownership_signals"]

    assert signals["uid"] == st.st_uid
    assert signals["gid"] == st.st_gid
    assert signals["mode_octal"] == format(stat.S_IMODE(st.st_mode), "04o")
    assert signals["permissions"] == stat.filemode(st.st_mode)
    # owner_name/group_name/acl_present may legitimately be None (recorded as
    # a limitation instead) but the keys must always be present.
    assert set(signals) == {
        "uid", "owner_name", "gid", "group_name", "mode_octal", "permissions", "acl_present",
    }


# 5. Unknowns and limitations remain distinct.
def test_unknowns_and_limitations_distinct(tmp_path):
    (tmp_path / "a.txt").write_text("hello")

    payload = scan_filesystem_findings(str(tmp_path))[0].to_dict()

    assert "Business ownership cannot be established from filesystem metadata." in payload[
        "unknowns"
    ]
    assert not (set(payload["unknowns"]) & set(payload["limitations"]))


# 6. Raw details preserve the original observation.
def test_raw_details_preserve_original_observation(tmp_path):
    target = tmp_path / "a.txt"
    target.write_text("hello world")
    st = os.stat(target)

    payload = scan_filesystem_findings(str(tmp_path))[0].to_dict()

    assert payload["technical_metadata"]["Size"] == st.st_size
    assert payload["technical_metadata"]["Encryption"] == "Unencrypted"


# 7. Stable Finding IDs remain stable across equivalent repeated scans.
def test_finding_id_stable_across_repeated_scans(tmp_path):
    (tmp_path / "a.txt").write_text("hello")

    first = scan_filesystem_findings(str(tmp_path))[0]
    second = scan_filesystem_findings(str(tmp_path))[0]

    # observed_at (collection time) is intentionally excluded from the hash
    # input in findings.py's _generate_id(), so the id stays stable even
    # though each scan runs at a different wall-clock moment.
    assert first.finding_id == second.finding_id


# 8. Permission failures become limitations rather than disappearing.
@POSIX_ONLY
@NOT_ROOT
def test_permission_denied_becomes_limitation_not_a_dropped_finding(tmp_path):
    target = tmp_path / "secret.txt"
    target.write_text("hello")
    target.chmod(0o000)
    try:
        findings = scan_filesystem_findings(str(tmp_path))
    finally:
        target.chmod(0o644)  # restore so tmp_path cleanup can remove it

    assert len(findings) == 1
    payload = findings[0].to_dict()
    assert payload["location"].endswith("secret.txt")
    assert any("permission denied" in item.lower() for item in payload["limitations"])
    assert payload["confidence"] == "Low"


# 9. Symlinks are not followed by default.
@POSIX_ONLY
def test_symlinks_are_not_followed(tmp_path):
    outside_secret = tmp_path.parent / f"{tmp_path.name}_outside_secret.txt"
    outside_secret.write_text("outside content that must not be read")
    try:
        scan_root = tmp_path / "root"
        scan_root.mkdir()
        (scan_root / "link.txt").symlink_to(outside_secret)

        findings = scan_filesystem_findings(str(scan_root))

        assert findings == []
    finally:
        outside_secret.unlink()


# 9b. A broken symlink must not crash the scan or produce a finding.
@POSIX_ONLY
def test_broken_symlink_is_skipped_without_crashing(tmp_path):
    (tmp_path / "dangling.txt").symlink_to(tmp_path / "does_not_exist.txt")
    (tmp_path / "real.txt").write_text("hello")

    findings = scan_filesystem_findings(str(tmp_path))

    assert [f.location for f in findings] == [str(tmp_path / "real.txt")]


# 10. Special files are not accidentally read as normal files.
@POSIX_ONLY
def test_fifo_is_not_opened_or_reported(tmp_path):
    fifo_path = tmp_path / "pipe"
    os.mkfifo(fifo_path)
    (tmp_path / "real.txt").write_text("hello")

    # If the scanner ever opened the FIFO for reading, this call would hang
    # indefinitely (no writer is attached) instead of returning.
    findings = scan_filesystem_findings(str(tmp_path))

    assert [f.location for f in findings] == [str(tmp_path / "real.txt")]


# 11. A disappearing/changing file is handled without corrupting the scan.
def test_file_disappearing_mid_scan_does_not_corrupt_other_results(tmp_path, monkeypatch):
    (tmp_path / "stable.txt").write_text("hello")
    vanished = tmp_path / "vanishes.txt"
    vanished.write_text("bye")

    real_lstat = os.lstat

    def flaky_lstat(path, *args, **kwargs):
        if os.fspath(path) == str(vanished):
            raise FileNotFoundError(str(vanished))
        return real_lstat(path, *args, **kwargs)

    monkeypatch.setattr(fs_module.os, "lstat", flaky_lstat)

    findings = scan_filesystem_findings(str(tmp_path))
    by_location = {f.location: f.to_dict() for f in findings}

    assert str(tmp_path / "stable.txt") in by_location
    # Platform-dependent limitations (e.g. ACL presence, unavailable on
    # macOS) may legitimately appear; what matters is that the vanished
    # file's failure doesn't leak onto the unrelated stable file.
    assert not any(
        "inaccessible" in item.lower()
        for item in by_location[str(tmp_path / "stable.txt")]["limitations"]
    )

    vanished_payload = by_location[str(vanished)]
    assert any("inaccessible" in item.lower() for item in vanished_payload["limitations"])
    assert vanished_payload["confidence"] == "Low"


def test_file_content_unreadable_mid_scan_becomes_a_limitation_not_a_crash(tmp_path, monkeypatch):
    (tmp_path / "a.txt").write_text("hello")

    monkeypatch.setattr(
        fs_module,
        "_detect_file_signature_safe",
        lambda path: (None, "File became inaccessible while reading its header."),
    )

    payload = scan_filesystem_findings(str(tmp_path))[0].to_dict()

    assert payload["confidence"] == "Low"
    assert any("inaccessible" in item.lower() for item in payload["limitations"])


# 12. Serialization is JSON-compatible.
def test_finding_serializes_to_json(tmp_path):
    (tmp_path / "a.txt").write_text("hello")

    payload = scan_filesystem_findings(str(tmp_path))[0].to_dict()

    json.dumps(payload)  # must not raise


# 13. Existing filesystem behavior remains compatible.
def test_legacy_scan_filesystem_dataframe_shape_is_unchanged(tmp_path):
    (tmp_path / "a.txt").write_text("hello")

    df = scan_filesystem(str(tmp_path), max_depth=3)

    assert {"Location", "Size", "Modified", "Encryption", "Owner", "Risk"}.issubset(df.columns)


def test_evidence_scan_and_legacy_scan_agree_on_which_files_are_visited(tmp_path):
    (tmp_path / "a.txt").write_text("hello")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b.txt").write_text("world")

    legacy_locations = set(scan_filesystem(str(tmp_path))["Location"])
    evidence_locations = set(scan_filesystem_evidence(str(tmp_path))["Location"])

    assert legacy_locations == evidence_locations


# Zero-length files and unusual filenames must not crash the scan.
def test_zero_length_and_unusual_filenames(tmp_path):
    (tmp_path / "empty.bin").write_bytes(b"")
    (tmp_path / "name with spaces & (parens) - üñïçødé.txt").write_text("hello")

    findings = scan_filesystem_findings(str(tmp_path))

    assert len(findings) == 2
    for finding in findings:
        json.dumps(finding.to_dict())


# --- Coverage limitations: unreadable directories and max_depth boundary ----


@POSIX_ONLY
@NOT_ROOT
def test_unreadable_directory_produces_directory_limitation_finding(tmp_path):
    (tmp_path / "visible.txt").write_text("hello")
    blocked = tmp_path / "blocked"
    blocked.mkdir()
    (blocked / "hidden.txt").write_text("secret")
    blocked.chmod(0o000)
    try:
        findings = scan_filesystem_findings(str(tmp_path))
    finally:
        blocked.chmod(0o755)

    by_location = {f.location: f.to_dict() for f in findings}

    assert str(tmp_path / "visible.txt") in by_location
    # No fabricated file-level finding for what might be inside the blocked dir.
    assert str(blocked / "hidden.txt") not in by_location

    dir_finding = by_location[str(blocked)]
    assert dir_finding["asset_type"] == "directory"
    assert dir_finding["rule_id"] == "directory_traversal_error"
    assert dir_finding["limitations"]
    assert dir_finding["confidence"] == "High"


def test_max_depth_boundary_produces_directory_limitation_finding(tmp_path):
    (tmp_path / "l1").mkdir()
    (tmp_path / "l1" / "shallow.txt").write_text("hello")
    deep = tmp_path / "l1" / "l2"
    deep.mkdir()
    (deep / "buried.txt").write_text("buried")

    findings = scan_filesystem_findings(str(tmp_path), max_depth=1)
    by_location = {f.location: f.to_dict() for f in findings}

    assert str(tmp_path / "l1" / "shallow.txt") in by_location
    # Not fabricated: buried.txt sits beyond the boundary and was never visited.
    assert str(deep / "buried.txt") not in by_location

    boundary_finding = by_location[str(deep)]
    assert boundary_finding["asset_type"] == "directory"
    assert boundary_finding["rule_id"] == "max_depth_boundary"
    assert boundary_finding["repeatable"] is True
    assert "max_depth" in boundary_finding["evidence"]


def test_directory_limitation_findings_use_the_existing_finding_model(tmp_path):
    deep = tmp_path / "l1" / "l2"
    deep.mkdir(parents=True)

    findings = scan_filesystem_findings(str(tmp_path), max_depth=1)
    dir_finding = next(f for f in findings if f.location == str(deep))

    # No parallel summary object -- it's a NormalizedFinding like any other.
    assert isinstance(dir_finding, NormalizedFinding)
    assert dir_finding.source_type == "local_filesystem"


# --- finding_id stability against real, changing filesystem state -----------


def test_finding_id_stable_when_mtime_touched(tmp_path):
    target = tmp_path / "a.txt"
    target.write_text("hello")

    first = scan_filesystem_findings(str(tmp_path))[0]
    st = target.stat()
    os.utime(target, (st.st_atime + 1000, st.st_mtime + 1000))
    second = scan_filesystem_findings(str(tmp_path))[0]

    assert first.technical_metadata["Modified"] != second.technical_metadata["Modified"]
    assert first.finding_id == second.finding_id


def test_finding_id_stable_when_size_changes_but_observation_unchanged(tmp_path):
    target = tmp_path / "a.txt"
    target.write_text("hello")
    first = scan_filesystem_findings(str(tmp_path))[0]

    target.write_text("hello, now with a lot more unremarkable plain-text content")
    second = scan_filesystem_findings(str(tmp_path))[0]

    assert first.technical_metadata["Size"] != second.technical_metadata["Size"]
    assert first.rule_id == second.rule_id  # same detection path both times
    assert first.finding_id == second.finding_id


@POSIX_ONLY
def test_finding_id_stable_when_mode_and_ownership_signals_change(tmp_path):
    target = tmp_path / "a.txt"
    target.write_text("hello")
    first = scan_filesystem_findings(str(tmp_path))[0]

    target.chmod(0o600)
    second = scan_filesystem_findings(str(tmp_path))[0]

    assert first.ownership_signals["mode_octal"] != second.ownership_signals["mode_octal"]
    assert first.finding_id == second.finding_id


def test_finding_id_differs_for_different_observations(tmp_path):
    (tmp_path / "plain.txt").write_text("hello")
    (tmp_path / "secret.enc").write_bytes(b"Salted__" + b"\x00" * 16)

    by_name = {f.asset_name: f for f in scan_filesystem_findings(str(tmp_path))}

    assert by_name["plain.txt"].rule_id != by_name["secret.enc"].rule_id
    assert by_name["plain.txt"].finding_id != by_name["secret.enc"].finding_id


def test_finding_id_differs_for_different_paths(tmp_path):
    (tmp_path / "a.txt").write_text("hello")
    (tmp_path / "b.txt").write_text("hello")

    ids = {f.finding_id for f in scan_filesystem_findings(str(tmp_path))}

    assert len(ids) == 2


# --- collection_source describes the scan target, not the scanning host -----


def test_collection_source_is_the_scan_target_not_the_hostname(tmp_path, monkeypatch):
    monkeypatch.setattr(fs_module.platform, "node", lambda: "some-workstation-hostname")
    (tmp_path / "a.txt").write_text("hello")

    payload = scan_filesystem_findings(str(tmp_path))[0].to_dict()

    assert payload["collection_source"] == os.path.abspath(str(tmp_path))
    assert "some-workstation-hostname" not in payload["collection_source"]


def test_collection_source_and_finding_id_are_stable_across_different_hosts(tmp_path, monkeypatch):
    (tmp_path / "a.txt").write_text("hello")

    monkeypatch.setattr(fs_module.platform, "node", lambda: "machine-one")
    first = scan_filesystem_findings(str(tmp_path))[0]

    monkeypatch.setattr(fs_module.platform, "node", lambda: "machine-two")
    second = scan_filesystem_findings(str(tmp_path))[0]

    assert first.collection_source == second.collection_source
    assert first.finding_id == second.finding_id
