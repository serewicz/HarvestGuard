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


# An ordinary readable file with no file-level signature and no file-specific
# failure produces no record of its own (see the aggregate-context design in
# scanner/filesystem.py and tests/test_filesystem_aggregate_context.py), so
# tests below that need a per-file record write a file carrying a real
# encrypted-format signature instead.
ENCRYPTED_BYTES = b"Salted__" + b"\x00" * 16


def _file_findings(findings):
    return [f for f in findings if f.asset_type == "file"]


def _context_findings(findings):
    return [f for f in findings if f.asset_type == "volume"]


# 1. A normal file is represented by aggregate mount context, not its own record.
def test_normal_file_produces_aggregate_context_not_a_per_file_finding(tmp_path):
    (tmp_path / "a.txt").write_text("hello")

    findings = scan_filesystem_findings(str(tmp_path))

    assert _file_findings(findings) == []
    assert len(findings) == 1
    payload = findings[0].to_dict()
    assert payload["source_type"] == "local_filesystem"
    assert payload["asset_type"] == "volume"
    assert payload["technical_metadata"]["Files Represented By This Context"] == 1


# 1b. A file with file-level evidence still produces its own record.
def test_file_level_signature_still_produces_a_per_file_finding(tmp_path):
    (tmp_path / "a.enc").write_bytes(ENCRYPTED_BYTES)

    findings = scan_filesystem_findings(str(tmp_path))

    assert len(findings) == 1
    payload = findings[0].to_dict()
    assert payload["source_type"] == "local_filesystem"
    assert payload["asset_type"] == "file"
    assert payload["location"].endswith("a.enc")
    assert payload["rule_id"] == "file_signature:file_level_openssl"


# 2. Provenance is populated correctly, on per-file and aggregate records alike.
def test_provenance_populated(tmp_path):
    (tmp_path / "a.txt").write_text("hello")
    (tmp_path / "a.enc").write_bytes(ENCRYPTED_BYTES)

    findings = scan_filesystem_findings(str(tmp_path))

    assert len(findings) == 2
    for payload in (f.to_dict() for f in findings):
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
    (tmp_path / "a.enc").write_bytes(ENCRYPTED_BYTES)

    findings = scan_filesystem_findings(str(tmp_path))

    assert len(findings) == 2
    for payload in (f.to_dict() for f in findings):
        assert payload["confidence"] in {"High", "Medium", "Low"}
        assert payload["confidence_rationale"]
        # Confidence must never smuggle in severity/priority/business language.
        for banned in ("priority", "remediat", "business", "severity"):
            assert banned not in payload["confidence_rationale"].lower()


# 4. UID/GID/owner/group/mode are captured where supported.
@POSIX_ONLY
def test_ownership_signals_captured(tmp_path):
    target = tmp_path / "a.enc"
    target.write_bytes(ENCRYPTED_BYTES)
    st = os.stat(target)

    payload = _file_findings(scan_filesystem_findings(str(tmp_path)))[0].to_dict()
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
    target = tmp_path / "a.enc"
    target.write_bytes(ENCRYPTED_BYTES)
    st = os.stat(target)
    (tmp_path / "ordinary.txt").write_text("hello world")

    findings = scan_filesystem_findings(str(tmp_path))

    file_metadata = _file_findings(findings)[0].to_dict()["technical_metadata"]
    assert file_metadata["Size"] == st.st_size
    assert file_metadata["Encryption"] == "File-level (OpenSSL)"
    # The volume status the ordinary file used to carry per file is preserved
    # once, on the aggregate context record.
    context_metadata = _context_findings(findings)[0].to_dict()["technical_metadata"]
    assert context_metadata["Encryption"] == "Unencrypted"


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


# 9. Symlinks are not followed, but the skip stays visible.
@POSIX_ONLY
def test_symlinks_are_not_followed(tmp_path):
    outside_secret = tmp_path.parent / f"{tmp_path.name}_outside_secret.txt"
    outside_secret.write_text("outside content that must not be read")
    try:
        scan_root = tmp_path / "root"
        scan_root.mkdir()
        (scan_root / "link.txt").symlink_to(outside_secret)

        findings = scan_filesystem_findings(str(scan_root))

        # The link is reported as an explicitly skipped asset -- never as an
        # inspected file, and never with evidence about the target's content.
        assert [f.location for f in findings] == [str(scan_root / "link.txt")]
        payload = findings[0].to_dict()
        assert payload["asset_type"] == "special_file"
        assert payload["rule_id"] == "skipped_special_file"
        assert payload["limitations"]
        assert payload["unknowns"]
        assert payload["technical_metadata"] == {}
        assert str(outside_secret) not in json.dumps(payload)
    finally:
        outside_secret.unlink()


# 9b. A broken symlink must not crash the scan, and must not be read as a file.
@POSIX_ONLY
def test_broken_symlink_is_skipped_without_crashing(tmp_path):
    (tmp_path / "dangling.txt").symlink_to(tmp_path / "does_not_exist.txt")
    (tmp_path / "real.enc").write_bytes(ENCRYPTED_BYTES)

    findings = scan_filesystem_findings(str(tmp_path))
    by_location = {f.location: f.to_dict() for f in findings}

    assert by_location[str(tmp_path / "real.enc")]["asset_type"] == "file"
    dangling = by_location[str(tmp_path / "dangling.txt")]
    assert dangling["asset_type"] == "special_file"
    assert dangling["rule_id"] == "skipped_special_file"


# 9c. A symlinked directory is not descended into, and the skip stays visible.
@POSIX_ONLY
def test_symlinked_directory_is_not_descended_into(tmp_path):
    real_dir = tmp_path / "real_dir"
    real_dir.mkdir()
    (real_dir / "inside.txt").write_text("hello")
    scan_root = tmp_path / "root"
    scan_root.mkdir()
    (scan_root / "link_dir").symlink_to(real_dir, target_is_directory=True)

    findings = scan_filesystem_findings(str(scan_root))
    by_location = {f.location: f.to_dict() for f in findings}

    # Nothing beneath the link was inspected, and nothing was fabricated.
    assert str(scan_root / "link_dir" / "inside.txt") not in by_location
    link_finding = by_location[str(scan_root / "link_dir")]
    assert link_finding["asset_type"] == "special_file"
    assert link_finding["rule_id"] == "skipped_special_file"
    assert link_finding["limitations"]


# 9d. A symlinked directory sitting exactly at the max-depth boundary must
# still be classified as a skipped special file, not shadowed by max-depth
# boundary classification -- regression test for the ordering bug where the
# depth>=max_depth branch reported every child of `dirs` as
# max_depth_boundary without checking whether the child was itself a
# symlink.
@POSIX_ONLY
def test_symlinked_directory_at_max_depth_boundary_stays_special_file(tmp_path):
    real_dir = tmp_path / "real_dir"
    real_dir.mkdir()
    (real_dir / "inside.txt").write_text("hello")
    scan_root = tmp_path / "root"
    (scan_root / "l1").mkdir(parents=True)
    (scan_root / "l1" / "link_dir").symlink_to(real_dir, target_is_directory=True)

    # max_depth=1: "l1" is at depth 1, so its children (including link_dir)
    # are evaluated in the depth>=max_depth branch that prunes and reports
    # max_depth_boundary findings -- exactly the code path the fix touches.
    findings = scan_filesystem_findings(str(scan_root), max_depth=1)
    by_location = {f.location: f.to_dict() for f in findings}

    link_path = str(scan_root / "l1" / "link_dir")
    assert link_path in by_location
    link_finding = by_location[link_path]
    assert link_finding["asset_type"] == "special_file"
    assert link_finding["rule_id"] == "skipped_special_file"
    # Reported exactly once -- never also as a max_depth_boundary directory.
    assert [f.location for f in findings].count(link_path) == 1
    assert not any(
        f.location == link_path and f.rule_id == "max_depth_boundary" for f in findings
    )
    # Nothing beneath the link was inspected, and nothing was fabricated.
    assert str(scan_root / "l1" / "link_dir" / "inside.txt") not in by_location


# 10. Special files are not accidentally read as normal files.
@POSIX_ONLY
def test_fifo_is_not_opened_or_reported(tmp_path):
    fifo_path = tmp_path / "pipe"
    os.mkfifo(fifo_path)
    (tmp_path / "real.enc").write_bytes(ENCRYPTED_BYTES)

    # If the scanner ever opened the FIFO for reading, this call would hang
    # indefinitely (no writer is attached) instead of returning.
    findings = scan_filesystem_findings(str(tmp_path))
    by_location = {f.location: f.to_dict() for f in findings}

    assert by_location[str(tmp_path / "real.enc")]["asset_type"] == "file"
    fifo_finding = by_location[str(fifo_path)]
    assert fifo_finding["asset_type"] == "special_file"
    assert fifo_finding["rule_id"] == "skipped_special_file"
    assert "FIFO" in fifo_finding["evidence"]
    # No encryption evidence is fabricated for something never opened.
    assert fifo_finding["technical_metadata"] == {}


# 11. A disappearing/changing file is handled without corrupting the scan.
def test_file_disappearing_mid_scan_does_not_corrupt_other_results(tmp_path, monkeypatch):
    # File-level evidence, not an ordinary file: it must survive as its own
    # finding so this test can verify the vanished file's failure doesn't
    # leak onto it specifically (an ordinary file would be absorbed into the
    # mount's aggregate context record instead, which isn't what this test
    # is about).
    (tmp_path / "stable.enc").write_bytes(ENCRYPTED_BYTES)
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

    assert str(tmp_path / "stable.enc") in by_location
    # Platform-dependent limitations (e.g. ACL presence, unavailable on
    # macOS) may legitimately appear; what matters is that the vanished
    # file's failure doesn't leak onto the unrelated stable file.
    assert not any(
        "inaccessible" in item.lower()
        for item in by_location[str(tmp_path / "stable.enc")]["limitations"]
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


# 11b. Inspected file content never reaches the finding.
def test_file_content_is_never_emitted_in_the_finding(tmp_path):
    # The scanner reads leading bytes for signature detection; none of that
    # content may survive into the evidence record.
    marker = "MARKER-VALUE-THAT-MUST-NOT-BE-EMITTED"
    (tmp_path / "a.txt").write_text(marker * 4)

    payload = scan_filesystem_findings(str(tmp_path))[0].to_dict()

    assert marker not in json.dumps(payload)


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
    # One ordinary file (absorbed into the aggregate context record) and one
    # file with real evidence (gets its own row), so both evidence-path
    # mechanisms are exercised in the same scan.
    ordinary = tmp_path / "a.txt"
    ordinary.write_text("hello")
    (tmp_path / "sub").mkdir()
    evidenced = tmp_path / "sub" / "b.enc"
    evidenced.write_bytes(ENCRYPTED_BYTES)

    legacy_locations = set(scan_filesystem(str(tmp_path))["Location"])
    evidence_df = scan_filesystem_evidence(str(tmp_path))
    # The legacy path has no equivalent of an aggregate mount/volume context
    # record -- it still emits one row per file, ordinary or not. On the
    # evidence path, a file with real evidence still gets its own "file" row,
    # but an ordinary file does not: it is represented by the mount's
    # aggregate "volume" context record instead (see
    # tests/test_filesystem_aggregate_context.py). Every location the legacy
    # scanner visited must therefore be accounted for by one of the two.
    file_locations = set(evidence_df.loc[evidence_df["Asset Type"] == "file", "Location"])
    context_rows = evidence_df[evidence_df["Asset Type"] == "volume"]

    assert file_locations == {str(evidenced)}
    assert legacy_locations - file_locations == {str(ordinary)}
    assert len(context_rows) == 1
    assert context_rows.iloc[0]["Files Represented By This Context"] == 1


# Zero-length files and unusual filenames must not crash the scan.
def test_zero_length_and_unusual_filenames(tmp_path):
    (tmp_path / "empty.bin").write_bytes(b"")
    (tmp_path / "name with spaces & (parens) - üñïçødé.txt").write_text("hello")

    findings = scan_filesystem_findings(str(tmp_path))

    # Both are ordinary files (no signature, no failure), so they are
    # represented by one aggregate context record rather than a finding
    # each -- the crash-safety property under test still holds: the scan
    # completes and the result serializes cleanly.
    assert len(findings) == 1
    assert findings[0].technical_metadata["Files Represented By This Context"] == 2
    for finding in findings:
        json.dumps(finding.to_dict())


# --- Coverage limitations: unreadable directories and max_depth boundary ----


@POSIX_ONLY
@NOT_ROOT
def test_unreadable_directory_produces_directory_limitation_finding(tmp_path):
    # File-level evidence, not an ordinary file: it must produce its own
    # finding so this test can verify the blocked directory doesn't swallow
    # or otherwise affect an unrelated sibling file's finding.
    (tmp_path / "visible.enc").write_bytes(ENCRYPTED_BYTES)
    blocked = tmp_path / "blocked"
    blocked.mkdir()
    (blocked / "hidden.txt").write_text("secret")
    blocked.chmod(0o000)
    try:
        findings = scan_filesystem_findings(str(tmp_path))
    finally:
        blocked.chmod(0o755)

    by_location = {f.location: f.to_dict() for f in findings}

    assert str(tmp_path / "visible.enc") in by_location
    # No fabricated file-level finding for what might be inside the blocked dir.
    assert str(blocked / "hidden.txt") not in by_location

    dir_finding = by_location[str(blocked)]
    assert dir_finding["asset_type"] == "directory"
    assert dir_finding["rule_id"] == "directory_traversal_error"
    assert dir_finding["limitations"]
    assert dir_finding["confidence"] == "High"


def test_max_depth_boundary_produces_directory_limitation_finding(tmp_path):
    (tmp_path / "l1").mkdir()
    # File-level evidence, not an ordinary file: it must produce its own
    # finding so this test can verify it, distinct from the max-depth
    # boundary finding, at the same directory level.
    (tmp_path / "l1" / "shallow.enc").write_bytes(ENCRYPTED_BYTES)
    deep = tmp_path / "l1" / "l2"
    deep.mkdir()
    (deep / "buried.txt").write_text("buried")

    findings = scan_filesystem_findings(str(tmp_path), max_depth=1)
    by_location = {f.location: f.to_dict() for f in findings}

    assert str(tmp_path / "l1" / "shallow.enc") in by_location
    # Not fabricated: buried.txt sits beyond the boundary and was never visited.
    assert str(deep / "buried.txt") not in by_location

    boundary_finding = by_location[str(deep)]
    assert boundary_finding["asset_type"] == "directory"
    assert boundary_finding["rule_id"] == "max_depth_boundary"
    assert boundary_finding["repeatable"] is True


def _depth_tree(root):
    """root/ (depth 0) -> l1/ (depth 1) -> l2/ (depth 2) -> l3/ (depth 3), each
    holding one regular file with real file-level evidence, so each still
    produces its own per-file finding under the aggregate-context design
    (an ordinary file with no signature is represented by its mount's
    aggregate context record instead, which these depth tests are not about)."""
    (root / "d0.txt").write_bytes(ENCRYPTED_BYTES)
    current = root
    for level in range(1, 4):
        current = current / f"l{level}"
        current.mkdir()
        (current / f"d{level}.txt").write_bytes(ENCRYPTED_BYTES)
    return root


def test_scan_root_is_depth_zero(tmp_path):
    # max_depth=0 permits files in the root itself and nothing below it: the
    # root is depth 0, so its child directories are already past the boundary.
    _depth_tree(tmp_path)

    findings = scan_filesystem_findings(str(tmp_path), max_depth=0)
    by_location = {f.location: f.to_dict() for f in findings}

    assert by_location[str(tmp_path / "d0.txt")]["asset_type"] == "file"
    assert str(tmp_path / "l1" / "d1.txt") not in by_location
    assert by_location[str(tmp_path / "l1")]["rule_id"] == "max_depth_boundary"


def test_files_in_directories_at_max_depth_are_inspected(tmp_path):
    # max_depth=2 permits files in directories at depth 2 (root/l1/l2), and
    # stops at the depth-3 directory below it.
    _depth_tree(tmp_path)

    findings = scan_filesystem_findings(str(tmp_path), max_depth=2)
    by_location = {f.location: f.to_dict() for f in findings}

    for level, location in enumerate(
        [
            tmp_path / "d0.txt",
            tmp_path / "l1" / "d1.txt",
            tmp_path / "l1" / "l2" / "d2.txt",
        ]
    ):
        assert by_location[str(location)]["asset_type"] == "file", level
    assert str(tmp_path / "l1" / "l2" / "l3" / "d3.txt") not in by_location
    assert by_location[str(tmp_path / "l1" / "l2" / "l3")]["rule_id"] == "max_depth_boundary"


def test_directories_below_max_depth_are_pruned_before_descent(tmp_path, monkeypatch):
    # Pruning must happen before descent, not by filtering results afterwards:
    # nothing beneath the boundary should be listed or stat'd at all.
    _depth_tree(tmp_path)
    beyond = tmp_path / "l1" / "l2"
    inspected: list[str] = []
    real_lstat = os.lstat

    def recording_lstat(path, *args, **kwargs):
        inspected.append(os.fspath(path))
        return real_lstat(path, *args, **kwargs)

    monkeypatch.setattr(fs_module.os, "lstat", recording_lstat)

    findings = scan_filesystem_findings(str(tmp_path), max_depth=1)
    locations = {f.location for f in findings}

    assert not any(path.startswith(str(beyond) + os.sep) for path in inspected)
    # The boundary directory itself is reported once; the directory below it is
    # never even discovered, so no second boundary finding is emitted for it.
    assert str(beyond) in locations
    assert str(beyond / "l3") not in locations


def test_trailing_separator_on_root_does_not_shift_depth(tmp_path):
    # "/data/" and "/data" describe the same scan root, so they must produce
    # the same depth boundary rather than silently scanning a level deeper.
    _depth_tree(tmp_path)

    without = {f.location for f in scan_filesystem_findings(str(tmp_path), max_depth=1)}
    with_sep = {
        f.location for f in scan_filesystem_findings(str(tmp_path) + os.sep, max_depth=1)
    }

    assert without == with_sep


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
    # File-level evidence, not an ordinary file: an ordinary file's mtime
    # isn't tracked at all on the aggregate context record that represents
    # it, so this per-finding mtime-stability property needs its own record.
    target = tmp_path / "a.enc"
    target.write_bytes(ENCRYPTED_BYTES)

    first = scan_filesystem_findings(str(tmp_path))[0]
    st = target.stat()
    os.utime(target, (st.st_atime + 1000, st.st_mtime + 1000))
    second = scan_filesystem_findings(str(tmp_path))[0]

    assert first.technical_metadata["Modified"] != second.technical_metadata["Modified"]
    assert first.finding_id == second.finding_id


def test_finding_id_stable_when_size_changes_but_observation_unchanged(tmp_path):
    target = tmp_path / "a.enc"
    target.write_bytes(ENCRYPTED_BYTES)
    first = scan_filesystem_findings(str(tmp_path))[0]

    target.write_bytes(ENCRYPTED_BYTES + b"padding to change size without changing the signature")
    second = scan_filesystem_findings(str(tmp_path))[0]

    assert first.technical_metadata["Size"] != second.technical_metadata["Size"]
    assert first.rule_id == second.rule_id  # same detection path both times
    assert first.finding_id == second.finding_id


@POSIX_ONLY
def test_finding_id_stable_when_mode_and_ownership_signals_change(tmp_path):
    target = tmp_path / "a.enc"
    target.write_bytes(ENCRYPTED_BYTES)
    first = scan_filesystem_findings(str(tmp_path))[0]

    target.chmod(0o600)
    second = scan_filesystem_findings(str(tmp_path))[0]

    assert first.ownership_signals["mode_octal"] != second.ownership_signals["mode_octal"]
    assert first.finding_id == second.finding_id


def test_finding_id_differs_for_different_observations(tmp_path):
    # Two genuinely different per-file observations: an ordinary file would
    # produce no finding of its own at all (see
    # tests/test_filesystem_aggregate_context.py), so this needs two
    # distinct real signatures rather than "plain vs. encrypted".
    (tmp_path / "openssl.enc").write_bytes(b"Salted__" + b"\x00" * 16)
    (tmp_path / "age.enc").write_bytes(b"age-encryption.org/v1" + b"\x00" * 8)

    by_name = {f.asset_name: f for f in scan_filesystem_findings(str(tmp_path))}

    assert by_name["openssl.enc"].rule_id != by_name["age.enc"].rule_id
    assert by_name["openssl.enc"].finding_id != by_name["age.enc"].finding_id


def test_finding_id_differs_for_different_paths(tmp_path):
    # File-level evidence, not ordinary files: two ordinary files at
    # different paths would both be represented by the same single
    # aggregate context record (see
    # tests/test_filesystem_aggregate_context.py), so this per-file-path
    # property needs its own per-file records.
    (tmp_path / "a.enc").write_bytes(ENCRYPTED_BYTES)
    (tmp_path / "b.enc").write_bytes(ENCRYPTED_BYTES)

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
