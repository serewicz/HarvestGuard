"""Regression coverage for the aggregate filesystem context design (roadmap
HG-029, GitHub issue #65): ordinary files are represented by one aggregate
NormalizedFinding per mount instead of one record per file.

Complements tests/test_filesystem_findings.py, which covers per-file
evidence, coverage limitations, and skipped/inaccessible entries -- this file
is specifically about the aggregate-context mechanism itself: scale, mount
identity, Unknown-vs-Unencrypted, and ACL-limitation aggregation.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

import scanner.filesystem as fs_module
from scanner.filesystem import scan_filesystem_findings

ENCRYPTED_BYTES = b"Salted__" + b"\x00" * 16


@pytest.fixture(autouse=True)
def _stable_volume_status(monkeypatch):
    # Isolate these tests from the real machine's FileVault/LUKS/BitLocker
    # status so assertions don't depend on how the test host is configured.
    monkeypatch.setattr(fs_module, "_detect_volume_encryption", lambda mount: "Unencrypted")


def _context_findings(findings):
    return [f for f in findings if f.asset_type == "volume"]


def _file_findings(findings):
    return [f for f in findings if f.asset_type == "file"]


# --- Many ordinary files do not create one record per file -----------------


@pytest.mark.parametrize("file_count", [10, 300])
def test_many_ordinary_files_produce_exactly_one_aggregate_context_record(tmp_path, file_count):
    for i in range(file_count):
        (tmp_path / f"file_{i}.txt").write_text(f"ordinary content {i}")

    findings = scan_filesystem_findings(str(tmp_path))

    # Never one record per file, regardless of scale: always exactly one
    # aggregate context record for the single mount all of these files sit
    # on. This is the direct fix for the field evidence in Issue #65
    # (Files scanned: 20,091 / Total Findings: 20,632).
    assert len(findings) == 1
    assert _file_findings(findings) == []
    context = _context_findings(findings)[0]
    assert context.technical_metadata["Files Represented By This Context"] == file_count
    assert context.technical_metadata["Regular Files Inspected"] == file_count
    assert context.technical_metadata["Files With Individual Findings"] == 0


def test_record_count_does_not_scale_with_ordinary_file_count(tmp_path):
    # The record count for a purely-ordinary tree must be constant (one
    # aggregate context record) whether the tree has 10 files or 500 -- not
    # merely "fewer than one per file", which a badly chosen batching scheme
    # could still satisfy while still growing with N.
    small_dir = tmp_path / "small"
    large_dir = tmp_path / "large"
    small_dir.mkdir()
    large_dir.mkdir()
    for i in range(10):
        (small_dir / f"f{i}.txt").write_text("x")
    for i in range(500):
        (large_dir / f"f{i}.txt").write_text("x")

    small_findings = scan_filesystem_findings(str(small_dir))
    large_findings = scan_filesystem_findings(str(large_dir))

    assert len(small_findings) == len(large_findings) == 1


def test_ordinary_and_evidenced_files_coexist_on_one_mount(tmp_path):
    for i in range(20):
        (tmp_path / f"ordinary_{i}.txt").write_text("x")
    (tmp_path / "secret.enc").write_bytes(ENCRYPTED_BYTES)

    findings = scan_filesystem_findings(str(tmp_path))

    file_findings = _file_findings(findings)
    context_findings = _context_findings(findings)
    assert len(file_findings) == 1
    assert file_findings[0].location.endswith("secret.enc")
    assert len(context_findings) == 1
    context = context_findings[0]
    assert context.technical_metadata["Regular Files Inspected"] == 21
    assert context.technical_metadata["Files Represented By This Context"] == 20
    assert context.technical_metadata["Files With Individual Findings"] == 1


def test_no_aggregate_record_when_every_file_has_its_own_finding(tmp_path):
    # A mount where every inspected file already produced its own per-file
    # finding has nothing left for an aggregate record to represent, so none
    # is emitted for it.
    (tmp_path / "a.enc").write_bytes(ENCRYPTED_BYTES)
    (tmp_path / "b.enc").write_bytes(b"age-encryption.org/v1" + b"\x00" * 8)

    findings = scan_filesystem_findings(str(tmp_path))

    assert len(findings) == 2
    assert _context_findings(findings) == []


# --- Unknown volume status is never presented as observed Unencrypted -----


def test_unknown_volume_status_is_a_distinct_finding_from_unencrypted(tmp_path, monkeypatch):
    monkeypatch.setattr(fs_module, "_detect_volume_encryption", lambda mount: "Unknown")
    (tmp_path / "a.txt").write_text("hello")

    findings = scan_filesystem_findings(str(tmp_path))

    assert len(findings) == 1
    context = findings[0]
    assert context.technical_metadata["Encryption"] == "Unknown"
    assert context.rule_id == "volume_status:unknown"
    assert context.confidence == "Low"
    # The evidence text must not read as an observation that the volume is
    # unencrypted -- Unknown means undetermined, not "checked and clean".
    assert "not an observation" in context.evidence.lower() or (
        "could not be determined" in context.evidence.lower()
    )
    assert "unencrypted" not in context.evidence.lower().split("not")[0]


def test_unencrypted_volume_status_is_distinguishable_from_unknown(tmp_path, monkeypatch):
    monkeypatch.setattr(fs_module, "_detect_volume_encryption", lambda mount: "Unencrypted")
    (tmp_path / "a.txt").write_text("hello")

    findings = scan_filesystem_findings(str(tmp_path))

    context = findings[0]
    assert context.technical_metadata["Encryption"] == "Unencrypted"
    assert context.rule_id == "volume_status:unencrypted"
    assert context.confidence == "Medium"
    assert context.rule_id != "volume_status:unknown"


def test_encrypted_volume_status_is_recorded_distinctly(tmp_path, monkeypatch):
    monkeypatch.setattr(
        fs_module, "_detect_volume_encryption", lambda mount: "Volume-level (FileVault)"
    )
    (tmp_path / "a.txt").write_text("hello")

    findings = scan_filesystem_findings(str(tmp_path))

    context = findings[0]
    assert context.technical_metadata["Encryption"] == "Volume-level (FileVault)"
    assert context.rule_id == "volume_status:volume_level_filevault"
    assert context.confidence == "Medium"


# --- ACL limitation is aggregated once, not duplicated per file ------------


def test_acl_limitation_appears_once_regardless_of_file_count(tmp_path, monkeypatch):
    # Force the platform-wide "ACL support unavailable" condition regardless
    # of the host actually running this test, so the assertion below is
    # deterministic rather than host-dependent.
    monkeypatch.setattr(fs_module, "_acl_support_unavailable", lambda: True)
    for i in range(25):
        (tmp_path / f"file_{i}.txt").write_text("x")

    findings = scan_filesystem_findings(str(tmp_path))

    assert len(findings) == 1
    context = findings[0]
    acl_message = "ACL presence could not be portably determined on this platform."
    # Exactly one occurrence on the one aggregate record -- never one per
    # ordinary file, which is what made large scans unreadable.
    assert context.limitations.count(acl_message) == 1
    total_acl_mentions = sum(f.limitations.count(acl_message) for f in findings)
    assert total_acl_mentions == 1


def test_acl_limitation_absent_when_acl_support_is_available(tmp_path, monkeypatch):
    monkeypatch.setattr(fs_module, "_acl_support_unavailable", lambda: False)
    (tmp_path / "a.txt").write_text("hello")

    findings = scan_filesystem_findings(str(tmp_path))

    context = findings[0]
    acl_message = "ACL presence could not be portably determined on this platform."
    assert acl_message not in context.limitations


# --- Multiple mounts produce separate, stable aggregate context records ---


def _two_mount_tree(tmp_path):
    """A directory tree straddling two simulated mounts: mount_a/ and
    mount_b/ are each treated as their own mount by patching _volume_root to
    return the immediate scan subdirectory instead of walking up to the real
    filesystem mount (which would resolve both to the same real mount in a
    test sandbox)."""
    mount_a = tmp_path / "mount_a"
    mount_b = tmp_path / "mount_b"
    mount_a.mkdir()
    mount_b.mkdir()
    for i in range(5):
        (mount_a / f"a{i}.txt").write_text("x")
    for i in range(3):
        (mount_b / f"b{i}.txt").write_text("x")
    return mount_a, mount_b


def test_multiple_mounts_produce_separate_stable_context_records(tmp_path, monkeypatch):
    mount_a, mount_b = _two_mount_tree(tmp_path)

    def fake_volume_root(path):
        # Simulate mount_a/ and mount_b/ each being their own mount, rather
        # than resolving up to the real host mount both would otherwise
        # share in a test sandbox.
        if str(path).startswith(str(mount_a)):
            return str(mount_a)
        if str(path).startswith(str(mount_b)):
            return str(mount_b)
        return str(tmp_path)

    volume_statuses = {str(mount_a): "Unencrypted", str(mount_b): "Volume-level (FileVault)"}
    monkeypatch.setattr(fs_module, "_volume_root", fake_volume_root)
    monkeypatch.setattr(
        fs_module, "_detect_volume_encryption", lambda mount: volume_statuses[mount]
    )

    findings = scan_filesystem_findings(str(tmp_path))
    contexts = {f.location: f for f in _context_findings(findings)}

    assert len(contexts) == 2
    assert set(contexts) == {str(mount_a), str(mount_b)}
    assert contexts[str(mount_a)].technical_metadata["Encryption"] == "Unencrypted"
    assert contexts[str(mount_a)].technical_metadata["Files Represented By This Context"] == 5
    assert (
        contexts[str(mount_b)].technical_metadata["Encryption"] == "Volume-level (FileVault)"
    )
    assert contexts[str(mount_b)].technical_metadata["Files Represented By This Context"] == 3
    # Distinct, stable identities -- one per mount, never blurred together.
    assert contexts[str(mount_a)].identity_key != contexts[str(mount_b)].identity_key
    assert contexts[str(mount_a)].identity_key == f"mount:{mount_a}"
    assert contexts[str(mount_b)].identity_key == f"mount:{mount_b}"


# --- Stable identity: excludes timestamps, hostnames, PIDs, durations -----


def test_aggregate_identity_key_is_stable_across_repeated_scans(tmp_path):
    (tmp_path / "a.txt").write_text("hello")

    first = scan_filesystem_findings(str(tmp_path))[0]
    second = scan_filesystem_findings(str(tmp_path))[0]

    assert first.identity_key == second.identity_key
    assert first.finding_id == second.finding_id


def test_aggregate_identity_key_is_stable_across_different_hosts(tmp_path, monkeypatch):
    (tmp_path / "a.txt").write_text("hello")

    monkeypatch.setattr(fs_module.platform, "node", lambda: "machine-one")
    first = scan_filesystem_findings(str(tmp_path))[0]

    monkeypatch.setattr(fs_module.platform, "node", lambda: "machine-two")
    second = scan_filesystem_findings(str(tmp_path))[0]

    assert first.identity_key == second.identity_key
    assert "machine-one" not in first.identity_key
    assert "machine-two" not in second.identity_key


def test_aggregate_identity_key_excludes_volatile_details():
    # Direct check on the identity_key contract itself, independent of any
    # particular scan: it must be derivable from the mount point alone.
    from finding_adapters import FILESYSTEM_CONTEXT_ASSET_TYPE
    from scanner.filesystem import _volume_context_record

    record = _volume_context_record(
        mount_point="/data",
        volume_status="Unencrypted",
        files_inspected=5,
        files_represented=5,
        files_with_findings=0,
        collected_at=datetime.now(timezone.utc),
        collection_source="/data",
    )

    assert record["Identity Key"] == "mount:/data"
    assert record["Asset Type"] == FILESYSTEM_CONTEXT_ASSET_TYPE
    for volatile in ("pid", "hostname", "timestamp", "duration"):
        assert volatile not in record["Identity Key"].lower()
