import scanner.filesystem as fs_module
from scanner.filesystem import _detect_file_signature, scan_filesystem


def test_scan_filesystem_finds_files(tmp_path):
    (tmp_path / "a.txt").write_text("hello")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b.txt").write_text("world")

    df = scan_filesystem(str(tmp_path), max_depth=3)

    assert not df.empty
    assert set(df["Location"].apply(lambda p: p.split("/")[-1])) == {"a.txt", "b.txt"}
    assert {"Location", "Size", "Modified", "Encryption", "Owner", "Risk"}.issubset(df.columns)


def test_scan_filesystem_respects_max_depth(tmp_path):
    (tmp_path / "top.txt").write_text("top")
    deep = tmp_path / "l1" / "l2" / "l3" / "l4"
    deep.mkdir(parents=True)
    (deep / "buried.txt").write_text("buried")

    df = scan_filesystem(str(tmp_path), max_depth=1)

    names = set(df["Location"].apply(lambda p: p.split("/")[-1]))
    assert "top.txt" in names
    assert "buried.txt" not in names


def test_scan_filesystem_empty_dir_returns_empty_dataframe(tmp_path):
    df = scan_filesystem(str(tmp_path))
    assert df.empty


def test_detect_file_signature_openssl(tmp_path):
    f = tmp_path / "secrets.enc"
    f.write_bytes(b"Salted__" + b"\x00" * 16 + b"ciphertext")
    assert _detect_file_signature(str(f)) == "File-level (OpenSSL)"


def test_detect_file_signature_pgp_armor(tmp_path):
    f = tmp_path / "message.asc"
    f.write_bytes(b"-----BEGIN PGP MESSAGE-----\nversion 1\n")
    assert _detect_file_signature(str(f)) == "File-level (PGP/GPG)"


def test_detect_file_signature_encrypted_zip(tmp_path):
    f = tmp_path / "archive.zip"
    # Local file header with general-purpose bit flag bit 0 (encrypted) set.
    f.write_bytes(b"PK\x03\x04\x14\x00\x01\x00" + b"\x00" * 16)
    assert _detect_file_signature(str(f)) == "File-level (Encrypted ZIP)"


def test_detect_file_signature_plaintext_returns_none(tmp_path):
    f = tmp_path / "notes.txt"
    f.write_text("just some plain text")
    assert _detect_file_signature(str(f)) is None


def test_scan_filesystem_falls_back_to_volume_status(tmp_path, monkeypatch):
    monkeypatch.setattr(
        fs_module, "_detect_volume_encryption", lambda mount: "Volume-level (FileVault)"
    )
    (tmp_path / "plain.txt").write_text("hello")

    df = scan_filesystem(str(tmp_path))

    assert df.iloc[0]["Encryption"] == "Volume-level (FileVault)"
    assert df.iloc[0]["Risk"] == "Low"


def test_scan_filesystem_flags_unencrypted_volume_as_high_risk(tmp_path, monkeypatch):
    monkeypatch.setattr(fs_module, "_detect_volume_encryption", lambda mount: "Unencrypted")
    (tmp_path / "plain.txt").write_text("hello")

    df = scan_filesystem(str(tmp_path))

    assert df.iloc[0]["Encryption"] == "Unencrypted"
    assert df.iloc[0]["Risk"] == "High"


def test_scan_filesystem_file_signature_takes_precedence_over_volume(tmp_path, monkeypatch):
    monkeypatch.setattr(fs_module, "_detect_volume_encryption", lambda mount: "Unencrypted")
    (tmp_path / "secrets.enc").write_bytes(b"Salted__" + b"\x00" * 16)

    df = scan_filesystem(str(tmp_path))

    assert df.iloc[0]["Encryption"] == "File-level (OpenSSL)"
    assert df.iloc[0]["Risk"] == "Low"
