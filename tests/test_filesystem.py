from scanner.filesystem import scan_filesystem


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
