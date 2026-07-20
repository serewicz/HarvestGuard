import subprocess
from unittest.mock import patch

from code_analysis.scanner import scan_source_for_crypto_usage


def test_scan_source_detects_weak_md5_hash(tmp_path):
    (tmp_path / "app.py").write_text(
        "import hashlib\n"
        "def h(x):\n"
        "    return hashlib.md5(x).hexdigest()\n"
    )

    df = scan_source_for_crypto_usage(str(tmp_path))

    assert len(df) == 1
    assert df.iloc[0]["Rule"] == "weak-hash-md5"
    assert df.iloc[0]["Risk"] == "High"
    assert "app.py:3" in df.iloc[0]["Location"]


def test_scan_source_detects_weak_cipher_des_and_ecb_mode(tmp_path):
    (tmp_path / "cipher.py").write_text(
        "from Crypto.Cipher import DES\n"
        "def enc(key):\n"
        "    return DES.new(key, DES.MODE_ECB)\n"
    )

    df = scan_source_for_crypto_usage(str(tmp_path))

    rules = set(df["Rule"])
    assert "weak-cipher-des" in rules
    assert "weak-cipher-ecb-mode" in rules
    assert (df["Risk"] == "High").all()


def test_scan_source_detects_weak_rsa_key_size(tmp_path):
    (tmp_path / "keys.py").write_text(
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "def gen():\n"
        "    return rsa.generate_private_key(public_exponent=65537, key_size=1024)\n"
    )

    df = scan_source_for_crypto_usage(str(tmp_path))

    assert len(df) == 1
    assert df.iloc[0]["Rule"] == "weak-rsa-key-size"
    assert df.iloc[0]["Risk"] == "Medium"


def test_scan_source_no_findings_on_modern_crypto(tmp_path):
    (tmp_path / "safe.py").write_text(
        "import hashlib\n"
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "def h(x):\n"
        "    return hashlib.sha256(x).hexdigest()\n"
        "def gen():\n"
        "    return rsa.generate_private_key(public_exponent=65537, key_size=4096)\n"
    )

    df = scan_source_for_crypto_usage(str(tmp_path))

    assert df.empty


def test_scan_source_empty_dir_returns_empty_dataframe(tmp_path):
    df = scan_source_for_crypto_usage(str(tmp_path))
    assert df.empty


@patch("code_analysis.scanner.subprocess.run")
def test_scan_source_handles_missing_semgrep_gracefully(mock_run, tmp_path):
    mock_run.side_effect = FileNotFoundError("semgrep not found")

    df = scan_source_for_crypto_usage(str(tmp_path))

    assert df.empty


@patch("code_analysis.scanner.subprocess.run")
def test_scan_source_handles_nonzero_exit_gracefully(mock_run, tmp_path):
    # With --quiet, semgrep exits 0 whether or not it found anything, so a
    # non-zero exit means the scan itself failed (e.g. a broken container
    # install), not that the code is clean.
    mock_run.return_value = subprocess.CompletedProcess(
        args=["semgrep"], returncode=1, stdout="", stderr="something went wrong"
    )

    df = scan_source_for_crypto_usage(str(tmp_path))

    assert df.empty


@patch("code_analysis.scanner.subprocess.run")
def test_scan_source_handles_timeout_gracefully(mock_run, tmp_path):
    mock_run.side_effect = subprocess.TimeoutExpired(cmd="semgrep", timeout=120)

    df = scan_source_for_crypto_usage(str(tmp_path))

    assert df.empty
