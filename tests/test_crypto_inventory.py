from __future__ import annotations

from pathlib import Path

from scanner.crypto_inventory import scan_crypto_inventory

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "crypto_inventory"


def _by_name(df):
    return df.set_index(df["Location"].apply(lambda p: Path(p).name), drop=False)


def test_scan_crypto_inventory_detects_certificate_assets():
    df = scan_crypto_inventory(str(FIXTURE_DIR))
    by_name = _by_name(df)

    rsa_cert = by_name.loc["rsa_cert.pem"]
    assert rsa_cert["Asset Type"] == "PEM Certificate"
    assert rsa_cert["Algorithm"] == "RSA"
    assert rsa_cert["Key Size"] == 2048
    assert rsa_cert["Signature Algorithm"] == "sha256"
    assert "CN=rsa.harvestguard.test" in rsa_cert["Subject"]
    assert "CN=rsa.harvestguard.test" in rsa_cert["Issuer"]
    assert rsa_cert["Expiration"].startswith("2027-01-01")
    assert len(rsa_cert["Fingerprint"]) == 64
    assert rsa_cert["Confidence"] == "High"

    ecc_cert = by_name.loc["ecc_cert.pem"]
    assert ecc_cert["Asset Type"] == "PEM Certificate"
    assert ecc_cert["Algorithm"] == "EC (secp256r1)"
    assert ecc_cert["Key Size"] == 256


def test_scan_crypto_inventory_detects_der_and_expired_certificates():
    df = scan_crypto_inventory(str(FIXTURE_DIR))
    by_name = _by_name(df)

    der_cert = by_name.loc["rsa_cert.der"]
    assert der_cert["Asset Type"] == "DER Certificate"
    assert der_cert["Algorithm"] == "RSA"
    assert der_cert["Key Size"] == 2048

    expired_cert = by_name.loc["expired_cert.pem"]
    assert expired_cert["Asset Type"] == "PEM Certificate"
    assert expired_cert["Expiration"].startswith("2024-11-27")


def test_scan_crypto_inventory_detects_private_keys_and_encryption():
    df = scan_crypto_inventory(str(FIXTURE_DIR))
    by_name = _by_name(df)

    key = by_name.loc["valid_key.pem"]
    assert key["Asset Type"] == "PEM Private Key"
    assert key["Algorithm"] == "RSA"
    assert key["Key Size"] == 2048
    assert key["Confidence"] == "High"

    encrypted = by_name.loc["encrypted_key.pem"]
    assert encrypted["Asset Type"] == "Encrypted PEM Private Key"
    assert encrypted["Evidence"] == "Encrypted PEM block BEGIN ENCRYPTED PRIVATE KEY"
    assert encrypted["Confidence"] == "High"
    assert "requires a passphrase" in encrypted["Errors"]


def test_scan_crypto_inventory_detects_ssh_assets():
    df = scan_crypto_inventory(str(FIXTURE_DIR))
    by_name = _by_name(df)

    private_key = by_name.loc["ssh_key"]
    assert private_key["Asset Type"] == "OpenSSH Private Key"
    assert private_key["Algorithm"] == "Ed25519"
    assert private_key["Key Size"] == 256

    public_key = by_name.loc["ssh_key.pub"]
    assert public_key["Asset Type"] == "OpenSSH Public Key"
    assert public_key["Algorithm"] == "Ed25519"
    assert public_key["Key Size"] == 256


def test_scan_crypto_inventory_detects_pkcs12_and_jks_assets():
    df = scan_crypto_inventory(str(FIXTURE_DIR))
    by_name = _by_name(df)

    pkcs12_rows = df[df["Location"].apply(lambda p: Path(p).name) == "bundle.p12"]
    assert set(pkcs12_rows["Asset Type"]) == {"PKCS#12 Certificate", "PKCS#12 Private Key"}
    assert "RSA" in set(pkcs12_rows["Algorithm"])
    assert "EC (secp256r1)" in set(pkcs12_rows["Algorithm"])

    jks = by_name.loc["sample.jks"]
    assert jks["Asset Type"] == "Java Keystore"
    assert jks["Confidence"] == "Medium"
    assert "not implemented" in jks["Errors"]


def test_scan_crypto_inventory_handles_malformed_and_random_files():
    df = scan_crypto_inventory(str(FIXTURE_DIR))
    by_name = _by_name(df)

    malformed = by_name.loc["malformed_cert.pem"]
    assert malformed["Asset Type"] == "Malformed PEM Certificate"
    assert malformed["Confidence"] == "Low"
    assert malformed["Errors"]

    assert "random.bin" not in set(by_name.index)


def test_scan_crypto_inventory_supports_exclusions_and_symlink_safety(tmp_path):
    (tmp_path / "certs").mkdir()
    (tmp_path / "certs" / "rsa_cert.pem").write_bytes((FIXTURE_DIR / "rsa_cert.pem").read_bytes())
    (tmp_path / "skip.pem").write_bytes((FIXTURE_DIR / "ecc_cert.pem").read_bytes())
    (tmp_path / "linked.pem").symlink_to(FIXTURE_DIR / "rsa_cert.pem")

    df = scan_crypto_inventory(str(tmp_path), exclude_patterns=["skip.pem"])

    names = set(df["Location"].apply(lambda p: Path(p).name))
    assert names == {"rsa_cert.pem"}
