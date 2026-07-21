from __future__ import annotations

import argparse
import fnmatch
import json
import math
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.serialization import pkcs12

SCANNER_NAME = "crypto_inventory"
SCANNER_VERSION = "0.1.0"

_MAX_TEXT_BYTES = 5_000_000
_BINARY_PARSE_EXTENSIONS = {".cer", ".crt", ".der", ".jks", ".p12", ".pfx"}
_PEM_BLOCK_MARKERS = {
    "CERTIFICATE": "PEM Certificate",
    "PRIVATE KEY": "PEM Private Key",
    "ENCRYPTED PRIVATE KEY": "Encrypted PEM Private Key",
    "RSA PRIVATE KEY": "PEM Private Key",
    "DSA PRIVATE KEY": "PEM Private Key",
    "EC PRIVATE KEY": "PEM Private Key",
    "OPENSSH PRIVATE KEY": "OpenSSH Private Key",
    "PUBLIC KEY": "PEM Public Key",
}


@dataclass
class CryptoInventoryFinding:
    asset_type: str
    location: str
    algorithm: str | None = None
    key_size: int | None = None
    signature_algorithm: str | None = None
    expiration: str | None = None
    issuer: str | None = None
    subject: str | None = None
    fingerprint: str | None = None
    evidence: str = ""
    confidence: str = "Low"
    errors: list[str] = field(default_factory=list)
    scanner: str = SCANNER_NAME
    scanner_version: str = SCANNER_VERSION
    observed_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    )

    def to_record(self) -> dict[str, Any]:
        return {
            "Asset Type": self.asset_type,
            "Location": self.location,
            "Algorithm": self.algorithm,
            "Key Size": self.key_size,
            "Signature Algorithm": self.signature_algorithm,
            "Expiration": self.expiration,
            "Issuer": self.issuer,
            "Subject": self.subject,
            "Fingerprint": self.fingerprint,
            "Evidence": self.evidence,
            "Confidence": self.confidence,
            "Errors": "; ".join(self.errors),
            "Scanner": self.scanner,
            "Scanner Version": self.scanner_version,
            "Observed At": self.observed_at,
        }


def scan_crypto_inventory(
    path: str,
    exclude_patterns: list[str] | None = None,
    follow_symlinks: bool = False,
) -> pd.DataFrame:
    """Recursively scan a local path for cryptographic asset evidence."""
    findings = []
    root_path = Path(path)
    patterns = exclude_patterns or []

    for file_path in _iter_candidate_files(root_path, patterns, follow_symlinks):
        findings.extend(_scan_file(file_path))

    return pd.DataFrame([finding.to_record() for finding in findings])


def _iter_candidate_files(
    root_path: Path, exclude_patterns: list[str], follow_symlinks: bool
):
    if root_path.is_file():
        if not _is_excluded(root_path, root_path.name, exclude_patterns):
            yield root_path
        return

    for current_root, dirs, files in os.walk(root_path, followlinks=follow_symlinks):
        current = Path(current_root)
        rel_root = _relative_for_match(current, root_path)
        dirs[:] = [
            d
            for d in dirs
            if (follow_symlinks or not (current / d).is_symlink())
            and not _is_excluded(current / d, _join_match_path(rel_root, d), exclude_patterns)
        ]

        for name in files:
            file_path = current / name
            rel_path = _join_match_path(rel_root, name)
            if _is_excluded(file_path, rel_path, exclude_patterns):
                continue
            if file_path.is_symlink() and not follow_symlinks:
                continue
            yield file_path


def _scan_file(file_path: Path) -> list[CryptoInventoryFinding]:
    try:
        data = file_path.read_bytes()
    except (OSError, PermissionError):
        return []

    if not _could_contain_crypto_asset(file_path, data):
        return []

    findings: list[CryptoInventoryFinding] = []
    if _looks_like_jks(data):
        findings.append(
            CryptoInventoryFinding(
                asset_type="Java Keystore",
                location=str(file_path),
                evidence="JKS magic header detected",
                confidence="Medium",
                errors=["JKS entry parsing is not implemented in the MVP scanner"],
            )
        )
        return findings

    if file_path.suffix.lower() in {".p12", ".pfx"}:
        return _parse_pkcs12(file_path, data)

    if _looks_like_der_candidate(file_path, data):
        findings.extend(_parse_der_certificate(file_path, data))
        if findings:
            return findings

    text = _decode_text(data)
    if text is None:
        return findings

    findings.extend(_parse_pem_certificates(file_path, text))
    findings.extend(_parse_pem_private_keys(file_path, text, data))
    findings.extend(_parse_ssh_public_keys(file_path, text))
    return findings


def _parse_pem_certificates(file_path: Path, text: str) -> list[CryptoInventoryFinding]:
    findings = []
    blocks = _extract_pem_blocks(text, "CERTIFICATE")
    for block in blocks:
        try:
            cert = x509.load_pem_x509_certificate(block.encode("ascii"))
            findings.append(_finding_from_certificate("PEM Certificate", file_path, cert))
        except (ValueError, TypeError) as exc:
            findings.append(
                CryptoInventoryFinding(
                    asset_type="Malformed PEM Certificate",
                    location=str(file_path),
                    evidence="PEM certificate block detected but parsing failed",
                    confidence="Low",
                    errors=[str(exc)],
                )
            )
    return findings


def _parse_der_certificate(file_path: Path, data: bytes) -> list[CryptoInventoryFinding]:
    try:
        cert = x509.load_der_x509_certificate(data)
    except ValueError:
        return [
            CryptoInventoryFinding(
                asset_type="Malformed DER Certificate",
                location=str(file_path),
                evidence="DER-like certificate file extension detected but parsing failed",
                confidence="Low",
                errors=["Unable to parse DER certificate"],
            )
        ]
    return [_finding_from_certificate("DER Certificate", file_path, cert)]


def _parse_pem_private_keys(
    file_path: Path, text: str, data: bytes
) -> list[CryptoInventoryFinding]:
    findings = []
    for label, asset_type in _PEM_BLOCK_MARKERS.items():
        if label in {"CERTIFICATE", "OPENSSH PRIVATE KEY", "PUBLIC KEY"}:
            continue
        for block in _extract_pem_blocks(text, label):
            encrypted = "ENCRYPTED" in label or "Proc-Type: 4,ENCRYPTED" in block
            try:
                key = serialization.load_pem_private_key(block.encode("ascii"), password=None)
                algorithm, key_size = _key_algorithm_and_size(key)
                findings.append(
                    CryptoInventoryFinding(
                        asset_type=asset_type,
                        location=str(file_path),
                        algorithm=algorithm,
                        key_size=key_size,
                        fingerprint=_public_key_fingerprint(key.public_key()),
                        evidence=f"PEM block BEGIN {label}",
                        confidence="High",
                    )
                )
            except (TypeError, ValueError) as exc:
                if encrypted:
                    algorithm = _algorithm_from_pem_label(label)
                    findings.append(
                        CryptoInventoryFinding(
                            asset_type="Encrypted PEM Private Key",
                            location=str(file_path),
                            algorithm=algorithm,
                            evidence=f"Encrypted PEM block BEGIN {label}",
                            confidence="High",
                            errors=[
                                "Private key is encrypted; key metadata requires a passphrase",
                            ],
                        )
                    )
                else:
                    findings.append(
                        CryptoInventoryFinding(
                            asset_type=f"Malformed {asset_type}",
                            location=str(file_path),
                            evidence=f"PEM block BEGIN {label} detected but parsing failed",
                            confidence="Low",
                            errors=[str(exc)],
                        )
                    )

    if "BEGIN OPENSSH PRIVATE KEY" in text and not any(
        finding.asset_type == "OpenSSH Private Key" for finding in findings
    ):
        try:
            key = serialization.load_ssh_private_key(data, password=None)
            algorithm, key_size = _key_algorithm_and_size(key)
            findings.append(
                CryptoInventoryFinding(
                    asset_type="OpenSSH Private Key",
                    location=str(file_path),
                    algorithm=algorithm,
                    key_size=key_size,
                    fingerprint=_public_key_fingerprint(key.public_key()),
                    evidence="OpenSSH private key block detected",
                    confidence="High",
                )
            )
        except (TypeError, ValueError) as exc:
            findings.append(
                CryptoInventoryFinding(
                    asset_type="Encrypted OpenSSH Private Key",
                    location=str(file_path),
                    evidence="OpenSSH private key block detected",
                    confidence="Medium",
                    errors=[str(exc)],
                )
            )

    return findings


def _parse_ssh_public_keys(file_path: Path, text: str) -> list[CryptoInventoryFinding]:
    findings = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith(("ssh-rsa ", "ssh-ed25519 ", "ecdsa-sha2-")):
            continue
        try:
            key = serialization.load_ssh_public_key(stripped.encode("utf-8"))
            algorithm, key_size = _key_algorithm_and_size(key)
            findings.append(
                CryptoInventoryFinding(
                    asset_type="OpenSSH Public Key",
                    location=str(file_path),
                    algorithm=algorithm,
                    key_size=key_size,
                    fingerprint=_public_key_fingerprint(key),
                    evidence=f"OpenSSH public key prefix {stripped.split()[0]}",
                    confidence="High",
                )
            )
        except ValueError as exc:
            findings.append(
                CryptoInventoryFinding(
                    asset_type="Malformed OpenSSH Public Key",
                    location=str(file_path),
                    evidence="OpenSSH public key prefix detected but parsing failed",
                    confidence="Low",
                    errors=[str(exc)],
                )
            )
    return findings


def _parse_pkcs12(file_path: Path, data: bytes) -> list[CryptoInventoryFinding]:
    try:
        key, cert, additional_certs = pkcs12.load_key_and_certificates(data, password=None)
    except ValueError as exc:
        return [
            CryptoInventoryFinding(
                asset_type="Malformed PKCS#12",
                location=str(file_path),
                evidence="PKCS#12 file extension detected but parsing failed",
                confidence="Low",
                errors=[str(exc)],
            )
        ]

    findings = []
    if cert is not None:
        finding = _finding_from_certificate("PKCS#12 Certificate", file_path, cert)
        finding.evidence = "PKCS#12 container certificate parsed"
        findings.append(finding)
    for extra_cert in additional_certs or []:
        finding = _finding_from_certificate("PKCS#12 Certificate", file_path, extra_cert)
        finding.evidence = "PKCS#12 additional certificate parsed"
        findings.append(finding)
    if key is not None:
        algorithm, key_size = _key_algorithm_and_size(key)
        findings.append(
            CryptoInventoryFinding(
                asset_type="PKCS#12 Private Key",
                location=str(file_path),
                algorithm=algorithm,
                key_size=key_size,
                fingerprint=_public_key_fingerprint(key.public_key()),
                evidence="PKCS#12 private key parsed",
                confidence="High",
            )
        )

    return findings


def _finding_from_certificate(
    asset_type: str, file_path: Path, cert: x509.Certificate
) -> CryptoInventoryFinding:
    public_key = cert.public_key()
    algorithm, key_size = _key_algorithm_and_size(public_key)
    return CryptoInventoryFinding(
        asset_type=asset_type,
        location=str(file_path),
        algorithm=algorithm,
        key_size=key_size,
        signature_algorithm=_signature_algorithm(cert),
        expiration=_certificate_expiration(cert),
        issuer=cert.issuer.rfc4514_string(),
        subject=cert.subject.rfc4514_string(),
        fingerprint=cert.fingerprint(hashes.SHA256()).hex(),
        evidence=f"{asset_type} parsed successfully",
        confidence="High",
    )


def _key_algorithm_and_size(key: object) -> tuple[str, int | None]:
    if isinstance(key, (rsa.RSAPrivateKey, rsa.RSAPublicKey)):
        return "RSA", key.key_size
    if isinstance(key, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)):
        return f"EC ({key.curve.name})", key.key_size
    if isinstance(key, (dsa.DSAPrivateKey, dsa.DSAPublicKey)):
        return "DSA", key.key_size
    if isinstance(key, (ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey)):
        return "Ed25519", 256
    if isinstance(key, (ed448.Ed448PrivateKey, ed448.Ed448PublicKey)):
        return "Ed448", 456
    return key.__class__.__name__, None


def _public_key_fingerprint(public_key: object) -> str | None:
    try:
        encoded = public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    except (TypeError, ValueError):
        return None
    digest = hashes.Hash(hashes.SHA256())
    digest.update(encoded)
    return digest.finalize().hex()


def _signature_algorithm(cert: x509.Certificate) -> str:
    if cert.signature_hash_algorithm is not None:
        return cert.signature_hash_algorithm.name
    return cert.signature_algorithm_oid._name


def _certificate_expiration(cert: x509.Certificate) -> str:
    try:
        expires = cert.not_valid_after_utc
    except AttributeError:
        expires = cert.not_valid_after.replace(tzinfo=timezone.utc)
    return expires.replace(microsecond=0).isoformat()


def _extract_pem_blocks(text: str, label: str) -> list[str]:
    begin = f"-----BEGIN {label}-----"
    end = f"-----END {label}-----"
    blocks = []
    start = 0
    while True:
        begin_index = text.find(begin, start)
        if begin_index == -1:
            return blocks
        end_index = text.find(end, begin_index)
        if end_index == -1:
            blocks.append(text[begin_index:])
            return blocks
        block_end = end_index + len(end)
        blocks.append(text[begin_index:block_end])
        start = block_end


def _decode_text(data: bytes) -> str | None:
    if len(data) > _MAX_TEXT_BYTES:
        return None
    if b"\x00" in data[:4096]:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        try:
            return data.decode("ascii")
        except UnicodeDecodeError:
            return None


def _could_contain_crypto_asset(file_path: Path, data: bytes) -> bool:
    suffix = file_path.suffix.lower()
    if suffix in _BINARY_PARSE_EXTENSIONS:
        return True
    if _looks_like_jks(data):
        return True
    if b"-----BEGIN " in data[:_MAX_TEXT_BYTES]:
        return True
    if data.startswith((b"ssh-rsa ", b"ssh-ed25519 ", b"ecdsa-sha2-")):
        return True
    return False


def _looks_like_der_candidate(file_path: Path, data: bytes) -> bool:
    return file_path.suffix.lower() in {".cer", ".crt", ".der"} and not data.startswith(
        b"-----BEGIN "
    )


def _looks_like_jks(data: bytes) -> bool:
    return data.startswith(b"\xfe\xed\xfe\xed")


def _algorithm_from_pem_label(label: str) -> str | None:
    if label.startswith("RSA"):
        return "RSA"
    if label.startswith("DSA"):
        return "DSA"
    if label.startswith("EC"):
        return "EC"
    if label == "OPENSSH PRIVATE KEY":
        return "OpenSSH"
    return None


def _relative_for_match(path: Path, root_path: Path) -> str:
    try:
        rel = path.relative_to(root_path)
    except ValueError:
        return path.name
    return "" if str(rel) == "." else rel.as_posix()


def _join_match_path(prefix: str, name: str) -> str:
    return name if not prefix else f"{prefix}/{name}"


def _is_excluded(path: Path, match_path: str, patterns: list[str]) -> bool:
    return any(
        fnmatch.fnmatch(path.name, pattern) or fnmatch.fnmatch(match_path, pattern)
        for pattern in patterns
    )


def _clean_json_value(value: object) -> object:
    if isinstance(value, CryptoInventoryFinding):
        return asdict(value)
    if isinstance(value, float) and math.isnan(value):
        return None
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return value


def _records_for_json(df: pd.DataFrame) -> list[dict[str, object]]:
    return [
        {key: _clean_json_value(value) for key, value in record.items()}
        for record in df.to_dict(orient="records")
    ]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Scan a directory for cryptographic assets.")
    parser.add_argument("path", help="File or directory to scan")
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        help="Glob pattern to exclude; may be supplied more than once",
    )
    parser.add_argument(
        "--follow-symlinks",
        action="store_true",
        help="Follow symbolic links during recursive scans",
    )
    args = parser.parse_args(argv)

    df = scan_crypto_inventory(
        args.path,
        exclude_patterns=args.exclude,
        follow_symlinks=args.follow_symlinks,
    )
    print(json.dumps(_records_for_json(df), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
