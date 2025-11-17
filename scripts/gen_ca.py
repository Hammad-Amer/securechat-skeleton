#!/usr/bin/env python3
# scripts/gen_ca.py  (refactored)
"""
Create a self-signed root Certificate Authority (CA).
Produces:
  certs/ca.key        (PEM private key)
  certs/ca.crt.pem    (PEM certificate)
"""
import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

OUT_DIR = Path("certs")


def ensure_out_dir():
    OUT_DIR.mkdir(parents=True, exist_ok=True)


def save_bytes(path: Path, data: bytes, mode: str = "wb"):
    with path.open(mode) as fh:
        fh.write(data)


def build_root_ca():
    # Generate RSA private key for CA
    # using 4096-bit for strong root key
    ca_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )

    # CA subject fields
    subj = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Islamabad"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My Secure Chat"),
            x509.NameAttribute(NameOID.COMMON_NAME, "MySecureChatRootCA"),
        ]
    )

    now = datetime.datetime.now(datetime.timezone.utc)
    expires = now + datetime.timedelta(days=3650)  # ~10 years

    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(subj)
        .issuer_name(subj)  # self-signed
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(expires)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    )

    ca_cert = cert_builder.sign(private_key=ca_key, algorithm=hashes.SHA256())

    return ca_key, ca_cert


def main():
    print("=== Root CA generator ===")
    ensure_out_dir()

    key_path = OUT_DIR / "ca.key"
    cert_path = OUT_DIR / "ca.crt.pem"

    ca_key, ca_cert = build_root_ca()

    # Serialize and write
    print(f"Writing CA key -> {key_path}")
    save_bytes(
        key_path,
        ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ),
    )

    print(f"Writing CA certificate -> {cert_path}")
    save_bytes(cert_path, ca_cert.public_bytes(serialization.Encoding.PEM))

    print("\nDone. Files created:")
    print("  -", key_path)
    print("  -", cert_path)


if __name__ == "__main__":
    main()
