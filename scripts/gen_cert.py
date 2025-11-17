#!/usr/bin/env python3
# scripts/gen_cert.py  (refactored)
"""
Create an end-entity certificate signed by the CA (certs/ca.key + certs/ca.crt.pem).
Usage:
  python3 scripts/gen_cert.py <basename> <common_name>
Example:
  python3 scripts/gen_cert.py server localhost
Outputs:
  certs/<basename>.key
  certs/<basename>.crt.pem
"""
import argparse
import datetime
from pathlib import Path
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


CERTS = Path("certs")
CA_KEY_FILE = CERTS / "ca.key"
CA_CERT_FILE = CERTS / "ca.crt.pem"


def parse_args():
    p = argparse.ArgumentParser(prog="gen_cert.py")
    p.add_argument("basename", help="base filename for key/cert (e.g. server)")
    p.add_argument("common_name", help="Common Name (CN) and SAN DNS entry")
    return p.parse_args()


def load_ca():
    if not CA_KEY_FILE.exists() or not CA_CERT_FILE.exists():
        raise FileNotFoundError("CA key or certificate missing - run gen_ca.py first")

    # load CA private key
    ca_priv = serialization.load_pem_private_key(
        CA_KEY_FILE.read_bytes(), password=None
    )
    ca_cert = x509.load_pem_x509_certificate(CA_CERT_FILE.read_bytes())
    return ca_priv, ca_cert


def generate_entity_key(bits=2048):
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def write_key(path: Path, key):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )


def build_cert(entity_pubkey, ca_cert, ca_key, cn: str, valid_days: int = 365):
    subj = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My Secure Chat"),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]
    )

    now = datetime.datetime.now(datetime.timezone.utc)
    expires = now + datetime.timedelta(days=valid_days)

    b = (
        x509.CertificateBuilder()
        .subject_name(subj)
        .issuer_name(ca_cert.subject)
        .public_key(entity_pubkey)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(expires)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(cn)]),
            critical=False,
        )
    )

    return b.sign(private_key=ca_key, algorithm=hashes.SHA256())


def main():
    args = parse_args()
    name = args.basename
    cn = args.common_name

    print(f"Generating key+cert for '{name}' (CN={cn})")

    try:
        ca_key, ca_cert = load_ca()
    except FileNotFoundError as e:
        print("ERROR:", e)
        sys.exit(1)

    key = generate_entity_key()
    key_path = CERTS / f"{name}.key"
    cert_path = CERTS / f"{name}.crt.pem"

    print("Saving private key:", key_path)
    write_key(key_path, key)

    print("Building certificate...")
    cert = build_cert(key.public_key(), ca_cert, ca_key, cn)

    print("Writing certificate:", cert_path)
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    print("\nSuccess.")
    print("Key ->", key_path)
    print("Cert->", cert_path)


if __name__ == "__main__":
    main()
