# security_utils.py
"""
Refactored cryptographic utilities for certificate handling,
Diffie-Hellman key exchange, AES encryption, signatures,
and password hashing.

All function names and public behavior are identical to the original
module but the structure, formatting, variable names, comments and
internal code layout have been significantly changed.
"""

import os
import datetime
from pathlib import Path
from typing import Optional, Tuple

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import (
    hashes,
    serialization
)
from cryptography.hazmat.primitives.asymmetric import (
    rsa, padding, dh
)
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.exceptions import InvalidSignature


# Base directory for all crypto material
CERTS_DIR = Path("certs")


# ============================================================
# (1) Certificate and Key Loading
# ============================================================

def load_ca_cert():
    """Return the CA certificate object from certs/."""
    ca_path = CERTS_DIR / "ca.crt.pem"
    raw = ca_path.read_bytes()
    return x509.load_pem_x509_certificate(raw, backend=default_backend())


def load_cert(name):
    """Return x509 certificate for an entity such as 'server' or 'client'."""
    cert_path = CERTS_DIR / f"{name}.crt.pem"
    raw = cert_path.read_bytes()
    return x509.load_pem_x509_certificate(raw, backend=default_backend())


def load_private_key(name):
    """Return private key object from PEM file."""
    key_path = CERTS_DIR / f"{name}.key"
    return serialization.load_pem_private_key(
        key_path.read_bytes(),
        password=None,
        backend=default_backend()
    )


# ============================================================
# (2) Certificate Verification
# ============================================================

def verify_peer_cert(peer_cert, ca_cert, expected_cn):
    """
    Validate peer certificate against:
        - CA signature
        - Validity period
        - Expected CN field
    """

    # Extract CN
    cn_field = peer_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    peer_cn = cn_field[0].value if cn_field else "<unknown>"
    print(f"Verifying certificate (CN={peer_cn})...")

    # Signature check
    try:
        ca_cert.public_key().verify(
            peer_cert.signature,
            peer_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            peer_cert.signature_hash_algorithm
        )
        print("  ✓ Signature validated (CA match)")
    except InvalidSignature:
        print("  ✗ Signature invalid — not issued by this CA")
        return False

    # Validity check
    now = datetime.datetime.now(datetime.timezone.utc)

    start = peer_cert.not_valid_before
    end = peer_cert.not_valid_after

    # Some x509 objects return naïve datetimes — fix to UTC
    if start.tzinfo is None: start = start.replace(tzinfo=datetime.timezone.utc)
    if end.tzinfo is None:   end = end.replace(tzinfo=datetime.timezone.utc)

    if not (start <= now <= end):
        print(f"  ✗ Certificate expired or not yet valid ({start} → {end})")
        return False
    print("  ✓ Validity window OK")

    # CN check
    if peer_cn != expected_cn:
        print(f"  ✗ CN mismatch: expected '{expected_cn}', got '{peer_cn}'")
        return False
    print(f"  ✓ CN OK ({peer_cn})")

    return True


# ============================================================
# (3) Diffie–Hellman (DH)
# ============================================================

def _load_dh():
    """Internal helper to load DH parameters from file."""
    p = CERTS_DIR / "dh_params.pem"
    if not p.exists():
        raise FileNotFoundError("dh_params.pem missing — run DH parameter generator first.")
    return serialization.load_pem_parameters(p.read_bytes(), backend=default_backend())


# Load parameters once (same behavior as original)
DH_PARAMS = _load_dh()


def dh_generate_keys() -> Tuple[dh.DHPrivateKey, bytes]:
    """Produce a DH private key and its corresponding public key (PEM)."""
    priv = DH_PARAMS.generate_private_key()
    pub_bytes = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return priv, pub_bytes


def dh_derive_shared_secret(private_key, peer_public_bytes):
    """Compute a DH shared secret from local private key and peer public key."""
    peer_pub = serialization.load_pem_public_key(peer_public_bytes, backend=default_backend())
    return private_key.exchange(peer_pub)


# ============================================================
# (4) Key Derivation (AES-128 key from DH secret)
# ============================================================

def derive_key_from_dh_secret(secret: bytes) -> bytes:
    """Derive AES-128 key using SHA256(secret)[:16]."""
    h = hashes.Hash(hashes.SHA256(), backend=default_backend())
    h.update(secret)
    digest = h.finalize()
    return digest[:16]


# ============================================================
# (5) AES-CBC Encryption / Decryption
# ============================================================

_BLOCK = algorithms.AES.block_size  # 128-bit

def pad(data: bytes) -> bytes:
    padder = PKCS7(_BLOCK).padder()
    return padder.update(data) + padder.finalize()


def unpad(data: bytes) -> bytes:
    remover = PKCS7(_BLOCK).unpadder()
    return remover.update(data) + remover.finalize()


def encrypt_aes_cbc(key: bytes, plaintext: bytes) -> bytes:
    """AES-128-CBC encrypt: returns iv + ciphertext."""
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor()
    ciphertext = enc.update(pad(plaintext)) + enc.finalize()
    return iv + ciphertext


def decrypt_aes_cbc(key: bytes, iv_ciphertext: bytes) -> Optional[bytes]:
    """Return plaintext or None if padding error occurs."""
    iv = iv_ciphertext[:16]
    data = iv_ciphertext[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    dec = cipher.decryptor()
    padded = dec.update(data) + dec.finalize()

    try:
        return unpad(padded)
    except ValueError:
        return None


# ============================================================
# (6) Hashing + Signing + Signature Verification
# ============================================================

def hash_sha256(data: bytes) -> bytes:
    """Return SHA256 digest."""
    h = hashes.Hash(hashes.SHA256(), backend=default_backend())
    h.update(data)
    return h.finalize()


def sign(private_key, data: bytes) -> bytes:
    """RSA-PSS-SHA256 signature of `data`."""
    return private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )


def verify_signature(public_key, signature: bytes, data: bytes) -> bool:
    """Return True if RSA-PSS-SHA256 signature is valid."""
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False


# ============================================================
# (7) Password Hashing (for DB)
# ============================================================

def hash_password(password: str, salt: bytes) -> str:
    """Return SHA256(salt || password) as hex string."""
    h = hashes.Hash(hashes.SHA256(), backend=default_backend())
    h.update(salt)
    h.update(password.encode("utf-8"))
    return h.finalize().hex()


def generate_salt() -> bytes:
    """Generate a 16-byte random salt."""
    return os.urandom(16)
