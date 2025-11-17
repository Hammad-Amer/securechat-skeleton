#!/usr/bin/env python3
# verify_transcript.py 
"""
Validate a session receipt against a stored transcript.

Usage:
    python3 verify_transcript.py <receipt.json> <transcript.log>

Checks performed:
  1) Recomputes SHA-256(transcript) and compares with receipt.transcript_hash_hex
  2) Loads the signer certificate embedded in the receipt and verifies the signature
     over the recomputed transcript hash.


"""

import json
import sys
from pathlib import Path

import security_utils as sec
from cryptography import x509
from cryptography.hazmat.backends import default_backend


def _usage_and_exit():
    print("Usage: python3 verify_transcript.py <path_to_receipt.json> <path_to_transcript.log>")
    sys.exit(1)


def _load_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise RuntimeError(f"Failed to load JSON from {path}: {exc}") from exc


def _load_transcript_bytes(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except Exception as exc:
        raise RuntimeError(f"Failed to read transcript {path}: {exc}") from exc


def _get_signer_cert_from_receipt(receipt: dict) -> (str, str):
    """
    Return tuple (role, pem_string). role is 'client' or 'server'.
    Raises if neither certificate is present.
    """
    if "client_cert" in receipt and receipt["client_cert"]:
        return "client", receipt["client_cert"]
    if "server_cert" in receipt and receipt["server_cert"]:
        return "server", receipt["server_cert"]
    raise RuntimeError("Receipt does not contain 'client_cert' or 'server_cert'.")


def main():
    if len(sys.argv) != 3:
        _usage_and_exit()

    receipt_path = Path(sys.argv[1])
    transcript_path = Path(sys.argv[2])

    print(f"Receipt:   {receipt_path}")
    print(f"Transcript: {transcript_path}\n")

    # --- load receipt JSON ---
    try:
        receipt = _load_json(receipt_path)
    except Exception as e:
        print("ERROR:", e)
        sys.exit(1)

    # --- recompute transcript hash ---
    try:
        transcript_bytes = _load_transcript_bytes(transcript_path)
        computed_hash = sec.hash_sha256(transcript_bytes)
    except Exception as e:
        print("ERROR:", e)
        sys.exit(1)

    receipt_hash_hex = receipt.get("transcript_hash_hex", "")
    print("Receipt hash:  ", receipt_hash_hex)
    print("Computed hash: ", computed_hash.hex())

    if computed_hash.hex() != receipt_hash_hex:
        print("\n❌ HASH MISMATCH: transcript does not match receipt.")
        sys.exit(1)

    print("\n✅ Transcript hash matches receipt.")

    # --- determine signer and verify signature ---
    try:
        signer_role, pem_str = _get_signer_cert_from_receipt(receipt)
        print(f"Receipt signer: {signer_role.upper()}")

        # load cert and extract public key
        cert = x509.load_pem_x509_certificate(pem_str.encode("utf-8"), backend=default_backend())
        pubkey = cert.public_key()

        signature_hex = receipt.get("signature_hex", "")
        if not signature_hex:
            print("❌ No signature found in receipt.")
            sys.exit(1)

        signature = bytes.fromhex(signature_hex)

        # verify signature over the computed hash
        valid = sec.verify_signature(pubkey, signature, computed_hash)
        if valid:
            print("✅ Signature valid.")
            print("\n--- VERIFICATION SUCCESSFUL ---")
            print("Transcript authenticity and integrity verified.")
            sys.exit(0)
        else:
            print("❌ INVALID SIGNATURE: receipt forgery or wrong key.")
            sys.exit(1)

    except Exception as e:
        print("ERROR during signature verification:", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
