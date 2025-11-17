# scripts/gen_dh_params.py
"""
Generate Diffie–Hellman (DH) parameters for the secure chat application.

These parameters are shared by both client and server to perform
ephemeral DH key exchanges. The generated file is stored in:

    certs/dh_params.pem
"""

from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization

def main():
    print("Creating 2048-bit DH parameter set... please wait.")

    # -------------------------------
    # Generate DH parameters
    # -------------------------------
    # Using generator = 2, key_size = 2048 (safe & standard)
    dh_params = dh.generate_parameters(
        generator=2,
        key_size=2048
    )

    # -------------------------------
    # Ensure certs directory exists
    # -------------------------------
    target_dir = Path("certs")
    target_dir.mkdir(exist_ok=True)

    output_file = target_dir / "dh_params.pem"

    # -------------------------------
    # Write parameters to PEM file
    # -------------------------------
    with output_file.open("wb") as fh:
        pem_bytes = dh_params.parameter_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.ParameterFormat.PKCS3
        )
        fh.write(pem_bytes)

    print(f"DH parameters written to: {output_file}")


if __name__ == "__main__":
    main()
