#!/usr/bin/env python3
"""
keygen.py
Generates an Ed25519 asymmetric keypair into .secrets/private.pem and .secrets/public.pem.
"""

import argparse
import os
import stat
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization


def generate_keypair(secrets_dir: str = ".secrets", force: bool = False) -> tuple[str, str]:
    secrets_path = Path(secrets_dir)
    secrets_path.mkdir(parents=True, exist_ok=True)

    priv_path = secrets_path / "private.pem"
    pub_path = secrets_path / "public.pem"

    if priv_path.exists() and pub_path.exists() and not force:
        print(f"[keygen] Keys already exist in {secrets_path}. Skipping generation (use --force to overwrite).")
        return str(priv_path), str(pub_path)

    print(f"[keygen] Generating new Ed25519 keypair in {secrets_path}...")
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    with open(priv_path, "wb") as f:
        f.write(priv_pem)
    # Restrict private key permissions to read/write by owner only
    os.chmod(priv_path, stat.S_IRUSR | stat.S_IWUSR)

    with open(pub_path, "wb") as f:
        f.write(pub_pem)
    os.chmod(pub_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)

    print(f"[keygen] Successfully generated:")
    print(f"         Private Key: {priv_path} (mode 0600)")
    print(f"         Public Key:  {pub_path} (mode 0644)")

    return str(priv_path), str(pub_path)


def main():
    parser = argparse.ArgumentParser(description="Generate Ed25519 keypair for B2B License Guard")
    parser.add_argument("--secrets-dir", default=".secrets", help="Directory to store private and public keys")
    parser.add_argument("--force", action="store_true", help="Force overwrite existing keys")
    args = parser.parse_args()

    generate_keypair(secrets_dir=args.secrets_dir, force=args.force)


if __name__ == "__main__":
    main()

