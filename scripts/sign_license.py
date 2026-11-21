#!/usr/bin/env python3
"""
sign_license.py
Signs a license payload with .secrets/private.pem using Ed25519 asymmetric cryptography.
Outputs a Base64-encoded license key file.
"""

import argparse
import base64
import json
import os
import socket
import sys
import time
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization


def sign_license(
    client_name: str,
    tier: str,
    days: int,
    host: str,
    private_key_path: str = ".secrets/private.pem",
    out_path: str = "license.key",
) -> str:
    key_path = Path(private_key_path)
    if not key_path.exists():
        sys.stderr.write(f"Error: Private key not found at {private_key_path}. Run keygen.py first.\n")
        sys.exit(1)

    with open(key_path, "rb") as f:
        priv_pem = f.read()

    try:
        private_key = serialization.load_pem_private_key(priv_pem, password=None)
        if not isinstance(private_key, ed25519.Ed25519PrivateKey):
            raise TypeError("Expected Ed25519PrivateKey")
    except Exception as e:
        sys.stderr.write(f"Error loading private key: {e}\n")
        sys.exit(1)

    now = int(time.time())
    expires_at = now + (days * 86400)

    payload = {
        "client_name": client_name,
        "tier": tier.lower(),
        "issued_at": now,
        "expires_at": expires_at,
        "host": host,
    }

    # Canonical sorted JSON without whitespace
    canonical_data = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    # Sign canonical bytes with Ed25519
    signature_bytes = private_key.sign(canonical_data)
    signature_b64 = base64.b64encode(signature_bytes).decode("ascii")

    envelope = {
        "data": payload,
        "sig": signature_b64,
    }

    envelope_json = json.dumps(envelope, separators=(",", ":"))
    token_b64 = base64.b64encode(envelope_json.encode("utf-8")).decode("ascii")

    # Format nicely with newline every 64 chars or single string
    out_file = Path(out_path)
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with open(out_file, "w", encoding="utf-8") as f:
        f.write(token_b64 + "\n")

    print(f"[sign_license] License successfully generated and signed:")
    print(f"               Client:     {client_name}")
    print(f"               Tier:       {tier.lower()}")
    print(f"               Host:       {host}")
    print(f"               Days Valid: {days} (Expires: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(expires_at))})")
    print(f"               Output:     {out_path}")

    return out_path


def main():
    parser = argparse.ArgumentParser(description="Sign Ed25519 License Token for B2B Pricing Engine")
    parser.add_argument("--client", default="Acme Global Corporation", help="Client name")
    parser.add_argument("--tier", default="enterprise", choices=["starter", "standard", "enterprise"], help="License tier")
    parser.add_argument("--days", type=int, default=30, help="Days until expiration (can be negative to test expiry)")
    parser.add_argument("--host", default=socket.gethostname(), help="Host lock (* for wildcard or specific hostname)")
    parser.add_argument("--private-key", default=".secrets/private.pem", help="Path to private key PEM")
    parser.add_argument("--out", default="license.key", help="Output file path")

    args = parser.parse_args()

    sign_license(
        client_name=args.client,
        tier=args.tier,
        days=args.days,
        host=args.host,
        private_key_path=args.private_key,
        out_path=args.out,
    )


if __name__ == "__main__":
    main()

