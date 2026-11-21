"""
license_guard.py
Ed25519 Asymmetric License Verification Guard.
Pre-compilation contains placeholder PUBLIC_KEY_PEM which build_release.sh
replaces with the embedded public key before Cython native binary compilation.
"""

import base64
import json
import os
import socket
import time
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

# Embedded public key placeholder (replaced during build_release.sh)
PUBLIC_KEY_PEM = b"""__EMBEDDED_PUBLIC_KEY__"""


def _get_public_key():
    """Retrieve public key from baked-in binary or fallback for development."""
    pem_bytes = PUBLIC_KEY_PEM

    # In dev mode before compilation, allow fallback to .secrets/public.pem
    if b"__EMBEDDED_PUBLIC_KEY__" in pem_bytes:
        dev_pub = Path(".secrets/public.pem")
        if dev_pub.exists():
            with open(dev_pub, "rb") as f:
                pem_bytes = f.read()
        else:
            raise RuntimeError(
                "LicenseGuard: Embedded public key is unpopulated and .secrets/public.pem was not found."
            )

    try:
        return serialization.load_pem_public_key(pem_bytes)
    except Exception as e:
        raise RuntimeError(f"LicenseGuard: Failed to parse embedded public key: {e}")


def verify_license(license_path: str = "license.key") -> dict:
    """
    Verifies the license file using Ed25519 asymmetric cryptography.
    Checks signature integrity, expiration timestamp, and hostname lock.

    Raises RuntimeError on any failure.
    """
    if not os.path.isfile(license_path):
        raise RuntimeError(f"License verification failed: license file not found at '{license_path}'")

    try:
        with open(license_path, "r", encoding="utf-8") as f:
            raw_token = f.read().strip()
    except Exception as e:
        raise RuntimeError(f"License verification failed: could not read '{license_path}': {e}")

    if not raw_token:
        raise RuntimeError("License verification failed: license file is empty")

    # Decode Base64 token to obtain envelope JSON
    try:
        decoded_bytes = base64.b64decode(raw_token)
        envelope = json.loads(decoded_bytes.decode("utf-8"))
    except Exception:
        # Fallback in case raw JSON was directly saved
        try:
            envelope = json.loads(raw_token)
        except Exception as e:
            raise RuntimeError(f"License verification failed: invalid token format (not valid Base64 JSON): {e}")

    if not isinstance(envelope, dict):
        raise RuntimeError("License verification failed: license payload must be a JSON object")

    if "data" not in envelope or "sig" not in envelope:
        raise RuntimeError("License verification failed: token missing required 'data' or 'sig' fields")

    data = envelope["data"]
    sig_b64 = envelope["sig"]

    if not isinstance(data, dict):
        raise RuntimeError("License verification failed: license 'data' must be an object")

    # Reconstruct canonical sorted JSON representation of data
    try:
        canonical_data = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
        signature_bytes = base64.b64decode(sig_b64)
    except Exception as e:
        raise RuntimeError(f"License verification failed: corrupted data or signature encoding: {e}")

    # Cryptographic Ed25519 signature check
    pub_key = _get_public_key()
    try:
        pub_key.verify(signature_bytes, canonical_data)
    except Exception as e:
        raise RuntimeError(f"License verification failed: Cryptographic signature mismatch! License has been tampered with or corrupted ({e})")

    # Expiry Check
    current_time = int(time.time())
    expires_at = data.get("expires_at")
    if expires_at is None:
        raise RuntimeError("License verification failed: license data missing 'expires_at' timestamp")

    if current_time >= int(expires_at):
        exp_str = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(expires_at))
        cur_str = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(current_time))
        raise RuntimeError(f"License verification failed: License expired on {exp_str} (current server time: {cur_str})")

    # Host Lock Check
    license_host = data.get("host", "*")
    current_host = socket.gethostname()
    if license_host != "*" and license_host != current_host:
        raise RuntimeError(
            f"License verification failed: Host mismatch! License is locked to '{license_host}', "
            f"but current server host is '{current_host}'"
        )

    client_name = data.get("client_name", "Unknown Client")
    tier = str(data.get("tier", "starter")).lower()
    issued_at = data.get("issued_at", 0)

    return {
        "status": "VALID",
        "client_name": client_name,
        "tier": tier,
        "expires_at": expires_at,
        "expires_at_iso": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(expires_at)),
        "issued_at_iso": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(issued_at)) if issued_at else None,
        "host": license_host,
        "current_host": current_host,
    }

