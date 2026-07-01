#!/usr/bin/env python3
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta
from pathlib import Path
import base64
import json
import uuid

current_file_path = Path(__file__).resolve()

PRIVATE_KEY_PATH = current_file_path.parent.parent / "keys" / "private_key.pem"

def load_private_key(path: str):
    """Load RSA private key from PEM file."""
    with open(path, "rb") as f:
        private_key_data = f.read()

    private_key = serialization.load_pem_private_key(
        private_key_data,
        password=None,
        backend=default_backend()
    )
    return private_key


def create_license(customer_hash: str) -> dict:
    """Create license data with 5-minute validity and admin role."""

    now = datetime.now()
    valid_from = now
    valid_to = now + timedelta(minutes=10)

    license_data = {
        "license_id": str(uuid.uuid4()),
        "customer_hash": customer_hash,
        "role": "admin",   
        "valid_from": valid_from.isoformat(),
        "valid_to": valid_to.isoformat(),
        "max_activations": 2
    }

    return license_data


def sign_license(license_data: dict, private_key):
    """Sign license data using RSA + SHA256, return raw data bytes and Base64 signature."""
    # JSON -> bytes
    data_bytes = json.dumps(
        license_data,
        separators=(",", ":"), 
        ensure_ascii=False  
    ).encode("utf-8")

    signature = private_key.sign(
        data_bytes,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    signature_b64 = base64.b64encode(signature).decode("ascii")
    return data_bytes, signature_b64


def build_final_license_b64(license_data: dict, signature_b64: str) -> str:
    """Pack data + signature into JSON, then Base64-encode the whole package."""
    package = {
        "data": license_data,
        "signature": signature_b64
    }

    package_json = json.dumps(
        package,
        separators=(",", ":"),
        ensure_ascii=False
    )
    package_bytes = package_json.encode("utf-8")

    final_b64 = base64.b64encode(package_bytes).decode("ascii")
    return final_b64


def main():
    print("=== License Generator (Vendor Side) ===")
    print("This script will create a license valid for 5 minutes (Asia/Tehran) for role 'admin'.")
    print()

    customer_hash = input("Enter customer hash: ").strip()

    if not customer_hash:
        print("Error: customer hash is empty.")
        return

    try:
        private_key = load_private_key(PRIVATE_KEY_PATH)
    except Exception as e:
        print(f"Error loading private key from {PRIVATE_KEY_PATH}: {e}")
        return

    license_data = create_license(customer_hash)

    _, signature_b64 = sign_license(license_data, private_key)

    final_b64 = build_final_license_b64(license_data, signature_b64)

    print("\n--- LICENSE (BASE64) ---")
    print(final_b64)
    print("\nCopy this string and send it to your customer.")


if __name__ == "__main__":
    main()
