from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from dataclasses import dataclass
from datetime import datetime
import base64
import ctypes
import hashlib
import hmac
import json
import os
import platform

_CACHE_SECRET = b"your-internal-secret-key-here"

def _get_cache_path() -> str:
    if platform.system() == "Windows":
        base = os.environ.get("PROGRAMDATA", "C:\\ProgramData")
        return os.path.join(base, ".platform_cache", "lc.dat")
    base = os.path.expanduser("~")  # /home/username
    return os.path.join(base, ".platform_cache", "lc.dat")

cache_path = _get_cache_path()
os.makedirs(os.path.dirname(cache_path), exist_ok=True)

def _sign_cache(data: dict) -> str:
    raw = json.dumps(data, sort_keys=True).encode()
    return hmac.new(_CACHE_SECRET, raw, hashlib.sha256).hexdigest()

def _read_cache() -> dict:
    path = _get_cache_path()
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r") as f:
            stored = json.load(f)
        data = stored["data"]
        if not hmac.compare_digest(_sign_cache(data), stored["sig"]):
            return {}  # Tampered
        return data
    except Exception:
        return {}
    
def _write_cache(data: dict):
    path = _get_cache_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    payload = {"data": data, "sig": _sign_cache(data)}
    with open(path, "w") as f:
        json.dump(payload, f)
    if platform.system() == "Windows":
        ctypes.windll.kernel32.SetFileAttributesW(path, 0x02)  # Hidden

def _check_and_record_activation(license_id: str, max_activations: int) -> bool:
    """True -> Allowed and registered | False -> Quota exhausted"""
    cache = _read_cache()
    count = cache.get(license_id, {}).get("count", 0)
    if count >= max_activations:
        return False
    cache[license_id] = {"count": count + 1}
    _write_cache(cache)
    return True

def _update_last_seen(ts: float):
    cache = _read_cache()
    cache["last_seen"] = ts
    _write_cache(cache)

def _get_last_seen() -> float:
    return _read_cache().get("last_seen", 0.0)

@dataclass
class LicenseVerificationResult:
    is_valid: bool
    message: str
    license_data: dict | None = None

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PUBLIC_KEY_PATH = os.path.join(BASE_DIR, "public_key.pem")

def load_public_key():
    with open(PUBLIC_KEY_PATH, "rb") as f:
        return serialization.load_pem_public_key(f.read())

def verify_license(machine_hash, license_key):
        
    try:
        public_key = load_public_key()

        package_bytes = base64.b64decode(license_key)
        package = json.loads(package_bytes.decode('utf-8'))

        if not isinstance(package, dict):
            return LicenseVerificationResult(
                is_valid=False,
                message="Invalid license structure"
            )
        
        if "data" not in package or "signature" not in package:
            return LicenseVerificationResult(
                is_valid=False,
                message="License is incomplete (missing required fields)"
            )
        
        license_data = package['data']
        signature_b64 = package['signature']
        
        if not isinstance(license_data, dict):
            return LicenseVerificationResult(
                is_valid=False,
                message="Invalid 'data' section in license"
            )
        
        if not isinstance(signature_b64, str):
            return LicenseVerificationResult(
                is_valid=False,
                message="Invalid license signature"
            )
        
        try:
            signature = base64.b64decode(signature_b64)
        except Exception:
            return LicenseVerificationResult(
                is_valid=False,
                message="Invalid license signature format"
            )

        data_to_verify = json.dumps(
            license_data, 
            separators=(",", ":"), 
            ensure_ascii=False
        ).encode("utf-8")

        try:
            public_key.verify(
                signature,
                data_to_verify,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
        except Exception:
            return LicenseVerificationResult(
                is_valid=False,
                message="Invalid license digital signature"
            )
        
        customer_hash = license_data.get("customer_hash")
        if customer_hash != machine_hash:
            return LicenseVerificationResult(
                is_valid=False,
                message="This license is issued for another system",
                license_data=license_data
            )
        
        valid_from_str = license_data.get("valid_from")
        valid_to_str = license_data.get("valid_to")

        if not valid_from_str or not valid_to_str:
            return LicenseVerificationResult(
                is_valid=False,
                message="Incomplete license time fields",
                license_data=license_data
            )
        
        try:
            valid_from = datetime.fromisoformat(valid_from_str)
            valid_to = datetime.fromisoformat(valid_to_str)
        except ValueError:
            return LicenseVerificationResult(
                is_valid=False,
                message="Invalid license date format",
                license_data = license_data
            )
        
        if valid_from > valid_to:
            return LicenseVerificationResult(
                is_valid=False,
                message="Invalid license validity period",
                license_data=license_data
            )

        now = datetime.now(valid_from.tzinfo) if valid_from.tzinfo else datetime.now()

        now_ts = now.timestamp()
        last_seen = _get_last_seen()

        if now_ts < last_seen:
            return LicenseVerificationResult(
                is_valid=False,
                message="System clock rollback detected. License deactivated."
            )
        
        _update_last_seen(now_ts)

        if now < valid_from:
            return LicenseVerificationResult(
                is_valid=False,
                message="License is not yet valid",
                license_data=license_data
            )
        
        if now > valid_to:
            return LicenseVerificationResult(
                is_valid=False,
                message="License has expired",
                license_data=license_data
            )

        role = license_data.get("role")        
        if role != "admin":
            return LicenseVerificationResult(
                is_valid=False,
                message="Unauthorized access level for this license",
                license_data=license_data
            )
        

        max_activations = license_data.get("max_activations")
        license_id = license_data.get("license_id")

        if max_activations is not None:
            try:
                max_activations = int(max_activations)
            except (ValueError, TypeError):
                return LicenseVerificationResult(
                    is_valid=False,
                    message="Invalid value for max_activations",
                    license_data = license_data
                )
            
            if not _check_and_record_activation(license_id, max_activations):
                return LicenseVerificationResult(
                    is_valid=False,
                    message=f"Maximum activation limit reached for ({max_activations})",
                    license_data = license_data
                )

        return LicenseVerificationResult(
            is_valid=True,
            message="License verified successfully",
            license_data=license_data
        )

    except Exception as e:
        return LicenseVerificationResult(
            is_valid=False,
            message=f"License validation failed: {str(e)}"
        )
    