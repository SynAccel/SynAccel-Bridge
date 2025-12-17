# src/security/signing.py
import hmac
import hashlib
import json
from typing import Any, Dict


def canonical_payload(data: Dict[str, Any]) -> bytes:
    """
    Deterministic serialization for signing:
    - excludes the 'sig' field
    - sorts keys
    - removes whitespace
    """
    d = dict(data)
    d.pop("sig", None)
    return json.dumps(d, separators=(",", ":"), sort_keys=True).encode("utf-8")


def sign_event(secret: str, event_dict: Dict[str, Any]) -> str:
    msg = canonical_payload(event_dict)
    mac = hmac.new(secret.encode("utf-8"), msg, hashlib.sha256)
    return mac.hexdigest()


def verify_event(secret: str, event_dict: Dict[str, Any]) -> bool:
    provided = (event_dict.get("sig") or "").strip().lower()
    expected = sign_event(secret, event_dict)
    return hmac.compare_digest(provided, expected)
