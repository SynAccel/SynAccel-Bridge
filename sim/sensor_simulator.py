import requests
import random
import time
import os
import json
import secrets
import hmac
import hashlib
from dotenv import load_dotenv

# -------- Load env vars --------
load_dotenv()
API_KEY = os.getenv("API_KEY")
DEVICE_SECRETS_RAW = os.getenv("DEVICE_SECRETS")  # JSON like {"uv01":"uv01secret","uv02":"uv02secret"}
BRIDGE_URL = "http://127.0.0.1:8000/api/event"

EVENT_TYPES = ["motion", "intrusion", "access_denied", "door_open"]
ZONES = ["Lobby", "Warehouse", "ServerRoom", "MainGate"]

DEVICE_ID = "uv01"

def canonical_payload(data: dict) -> bytes:
    d = dict(data)
    d.pop("sig", None)
    return json.dumps(d, separators=(",", ":"), sort_keys=True).encode("utf-8")

def sign_event(secret: str, event_dict: dict) -> str:
    msg = canonical_payload(event_dict)
    mac = hmac.new(secret.encode("utf-8"), msg, hashlib.sha256)
    return mac.hexdigest()

def send_event(event_type: str):
    if not API_KEY:
        raise RuntimeError("API_KEY is missing in .env")

    if not DEVICE_SECRETS_RAW:
        raise RuntimeError("DEVICE_SECRETS is missing in .env (needs JSON like {\"uv01\":\"uv01secret\"})")

    device_secrets = json.loads(DEVICE_SECRETS_RAW)
    secret = device_secrets.get(DEVICE_ID)
    if not secret:
        raise RuntimeError(f"No secret found for device_id={DEVICE_ID}. Check DEVICE_SECRETS in .env")

    payload = {
        "device_id": DEVICE_ID,
        "ts": int(time.time()),
        "nonce": secrets.token_hex(8),   # 16+ chars ✅
        "sig": "",                       # fill after signing
        "source": "simSensor-01",
        "type": event_type,
        "details": {
            "zone": random.choice(ZONES),
            "confidence": round(random.uniform(0.7, 0.99), 2)
        }
    }

    # compute signature exactly like src/security/signing.py
    payload["sig"] = sign_event(secret, payload)

    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json"
    }

    response = requests.post(BRIDGE_URL, headers=headers, json=payload, timeout=10)
    print(f"[SENT] {event_type} ({response.status_code}) {response.text}")

print("[INFO] SynAccel Sensor Simulator started. Press Ctrl+C to stop.")
try:
    while True:
        event = random.choice(EVENT_TYPES)
        send_event(event)
        time.sleep(random.randint(2, 5))
except KeyboardInterrupt:
    print("\n[INFO] Sensor simulation stopped.")


