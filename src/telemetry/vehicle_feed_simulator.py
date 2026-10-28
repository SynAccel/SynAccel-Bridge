import os
import json
import time
import random
import secrets
import requests
from dotenv import load_dotenv
from pathlib import Path

from src.security.signing import sign_event

# Load .env from repo root reliably
ENV_PATH = Path(__file__).resolve().parents[2] / ".env"
load_dotenv(dotenv_path=ENV_PATH, override=True)

API_URL = "http://127.0.0.1:8000/api/event"
API_KEY = os.getenv("API_KEY", "")
DEVICE_SECRETS = json.loads(os.getenv("DEVICE_SECRETS", "{}"))

HEADERS = {
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type": "application/json",
}

VEHICLES = ["uv01", "uv02"]

def generate_payload(vehicle_id: str) -> dict:
    """Generate random telemetry for a vehicle and sign it."""
    details = {
        "speed_kph": round(random.uniform(20, 60), 1),
        "gps": [
            round(random.uniform(42.33, 42.34), 6),
            round(random.uniform(-71.25, -71.24), 6),
        ],
        "battery_percent": round(random.uniform(70, 100), 1),
        "lidar_status": random.choice(["OK", "OK", "FAIL"]),
        "comm_latency_ms": round(random.uniform(40, 130), 1),
    }

    event = {
        "device_id": vehicle_id,
        "ts": int(time.time()),
        "nonce": secrets.token_hex(16),
        "sig": "",

        "source": vehicle_id,
        "type": "telemetry",
        "details": details,
    }

    secret = DEVICE_SECRETS.get(event["device_id"])
    if not secret:
        raise RuntimeError(f"No secret found for device_id='{event['device_id']}'. Check DEVICE_SECRETS in .env")

    event["sig"] = sign_event(secret, event)
    return event

def send_event(event: dict):
    """Send the signed event to the SynAccel-Bridge API."""
    r = requests.post(API_URL, headers=HEADERS, json=event, timeout=5)
    try:
        body = r.json()
    except Exception:
        body = r.text

    print(
        f"[{r.status_code}] {event['source']} -> "
        f"speed={event['details']['speed_kph']} lidar={event['details']['lidar_status']} | resp={body}"
    )

def main():
    print("Starting vehicle simulator (signed events)...")
    while True:
        for v in VEHICLES:
            try:
                event = generate_payload(v)
                send_event(event)
            except Exception as e:
                print(f"[ERROR] {v}: {e}")
            time.sleep(2)

if __name__ == "__main__":
    main()

