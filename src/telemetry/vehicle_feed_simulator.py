import requests
import time
import random
from datetime import datetime, timezone

API_URL = "http://127.0.0.1:8000/api/event"
API_KEY = "de3c5fd6b3c18ead317e62764b2a9da81643ffebefaa56348c2f46e1f1dc4519"
HEADERS = {
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type": "application/json"
}

VEHICLES = ["uv01", "uv02"]

def generate_payload(vehicle_id):
    """Generate random telemetry for a vehicle."""
    return {
        "source": vehicle_id,
        "type": "telemetry",
        "details": {
            "speed_kph": round(random.uniform(20, 60), 1),
            "gps": [round(random.uniform(42.33, 42.34), 6),
                    round(random.uniform(-71.25, -71.24), 6)],
            "battery_percent": round(random.uniform(70, 100), 1),
            "lidar_status": random.choice(["OK", "OK", "FAIL"]),
            "comm_latency_ms": round(random.uniform(40, 130), 1)
        }
    }

def send_event(payload):
    """Send the payload to the SynAccel-Bridge API."""
    try:
        r = requests.post(API_URL, headers=HEADERS, json=payload, timeout=5)
        print(f"[{r.status_code}] {payload['source']} -> {payload['details']}")
    except Exception as e:
        print(f"[ERROR] {e}")

if __name__ == "__main__":
    print("Starting vehicle simulator...")
    while True:
        for v in VEHICLES:
            data = generate_payload(v)
            send_event(data)
            time.sleep(2)
