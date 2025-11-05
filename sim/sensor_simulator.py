import requests
import json
import random
import time
import os
from dotenv import load_dotenv

# -------- Load env vars --------
load_dotenv()
API_KEY = os.getenv("API_KEY")
BRIDGE_URL = "http://127.0.0.1:8000/api/event"

EVENT_TYPES = ["motion", "intrusion", "access_denied", "door_open"]
ZONES = ["Lobby", "Warehouse", "ServerRoom", "MainGate"]

def send_event(event_type):
    payload = {
        "source": "simSensor-01",
        "type": event_type,
        "details": {
            "zone": random.choice(ZONES),
            "confidence": round(random.uniform(0.7, 0.99), 2)
        }
    }
    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json"
    }

    try:
        response = requests.post(BRIDGE_URL, headers=headers, data=json.dumps(payload))
        print(f"[SENT] {event_type} ({response.status_code})")
    except Exception as e:
        print(f"[ERROR] Could not reach Bridge: {e}")

print("[INFO] SynAccel Sensor Simulator started. Press Ctrl+C to stop.")
try:
    while True:
        event = random.choice(EVENT_TYPES)
        send_event(event)
        time.sleep(random.randint(2, 5))
except KeyboardInterrupt:
    print("\n[INFO] Sensor simulation stopped.")
