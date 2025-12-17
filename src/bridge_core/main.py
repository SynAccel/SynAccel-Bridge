# ---------- Imports ----------
from fastapi import FastAPI, Depends, HTTPException, Security
from fastapi.security import APIKeyHeader
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from dotenv import load_dotenv
from datetime import datetime, timezone
from pathlib import Path
import os
import json
import time
from typing import Dict

from src.intelligence.correlation_engine import correlate_events
from src.ui.dashboard import router as dashboard_router
from src.security.signing import verify_event
from src.security.replay import NonceCache

# ---------- Load environment variables ----------
ENV_PATH = Path(__file__).resolve().parents[2] / ".env"   # repo root/.env
load_dotenv(dotenv_path=ENV_PATH, override=True)

API_KEY = os.getenv("API_KEY")
print("Loaded API_KEY:", API_KEY)

raw_secrets = os.getenv("DEVICE_SECRETS")
print("Raw DEVICE_SECRETS env:", raw_secrets)

DEVICE_SECRETS: Dict[str, str] = json.loads(raw_secrets) if raw_secrets else {}
print("Loaded DEVICE_SECRETS keys:", list(DEVICE_SECRETS.keys()))

MAX_SKEW_SECONDS = int(os.getenv("MAX_SKEW_SECONDS", "300"))
nonce_cache = NonceCache(max_per_device=2000)

# ---------- Create app ----------
app = FastAPI(title="SynAccel-Bridge API", version="0.2")
app.include_router(dashboard_router)

# ---------- Security system ----------
api_key_header = APIKeyHeader(name="Authorization", auto_error=False)

async def verify_api_key(api_key: str = Security(api_key_header)):
    """Verify that the Authorization header matches the API key."""
    print("Received API key header:", api_key)
    print("Expected API key:", f"Bearer {API_KEY}")

    if not api_key:
        raise HTTPException(status_code=401, detail="Missing API key")
    if api_key != f"Bearer {API_KEY}" and api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return True

# ---------- Pydantic model ----------
class Event(BaseModel):
    # integrity / anti-replay fields
    device_id: str
    ts: int
    nonce: str
    sig: str

    # existing fields
    source: str
    type: str
    details: dict

# ---------- Routes ----------
@app.get("/")
def index():
    return {"message": "SynAccel-Bridge API is running"}

recent_events = []

@app.post("/api/event")
async def receive_event(event: Event, authorized: bool = Depends(verify_api_key)):
    """Receive and process a security or sensor event."""

    # ----- v0.2 integrity + anti-replay checks -----
    now = int(time.time())

    # A) reject stale timestamps (prevents replay of old events)
    if abs(event.ts - now) > MAX_SKEW_SECONDS:
        raise HTTPException(status_code=400, detail="stale_timestamp")

    # B) basic nonce sanity (helps ensure it's actually random-ish)
    if len(event.nonce) < 16:
        raise HTTPException(status_code=400, detail="nonce_too_short")

    # C) verify the device is known
    secret = DEVICE_SECRETS.get(event.device_id)
    if not secret:
        raise HTTPException(status_code=401, detail="unknown_device")

    # D) verify signature (tamper-proof)
    event_dict = event.dict()
    if not verify_event(secret, event_dict):
        raise HTTPException(status_code=401, detail="bad_signature")

    # E) reject replayed nonces
    if not nonce_cache.check_and_store(event.device_id, event.nonce):
        raise HTTPException(status_code=409, detail="replay_detected")

    # ----- normal processing -----
    log_entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "device_id": event.device_id,
        "ts": event.ts,
        "nonce": event.nonce,
        "source": event.source,
        "type": event.type,
        "details": event.details
    }

    logs_dir = Path("logs")
    logs_dir.mkdir(exist_ok=True)

    # 1. Log the raw event
    log_file = logs_dir / "events_log.jsonl"
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(log_entry) + "\n")

    # 2. Maintain a short history for correlation
    recent_events.append(log_entry)
    if len(recent_events) > 20:
        recent_events.pop(0)

    # 3. Run correlation analysis
    print("[DEBUG] Running correlation engine with", len(recent_events), "events")
    alerts = correlate_events(recent_events)

    # 4. If alerts exist, enrich and write them
    if alerts:
        alerts_file = logs_dir / "alerts_log.jsonl"
        with open(alerts_file, "a", encoding="utf-8") as f:
            for alert in alerts:
                if "details" in log_entry and isinstance(log_entry["details"], dict):
                    telemetry = log_entry["details"]
                    alert["lidar_status"] = telemetry.get("lidar_status", "N/A")
                    alert["speed_kph"] = telemetry.get("speed_kph", "N/A")
                    alert["battery_percent"] = telemetry.get("battery_percent", "N/A")

                f.write(json.dumps(alert) + "\n")

        for a in alerts:
            lid = a.get("lidar_status", "N/A")
            spd = a.get("speed_kph", "N/A")
            print(f"[⚠] {a.get('severity','info').upper()} | {a.get('message','Alert')} | LIDAR={lid}, Speed={spd}")

    print(f"[✔] Logged {event.type} from {event.source} (device_id={event.device_id})")
    return {"received": True, "alerts_triggered": len(alerts), "data": event.dict()}

@app.get("/api/alerts")
def get_alerts():
    """Return all alerts as JSON list."""
    alerts = []
    alerts_file = Path("logs/alerts_log.jsonl")
    if alerts_file.exists():
        with open(alerts_file, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    alerts.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    print(f"Returning {len(alerts)} alerts from {alerts_file}")
    return JSONResponse(content=alerts)
