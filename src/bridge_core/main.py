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

from src.intelligence.correlation_engine import correlate_events
from src.ui.dashboard import router as dashboard_router

# ---------- Load environment variables ----------
load_dotenv()
API_KEY = os.getenv("API_KEY")
print("Loaded API_KEY:", API_KEY)

# ---------- Create app ----------
app = FastAPI(title="SynAccel-Bridge API", version="0.1")
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
    log_entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": event.source,
        "type": event.type,
        "details": event.details
    }

    logs_dir = Path("logs")
    logs_dir.mkdir(exist_ok=True)

    # 1. Log the raw event
    log_file = logs_dir / "events_log.jsonl"
    with open(log_file, "a") as f:
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
        with open(alerts_file, "a") as f:
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
            print(f"[⚠] {a['severity'].upper()} | {a['message']} | LIDAR={lid}, Speed={spd}")

    print(f"[✔] Logged {event.type} from {event.source}")
    return {"received": True, "alerts_triggered": len(alerts), "data": event.dict()}

@app.get("/api/alerts")
def get_alerts():
    """Return all alerts as JSON list."""
    alerts = []
    alerts_file = Path("logs/alerts_log.jsonl")
    if alerts_file.exists():
        with open(alerts_file, "r") as f:
            for line in f:
                try:
                    alerts.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    print(f"Returning {len(alerts)} alerts from {alerts_file}")
    return JSONResponse(content=alerts)
