# ---------- Imports ----------
from fastapi import FastAPI, Depends, HTTPException, Security
from fastapi.security import APIKeyHeader
from pydantic import BaseModel
from dotenv import load_dotenv
import os
from datetime import datetime, timezone
import json
from pathlib import Path
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
    # Accept either exact match or missing "Bearer " prefix
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
    log_file = logs_dir / "events_log.jsonl"
    with open(log_file, "a") as f:
        f.write(json.dumps(log_entry) + "\n")
        
    recent_events.append(log_entry)
    if len(recent_events) > 20:
        recent_events.pop(0)
        
    # --- 3. Run correlation analysis
    alerts = correlate_events(recent_events)

    if alerts:
        alerts_file = logs_dir / "alerts_log.jsonl"
        with open(alerts_file, "a") as f:
            for alert in alerts:
                f.write(json.dumps(alert) + "\n")
        for a in alerts:
            print(f"[⚠] {a['severity'].upper()} | {a['message']}")

    # Normal response
    print(f"[✔] Logged {event.type} from {event.source}")
    return {"received": True, "alerts_triggered": len(alerts), "data": event.dict()}
