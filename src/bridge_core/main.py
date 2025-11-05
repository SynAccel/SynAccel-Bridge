# ---------- Imports ----------
from fastapi import FastAPI, Depends, HTTPException, Security
from fastapi.security import APIKeyHeader
from pydantic import BaseModel
from dotenv import load_dotenv
import os
from datetime import datetime, timezone
import json
from pathlib import Path

# ---------- Load environment variables ----------
load_dotenv()
API_KEY = os.getenv("API_KEY")
print("Loaded API_KEY:", API_KEY)


# ---------- Create app ----------
app = FastAPI(title="SynAccel-Bridge API", version="0.1")

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

    return {
        "received": True,
        "message": "Event logged successfully",
        "data": event.dict()
    }
