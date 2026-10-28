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
import hmac
from typing import Dict

from src.intelligence.correlation_engine import correlate_events
from src.intelligence.anomaly import EwmaDetector
from src.intelligence.risk import scorer as risk_scorer
from src.ui.dashboard import router as dashboard_router
from src.security.signing import verify_event
from src.security.replay import NonceCache
from src.security.replay_store import SqliteNonceCache

# ---------- Load environment variables ----------
ENV_PATH = Path(__file__).resolve().parents[2] / ".env"   # repo root/.env
load_dotenv(dotenv_path=ENV_PATH, override=True)

API_KEY = os.getenv("API_KEY")

raw_secrets = os.getenv("DEVICE_SECRETS")
DEVICE_SECRETS: Dict[str, str] = json.loads(raw_secrets) if raw_secrets else {}
print("Loaded DEVICE_SECRETS keys:", list(DEVICE_SECRETS.keys()))

MAX_SKEW_SECONDS = int(os.getenv("MAX_SKEW_SECONDS", "300"))
NONCE_DB_PATH = os.getenv("NONCE_DB_PATH")  # set to persist nonces across restarts
nonce_cache = (
    SqliteNonceCache(NONCE_DB_PATH, ttl_seconds=MAX_SKEW_SECONDS * 2)
    if NONCE_DB_PATH
    else NonceCache(max_per_device=2000)
)
anomaly_detector = EwmaDetector()
ANOMALY_METRICS = ("speed_kph", "battery_percent")

# ---------- Create app ----------
app = FastAPI(title="SynAccel-Bridge API", version="0.3")
app.include_router(dashboard_router)

# ---------- Security system ----------
api_key_header = APIKeyHeader(name="Authorization", auto_error=False)

async def verify_api_key(api_key: str = Security(api_key_header)):
    """Verify that the Authorization header matches the API key."""
    if not api_key:
        raise HTTPException(status_code=401, detail="Missing API key")
    if not API_KEY:
        raise HTTPException(status_code=500, detail="Server API key not configured")

    # constant-time compare to avoid leaking key prefix via timing
    supplied = api_key.encode("utf-8")
    ok = hmac.compare_digest(supplied, f"Bearer {API_KEY}".encode("utf-8")) or hmac.compare_digest(
        supplied, API_KEY.encode("utf-8")
    )
    if not ok:
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
    event_dict = event.model_dump()
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

    # 3b. Baseline anomaly detection on numeric telemetry
    for metric in ANOMALY_METRICS:
        value = event.details.get(metric)
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            continue
        z = anomaly_detector.update(event.source, metric, float(value))
        if z is not None:
            alerts.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "source": event.source,
                "rule_id": 5,
                "category": "anomaly",
                "type": "telemetry_anomaly",
                "severity": "medium",
                "message": f"{metric}={value} deviates {z:.1f} sigma from baseline on {event.source}",
            })

    for a in alerts:
        a["risk_score"] = round(risk_scorer.add_alert(a["source"], a.get("severity", "low")), 1)

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
    return {"received": True, "alerts_triggered": len(alerts), "data": event.model_dump()}

@app.get("/health")
def health():
    return {"status": "ok", "version": app.version, "known_devices": len(DEVICE_SECRETS)}

@app.get("/api/risk", dependencies=[Depends(verify_api_key)])
def get_risk():
    """Current decayed risk score per source, highest first."""
    return risk_scorer.snapshot()

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
