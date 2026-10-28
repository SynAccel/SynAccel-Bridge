from fastapi import APIRouter, Request
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from pathlib import Path
import json

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])
templates = Jinja2Templates(directory="src/ui/templates")

@router.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    """Render the event dashboard with the latest events"""
    log_file = Path("logs/events_log.jsonl")

    # Read last 30 lines safely
    events = []
    if log_file.exists():
        with open(log_file, "r") as f:
            for line in f:
                try:
                    events.append(json.loads(line.strip()))
                except json.JSONDecodeError:
                    continue

    # Reverse so newest are on top
    events = events[::-1][:30]

    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "events": events,
        }
    )