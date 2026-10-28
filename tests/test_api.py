import json
import time
import uuid

import pytest
from fastapi.testclient import TestClient

from src.security.signing import sign_event


@pytest.fixture()
def client(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)  # keep logs/ out of the repo
    from src.bridge_core import main

    monkeypatch.setattr(main, "API_KEY", "test-key")
    monkeypatch.setattr(main, "DEVICE_SECRETS", {"dev1": "s3cret"})
    main.recent_events.clear()
    return TestClient(main.app)


def make_event(**over):
    ev = {
        "device_id": "dev1",
        "ts": int(time.time()),
        "nonce": uuid.uuid4().hex,
        "source": "door_A1",
        "type": "motion",
        "details": {"zone": "lab"},
    }
    ev.update(over)
    ev["sig"] = sign_event("s3cret", ev)
    return ev


H = {"Authorization": "Bearer test-key"}


def test_health(client):
    assert client.get("/health").json()["status"] == "ok"


def test_valid_event_accepted(client):
    r = client.post("/api/event", json=make_event(), headers=H)
    assert r.status_code == 200


def test_missing_and_bad_api_key(client):
    assert client.post("/api/event", json=make_event()).status_code == 401
    r = client.post("/api/event", json=make_event(), headers={"Authorization": "Bearer nope"})
    assert r.status_code == 401


def test_tampered_payload_rejected(client):
    ev = make_event()
    ev["type"] = "intrusion"
    assert client.post("/api/event", json=ev, headers=H).json()["detail"] == "bad_signature"


def test_replay_rejected(client):
    ev = make_event()
    assert client.post("/api/event", json=ev, headers=H).status_code == 200
    r = client.post("/api/event", json=ev, headers=H)
    assert r.status_code == 409


def test_stale_timestamp_rejected(client):
    r = client.post("/api/event", json=make_event(ts=int(time.time()) - 10_000), headers=H)
    assert r.json()["detail"] == "stale_timestamp"


def test_intrusion_spike_raises_alert_and_risk(client):
    last = None
    for _ in range(3):
        last = client.post("/api/event", json=make_event(type="intrusion"), headers=H).json()
    assert last["alerts_triggered"] >= 1
    risk = client.get("/api/risk", headers=H).json()
    assert risk and risk[0]["source"] == "door_A1" and risk[0]["score"] > 0


def test_dashboard_risk_endpoint(client):
    assert isinstance(client.get("/dashboard/risk").json(), list)


def test_dashboard_page_renders(client, monkeypatch):
    from pathlib import Path

    # templates are resolved relative to the repo root, not the temp cwd
    from src.ui import dashboard
    from fastapi.templating import Jinja2Templates

    root = Path(__file__).resolve().parents[1]
    monkeypatch.setattr(dashboard, "templates", Jinja2Templates(directory=str(root / "src/ui/templates")))
    r = client.get("/dashboard/")
    assert r.status_code == 200
    assert "Source Risk" in r.text
