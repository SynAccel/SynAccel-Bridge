import json

import pytest

from src.security.signing import verify_event


@pytest.fixture()
def sim(monkeypatch):
    from src.telemetry import vehicle_feed_simulator as sim

    monkeypatch.setattr(sim, "DEVICE_SECRETS", {"uv01": "secret"})
    return sim


def test_payload_is_signed_and_valid(sim):
    ev = sim.generate_payload("uv01")
    assert verify_event("secret", ev)
    assert len(ev["nonce"]) >= 16


def test_spike_chance_forces_high_speed(sim):
    ev = sim.generate_payload("uv01", spike_chance=1.0)
    assert ev["details"]["speed_kph"] >= 140
    assert verify_event("secret", json.loads(json.dumps(ev)))
