from src.intelligence.anomaly import EwmaDetector
from src.intelligence.risk import RiskScorer, level_for


def test_no_flags_during_warmup():
    d = EwmaDetector(warmup=5)
    assert all(d.update("v1", "speed_kph", x) is None for x in (10, 500, 10, 10))


def test_spike_flagged_after_stable_baseline():
    d = EwmaDetector(warmup=5)
    for x in [20, 21, 19, 20, 22, 20, 21, 20]:
        assert d.update("v1", "speed_kph", x) is None
    assert d.update("v1", "speed_kph", 90) is not None


def test_sources_are_independent():
    d = EwmaDetector(warmup=3)
    for _ in range(6):
        d.update("a", "speed_kph", 10)
    assert d.update("b", "speed_kph", 90) is None


def test_risk_accumulates_and_caps():
    r = RiskScorer()
    for _ in range(10):
        s = r.add_alert("x", "high", now=0)
    assert s == 100.0


def test_risk_decays_by_half_life():
    r = RiskScorer(half_life_s=100)
    r.add_alert("x", "high", now=0)
    assert abs(r.score("x", now=100) - 17.5) < 1e-6


def test_levels():
    assert level_for(0) == "normal"
    assert level_for(55) == "high"
    assert level_for(95) == "critical"
