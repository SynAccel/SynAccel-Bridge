"""Rolling per-source risk score: alerts add weight, which decays exponentially over time."""
import time
from typing import Dict, List, Optional

SEVERITY_WEIGHTS = {"low": 5.0, "medium": 15.0, "high": 35.0, "critical": 60.0}

LEVELS = [(80.0, "critical"), (50.0, "high"), (20.0, "elevated"), (0.0, "normal")]


def level_for(score: float) -> str:
    for threshold, name in LEVELS:
        if score >= threshold:
            return name
    return "normal"


class RiskScorer:
    def __init__(self, half_life_s: float = 300.0, cap: float = 100.0):
        self.half_life_s = half_life_s
        self.cap = cap
        self._scores: Dict[str, float] = {}
        self._updated: Dict[str, float] = {}

    def _decayed(self, source: str, now: float) -> float:
        last = self._updated.get(source)
        if last is None:
            return 0.0
        elapsed = max(0.0, now - last)
        return self._scores[source] * 0.5 ** (elapsed / self.half_life_s)

    def add_alert(self, source: str, severity: str, now: Optional[float] = None) -> float:
        now = time.time() if now is None else now
        score = min(self.cap, self._decayed(source, now) + SEVERITY_WEIGHTS.get(severity, 5.0))
        self._scores[source] = score
        self._updated[source] = now
        return score

    def score(self, source: str, now: Optional[float] = None) -> float:
        return self._decayed(source, time.time() if now is None else now)

    def snapshot(self, now: Optional[float] = None) -> List[dict]:
        now = time.time() if now is None else now
        rows = [
            {"source": s, "score": round(self._decayed(s, now), 1), "level": level_for(self._decayed(s, now))}
            for s in self._scores
        ]
        return sorted(rows, key=lambda r: r["score"], reverse=True)


# shared instance used by the API and the dashboard
scorer = RiskScorer()
