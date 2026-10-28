"""Per-source streaming anomaly detection on numeric telemetry (EWMA mean/variance)."""
from dataclasses import dataclass
from math import sqrt
from typing import Dict, Optional, Tuple


@dataclass
class _Stat:
    mean: float = 0.0
    var: float = 0.0
    n: int = 0


class EwmaDetector:
    """Flags values that deviate from a source's running baseline by more than `k` sigmas."""

    def __init__(self, alpha: float = 0.2, k: float = 4.0, warmup: int = 10, min_std: float = 1.0):
        self.alpha = alpha
        self.k = k
        self.warmup = warmup
        self.min_std = min_std  # floor so a near-constant signal doesn't flag tiny wiggles
        self._stats: Dict[Tuple[str, str], _Stat] = {}

    def update(self, source: str, metric: str, value: float) -> Optional[float]:
        """Feed a sample. Returns the z-score if it is anomalous, else None."""
        s = self._stats.setdefault((source, metric), _Stat())
        z = None

        if s.n >= self.warmup:
            std = max(sqrt(s.var), self.min_std)
            score = abs(value - s.mean) / std
            if score > self.k:
                z = score

        # Anomalies are excluded from the baseline so one spike doesn't mask the next.
        if z is None:
            if s.n == 0:
                s.mean = value
            else:
                diff = value - s.mean
                incr = self.alpha * diff
                s.mean += incr
                s.var = (1 - self.alpha) * (s.var + diff * incr)
            s.n += 1
        return z
