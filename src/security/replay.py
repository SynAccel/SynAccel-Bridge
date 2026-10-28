# src/security/replay.py
from collections import defaultdict, deque

class NonceCache:
    def __init__(self, max_per_device: int = 2000):
        self.max_per_device = max_per_device
        self.seen = defaultdict(set)
        self.order = defaultdict(lambda: deque())

    def check_and_store(self, device_id: str, nonce: str) -> bool:
        """
        Returns True if nonce is new (ok), False if replay (reject).
        """
        if nonce in self.seen[device_id]:
            return False

        self.seen[device_id].add(nonce)
        self.order[device_id].append(nonce)

        # keep memory bounded
        if len(self.order[device_id]) > self.max_per_device:
            old = self.order[device_id].popleft()
            self.seen[device_id].discard(old)

        return True