"""SQLite-backed nonce store so replay protection survives restarts."""
import sqlite3
import threading
import time


class SqliteNonceCache:
    def __init__(self, path: str = "logs/nonces.db", ttl_seconds: int = 900):
        self.ttl = ttl_seconds  # should exceed the accepted timestamp skew
        self._lock = threading.Lock()
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS nonces ("
            "device_id TEXT NOT NULL, nonce TEXT NOT NULL, seen_at REAL NOT NULL, "
            "PRIMARY KEY (device_id, nonce))"
        )
        self._db.commit()

    def check_and_store(self, device_id: str, nonce: str) -> bool:
        """Returns True if the nonce is new, False if it is a replay."""
        now = time.time()
        with self._lock:
            self._db.execute("DELETE FROM nonces WHERE seen_at < ?", (now - self.ttl,))
            try:
                self._db.execute("INSERT INTO nonces VALUES (?, ?, ?)", (device_id, nonce, now))
            except sqlite3.IntegrityError:
                return False
            self._db.commit()
            return True
