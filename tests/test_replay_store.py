from src.security.replay_store import SqliteNonceCache


def test_replay_detected(tmp_path):
    c = SqliteNonceCache(str(tmp_path / "n.db"))
    assert c.check_and_store("d1", "a" * 16)
    assert not c.check_and_store("d1", "a" * 16)
    assert c.check_and_store("d2", "a" * 16)


def test_survives_restart(tmp_path):
    p = str(tmp_path / "n.db")
    assert SqliteNonceCache(p).check_and_store("d1", "n" * 16)
    assert not SqliteNonceCache(p).check_and_store("d1", "n" * 16)


def test_expired_nonce_pruned(tmp_path):
    c = SqliteNonceCache(str(tmp_path / "n.db"), ttl_seconds=-1)
    assert c.check_and_store("d1", "x" * 16)
    assert c.check_and_store("d1", "x" * 16)
