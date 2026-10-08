from __future__ import annotations

import multiprocessing
import os
from datetime import datetime, timedelta, timezone

from agent_gate.host.stores import FileNonceStore, FileRevocationStore


def test_nonce_seen_and_record(tmp_path):
    store = FileNonceStore(tmp_path)
    assert store.seen("r1", "n1") is False
    store.record("r1", "n1")
    assert store.seen("r1", "n1") is True


def test_nonce_consume_once_in_process(tmp_path):
    store = FileNonceStore(tmp_path)
    assert store.consume("r1", "n1") is True
    assert store.consume("r1", "n1") is False


def _consume_worker(root: str, result_path: str) -> None:
    store = FileNonceStore(root)
    ok = store.consume("r1", "n1")
    with open(result_path, "a", encoding="utf-8") as fh:
        fh.write(("1" if ok else "0") + "\n")


def test_nonce_consume_exactly_once_across_two_processes(tmp_path):
    results = tmp_path / "results.txt"
    results.write_text("", encoding="utf-8")
    p1 = multiprocessing.Process(target=_consume_worker, args=(str(tmp_path), str(results)))
    p2 = multiprocessing.Process(target=_consume_worker, args=(str(tmp_path), str(results)))
    p1.start()
    p2.start()
    p1.join()
    p2.join()
    outcomes = [line.strip() for line in results.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert sorted(outcomes) == ["0", "1"]


def test_revocation_round_trips(tmp_path):
    store = FileRevocationStore(tmp_path)
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    assert store.is_revoked("key", "k1", at=now) is False
    store.revoke("key", "k1", now - timedelta(days=1))
    assert store.is_revoked("key", "k1", at=now) is True
    assert store.is_revoked("key", "k2", at=now) is False


def test_revocation_future_effective_date_not_yet_applied(tmp_path):
    store = FileRevocationStore(tmp_path)
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    store.revoke("key", "k1", now + timedelta(days=1))
    assert store.is_revoked("key", "k1", at=now) is False


def test_revocation_record_from_dict(tmp_path):
    store = FileRevocationStore(tmp_path)
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    store.record({"revoked_type": "run", "revoked_id": "r1", "effective_at": "2025-12-01T00:00:00Z"})
    assert store.is_revoked("run", "r1", at=now) is True


def test_nonce_store_fails_on_unreadable_root(tmp_path):
    root = tmp_path / "locked"
    root.mkdir()
    os.chmod(root, 0o000)
    store = FileNonceStore(root)
    try:
        import pytest

        with pytest.raises(Exception):
            store.consume("r1", "n1")
    finally:
        os.chmod(root, 0o700)
