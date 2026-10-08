from __future__ import annotations

import os
import subprocess
import sys

import pytest

from agent_gate.identity import IdentityStoreError, SessionIdentity, session_owner_pid


def test_claim_binds_then_resolves_across_instances(tmp_path):
    assert SessionIdentity(root=tmp_path).claim("s1", pid=os.getpid()) == "s1"
    assert SessionIdentity(root=tmp_path).resolve("s1") == "s1"


def test_claim_refuses_a_session_owned_by_another_live_process(tmp_path):
    other = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        ident = SessionIdentity(root=tmp_path)
        assert ident.claim("s1", pid=other.pid) == "s1"
        assert ident.claim("s1", pid=os.getpid()) is None
        assert ident.resolve("s1") == "s1"
    finally:
        other.kill()
        other.wait()


def test_claim_takes_over_a_dead_owner(tmp_path):
    dead = subprocess.Popen([sys.executable, "-c", "pass"])
    dead.wait()
    ident = SessionIdentity(root=tmp_path)
    ident.bind("s1", pid=dead.pid)
    assert ident.claim("s1", pid=os.getpid()) == "s1"


def test_claim_takes_over_a_recycled_pid(tmp_path):
    ident = SessionIdentity(root=tmp_path, pid_start_time_fn=lambda pid: 1.0)
    ident.bind("s1", pid=os.getpid())
    fresh = SessionIdentity(root=tmp_path)
    assert fresh.claim("s1", pid=os.getpid()) == "s1"


def test_corrupt_store_fails_closed(tmp_path):
    ident = SessionIdentity(root=tmp_path)
    ident.claim("s1", pid=os.getpid())
    (tmp_path / "sessions.json").write_text("{not json", encoding="utf-8")
    with pytest.raises(IdentityStoreError):
        ident.claim("s2", pid=os.getpid())
    with pytest.raises(IdentityStoreError):
        ident.resolve("s1")


def test_session_owner_skips_shells():
    code = "from agent_gate.identity import session_owner_pid; print(session_owner_pid())"
    out = subprocess.run(["/bin/sh", "-c", f"{sys.executable} -c '{code}'; true"],
                         capture_output=True, text=True, timeout=30,
                         env={**os.environ, "PYTHONPATH": os.pathsep.join(sys.path)})
    assert out.returncode == 0, out.stderr
    assert int(out.stdout.strip()) == os.getpid()


def test_a_non_shell_process_is_its_own_owner():
    assert session_owner_pid(os.getpid()) == os.getpid()


def test_claim_without_a_readable_start_time_binds_nothing(tmp_path):
    ident = SessionIdentity(root=tmp_path, pid_start_time_fn=lambda pid: None)
    assert ident.claim("s1", pid=os.getpid()) is None
    assert not (tmp_path / "sessions.json").exists()


def test_concurrent_first_claims_have_one_winner(tmp_path):
    sleepers = [subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"]) for _ in range(6)]
    import time
    t0 = time.time() + 2.0
    code = ("import sys, time; from agent_gate.identity import SessionIdentity; "
            f"time.sleep(max(0.0, {t0} - time.time())); "
            f"print(SessionIdentity(root={str(tmp_path)!r}).claim('s1', pid=int(sys.argv[1])) or '')")
    env = {**os.environ, "PYTHONPATH": os.pathsep.join(sys.path)}
    try:
        procs = [subprocess.Popen([sys.executable, "-c", code, str(s.pid)], stdout=subprocess.PIPE,
                                  text=True, env=env) for s in sleepers]
        winners = [p.communicate(timeout=60)[0].strip() for p in procs]
        assert winners.count("s1") == 1, winners
    finally:
        for s in sleepers:
            s.kill()
            s.wait()


def test_owner_walk_stops_at_a_shell_whose_parent_is_init(monkeypatch):
    import agent_gate.identity as ident_mod
    tree = {500: (100, "python3"), 100: (1, "sh"), 1: (0, "launchd")}
    monkeypatch.setattr(ident_mod, "_parent_and_name", lambda pid: tree[pid])
    assert session_owner_pid(100) == 100
