import json
import os
import time

from agent_gate.identity import connected_agents as ca


def test_register_and_list(tmp_path):
    root = str(tmp_path)
    connid = ca.register_connection(agent="claude-code", root=root, session_id="sess-1")
    rows = ca.list_connected(root=root)
    assert len(rows) == 1
    assert rows[0]["connid"] == connid
    assert rows[0]["session_id"] == "sess-1"
    assert rows[0]["pid"] == os.getpid()


def test_register_connection_captures_session_id_from_env(tmp_path, monkeypatch):
    root = str(tmp_path)
    monkeypatch.setenv("CLAUDE_CODE_SESSION_ID", "env-sess-1")
    connid = ca.register_connection(agent="claude-code", root=root)
    rec = json.loads((ca._agents_dir(root) / f"{connid}.json").read_text())
    assert rec["session_id"] == "env-sess-1"
    assert rec["pid"] == os.getpid()
    assert rec["pid_start"] is not None
    assert ca.pid_still_same(rec["pid"], rec["pid_start"])


def test_dead_pid_self_heals(tmp_path):
    root = str(tmp_path)
    dead_pid = 999999
    ca.register_connection(agent="a", pid=dead_pid, root=root)
    rows = ca.list_connected(root=root)
    assert rows == []


def test_reused_pid_different_start_time_is_not_same_session(tmp_path):
    root = str(tmp_path)
    pid = os.getpid()
    connid = ca.register_connection(agent="a", pid=pid, root=root)
    rows = ca.list_connected(root=root)
    assert len(rows) == 1

    import json
    f = ca._agents_dir(root) / f"{connid}.json"
    rec = json.loads(f.read_text())
    rec["pid_start"] = (rec["pid_start"] or time.time()) - 10_000
    f.write_text(json.dumps(rec))

    rows = ca.list_connected(root=root)
    assert rows == []


def test_pid_still_same_fails_closed_when_start_unknown_at_bind():
    assert ca.pid_still_same(os.getpid(), None) is False


def test_pid_still_same_fails_closed_when_start_unreadable_now(monkeypatch):
    monkeypatch.setattr(ca, "pid_start_time", lambda pid: None)
    assert ca.pid_still_same(os.getpid(), 100.0) is False


def test_backfill_session_ids_reads_live_process_env(tmp_path, monkeypatch):
    root = str(tmp_path)
    pid = os.getpid()
    monkeypatch.setattr(ca, "_pid_session_id", lambda p: "backfilled-sid")
    ca.register_connection(agent="a", pid=pid, session_id="", root=root)
    updated = ca.backfill_session_ids(root=root)
    assert updated == 1
    rows = ca.list_connected(root=root)
    assert rows[0]["session_id"] == "backfilled-sid"


def test_deregister_removes_record(tmp_path):
    root = str(tmp_path)
    connid = ca.register_connection(agent="a", root=root)
    ca.deregister_connection(connid, root=root)
    assert ca.list_connected(root=root) == []


def test_update_client_info_once_only(tmp_path):
    root = str(tmp_path)
    connid = ca.register_connection(agent="a", root=root)
    assert ca.update_client_info(connid, name="cursor", version="1.0", root=root)
    assert not ca.update_client_info(connid, name="other", version="2.0", root=root)
    rows = ca.list_connected(root=root)
    assert rows[0]["client_name"] == "cursor"


def test_pid_start_time_parses_under_non_english_locale(monkeypatch):
    monkeypatch.setenv("LANG", "de_DE.UTF-8")
    monkeypatch.setenv("LC_ALL", "de_DE.UTF-8")
    assert ca.pid_start_time(os.getpid()) is not None


def test_unreadable_start_time_is_skipped_not_purged(tmp_path, monkeypatch):
    root = str(tmp_path)
    connid = ca.register_connection(agent="claude-code", root=root, session_id="sess-1")
    monkeypatch.setattr(ca, "pid_start_time", lambda pid: None)
    assert ca.list_connected(root=root) == []
    assert (ca._agents_dir(root) / f"{connid}.json").exists()


def test_recycled_pid_is_purged(tmp_path, monkeypatch):
    root = str(tmp_path)
    connid = ca.register_connection(agent="claude-code", root=root, session_id="sess-1")
    monkeypatch.setattr(ca, "pid_start_time", lambda pid: 1.0)
    assert ca.list_connected(root=root) == []
    assert not (ca._agents_dir(root) / f"{connid}.json").exists()
