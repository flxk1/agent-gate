from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from agent_gate.identity import SessionIdentity
from agent_gate.identity.agent_keys import AgentKeyTrustStore
from agent_gate.ops.backup import JsonlChain
from agent_gate.ops import guardian_watch
from agent_gate.records import chain_receipt

from loomground_drift.breaker import Breaker, BreakerState, Lease

from .conftest import base_env, pretooluse_event, run_cli, run_hook

NOW = datetime(2026, 10, 8, tzinfo=timezone.utc)


def _permissive_policy(tmp_path: Path, actor: str, action: str) -> Path:
    p = tmp_path / "permissive.lg"
    p.write_text(f"{actor} may {action}.\n", encoding="utf-8")
    return p


def _footprinted_bash_evt(session_id: str, transcript: str, cwd: str) -> dict:
    return pretooluse_event(
        session_id=session_id, tool_name="Bash",
        tool_input={"command": "sudo rm -rf /tmp/x"}, cwd=cwd,
        transcript_path=transcript,
    )


def test_identity_bound_in_one_process_resolves_in_a_later_one(gate_home, transcript, tmp_path):
    home, status = gate_home
    session_id = "sess-cross-process-1"
    policy = _permissive_policy(tmp_path, session_id, "shell.exec")
    env = base_env(home, mode="enforce", policy=policy)

    proc1 = run_hook(_footprinted_bash_evt(session_id, transcript, str(tmp_path)), env=env)
    assert proc1.returncode == 0, proc1.stderr

    identity = SessionIdentity(root=status["root"])
    resolved = identity.resolve(session_id)
    assert resolved == session_id


def test_replayed_tool_call_is_refused_in_a_later_process(gate_home, transcript, tmp_path):
    home, status = gate_home
    session_id = "sess-replay"
    env = base_env(home, mode="enforce", policy=_permissive_policy(tmp_path, session_id, "shell.exec"))
    evt = _footprinted_bash_evt(session_id, transcript, str(tmp_path))
    evt["tool_use_id"] = "toolu_replay_1"
    first = run_hook(evt, env=env)
    second = run_hook(evt, env=env)
    assert first.returncode == 0 and "permissionDecision" not in first.stdout, (first.stdout, first.stderr)
    assert second.returncode == 2 or '"ask"' in second.stdout, (second.stdout, second.stderr)


def test_session_owned_by_another_live_process_is_refused(gate_home, transcript, tmp_path):
    import subprocess
    import sys
    home, status = gate_home
    session_id = "sess-hijack"
    other = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        SessionIdentity(root=status["root"]).claim(session_id, pid=other.pid)
        env = base_env(home, mode="enforce", policy=_permissive_policy(tmp_path, session_id, "shell.exec"))
        proc = run_hook(_footprinted_bash_evt(session_id, transcript, str(tmp_path)), env=env)
        assert proc.returncode == 2, (proc.stdout, proc.stderr)
        assert "not bound" in proc.stderr
        for _ in range(3):
            run_hook(_footprinted_bash_evt(session_id, transcript, str(tmp_path)), env=env)
        rules = [guardian_watch.WatchRule("rate", "rate", 100, window_seconds=10_000_000)]
        chain = JsonlChain(status["chain_path"])
        trust = AgentKeyTrustStore(root=status["keys_root"])
        assert guardian_watch.watch_metrics(chain, session_id, rules, trust_store=trust)["rate"] == 0.0
        assert len(chain.all()) == 4
    finally:
        other.kill()
        other.wait()


def test_receipts_from_separate_processes_form_one_verifiable_chain(gate_home, transcript, tmp_path):
    home, status = gate_home
    session_id = "sess-chain-1"
    policy = _permissive_policy(tmp_path, session_id, "shell.exec")
    env = base_env(home, mode="enforce", policy=policy)

    for i in range(3):
        evt = _footprinted_bash_evt(session_id, transcript, str(tmp_path))
        proc = run_hook(evt, env=env)
        assert proc.returncode == 0, proc.stderr

    chain = JsonlChain(status["chain_path"])
    entries = chain.all()
    assert len(entries) == 3, entries

    trust_store = AgentKeyTrustStore(root=status["keys_root"])
    result = chain_receipt.verify(chain, trust_store=trust_store)
    assert result.ok, result.errors


def test_monitor_mode_never_blocks_but_records(gate_home, transcript, tmp_path):
    home, status = gate_home
    session_id = "sess-monitor-1"
    env = base_env(home, mode="monitor")

    before = len(JsonlChain(status["chain_path"]).all())
    evt = _footprinted_bash_evt(session_id, transcript, str(tmp_path))
    proc = run_hook(evt, env=env)

    assert proc.returncode == 0, proc.stderr
    assert "BLOCK" not in proc.stderr
    assert "blocked" not in proc.stderr
    assert proc.stdout.strip() == ""
    assert "would ASK" in proc.stderr

    after_entries = JsonlChain(status["chain_path"]).all()
    assert len(after_entries) == before + 1
    assert after_entries[-1]["tool"] == "Bash"


def test_enforce_mode_holds_footprinted_call_without_a_permit(gate_home, transcript, tmp_path):
    home, status = gate_home
    session_id = "sess-enforce-hold-1"
    policy = _permissive_policy(tmp_path, "someone-else", "shell.exec")
    env = base_env(home, mode="enforce", policy=policy)

    before = len(JsonlChain(status["chain_path"]).all())
    evt = _footprinted_bash_evt(session_id, transcript, str(tmp_path))
    proc = run_hook(evt, env=env)

    assert proc.returncode == 0, proc.stderr
    out = json.loads(proc.stdout)
    decision = out["hookSpecificOutput"]["permissionDecision"]
    assert decision == "ask"
    assert "no permit" in out["hookSpecificOutput"]["permissionDecisionReason"]

    entries = JsonlChain(status["chain_path"]).all()
    assert len(entries) == before + 1
    assert entries[-1]["executor"]["id"].startswith("agent-gate:gate:")


def test_tampered_chain_file_trips_audit_tail_and_guardian_watch(gate_home, transcript, tmp_path):
    home, status = gate_home
    session_id = "sess-tamper-1"
    policy = _permissive_policy(tmp_path, session_id, "shell.exec")
    env = base_env(home, mode="enforce", policy=policy)

    for i in range(2):
        evt = _footprinted_bash_evt(session_id, transcript, str(tmp_path))
        proc = run_hook(evt, env=env)
        assert proc.returncode == 0, proc.stderr

    chain_path = Path(status["chain_path"])
    lines = chain_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    rec = json.loads(lines[-1])
    rec["tool"] = "Write"
    lines[-1] = json.dumps(rec)
    chain_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    audit = run_cli(["audit", "tail", str(chain_path), "-n", "0",
                     "--keys-root", status["keys_root"]], env=base_env(home))
    assert audit.returncode == 1, (audit.stdout, audit.stderr)

    chain = JsonlChain(chain_path)
    trust_store = AgentKeyTrustStore(root=status["keys_root"])
    breaker = Breaker(Lease(agent=session_id, granted_grade="L2", expires_at=NOW.timestamp() + 10_000))
    rule = guardian_watch.WatchRule("budget-guard", "budget", 1_000.0)
    result = guardian_watch.watch(chain, session_id, breaker, [rule], trust_store=trust_store)
    assert result.state is BreakerState.QUARANTINED


def test_missing_policy_in_enforce_refuses_footprinted_call(gate_home, transcript, tmp_path):
    home, status = gate_home
    session_id = "sess-no-policy-1"
    env = base_env(home, mode="enforce")

    status_proc = run_cli(["status"], env=env)
    assert json.loads(status_proc.stdout)["policy_loaded"] is False

    before = len(JsonlChain(status["chain_path"]).all())
    evt = _footprinted_bash_evt(session_id, transcript, str(tmp_path))
    proc = run_hook(evt, env=env)

    assert proc.returncode == 0, proc.stderr
    out = json.loads(proc.stdout)
    assert out["hookSpecificOutput"]["permissionDecision"] != "allow"
    assert out["hookSpecificOutput"]["permissionDecision"] == "ask"

    entries = JsonlChain(status["chain_path"]).all()
    assert len(entries) == before + 1
