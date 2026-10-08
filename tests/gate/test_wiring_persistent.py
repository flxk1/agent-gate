from __future__ import annotations

import ast
import os
import pathlib
import stat

import pytest

import agent_gate
from agent_gate.gate import wiring

SRC = pathlib.Path(agent_gate.__file__).resolve().parent
BANNED = {
    "generate_dev_keypair", "InMemoryTrustStore", "InMemoryNonceStore",
    "InMemoryRevocationStore", "_InMemoryIdentity", "_InMemoryChain",
}


def test_no_banned_names_in_non_test_src():
    offenders = []
    for path in SRC.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Name):
                names = [node.id]
            elif isinstance(node, ast.Attribute):
                names = [node.attr]
            elif isinstance(node, (ast.ClassDef, ast.FunctionDef)):
                names = [node.name]
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                names = [a.asname or a.name for a in node.names]
            for name in names:
                if name in BANNED:
                    offenders.append(f"{path.relative_to(SRC)}:{node.lineno} {name}")
    assert offenders == []


@pytest.fixture(autouse=True)
def _reset(monkeypatch, tmp_path):
    monkeypatch.setenv("AGENT_GATE_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("AGENT_GATE_POLICY", raising=False)
    wiring.reset_default_wiring()
    yield
    wiring.reset_default_wiring()


def test_build_creates_persistent_home(tmp_path):
    w = wiring.default_wiring()
    home = tmp_path / "home"
    assert home.exists()
    assert (home / "host_ed25519.key").exists()
    mode = stat.S_IMODE(os.stat(home / "host_ed25519.key").st_mode)
    assert mode == 0o600


def test_signer_is_the_persisted_host_key(tmp_path):
    from agent_gate.host import home as host_home

    w = wiring.default_wiring()
    info = host_home.init_home(root=str(tmp_path / "home"))
    assert w.issuer.key_id == info["key_id"]


def test_identity_bound_in_one_instance_resolves_in_a_fresh_one(tmp_path):
    w1 = wiring.default_wiring()
    w1.identity.bind("sess-1")
    wiring.reset_default_wiring()
    w2 = wiring.default_wiring()
    assert w2.identity.resolve("sess-1") == "sess-1"


def test_missing_policy_refuses_a_footprinted_call_and_records(tmp_path, monkeypatch):
    from agent_gate.gate.hook import evaluate

    monkeypatch.delenv("AGENT_GATE_POLICY", raising=False)
    monkeypatch.setenv("AGENT_GATE_HOOK_MODE", "enforce")
    monkeypatch.setenv("CLAUDE_CODE_SESSION_ID", "sess-missing-policy")
    evt = {"session_id": "sess-missing-policy", "tool_name": "Bash",
          "tool_input": {"command": "sudo rm -rf /"}}
    decision = evaluate(evt)
    assert decision.kind != "allow"

    w = wiring.default_wiring()
    assert w.policy_loaded is False
    assert w.chain.tail() is not None


def test_missing_policy_records_but_never_blocks_in_monitor(tmp_path, monkeypatch):
    from agent_gate.gate.hook import evaluate, emit, Decision

    monkeypatch.delenv("AGENT_GATE_POLICY", raising=False)
    monkeypatch.setenv("AGENT_GATE_HOOK_MODE", "monitor")
    evt = {"session_id": "sess-monitor", "tool_name": "Bash",
          "tool_input": {"command": "sudo rm -rf /"}}
    decision = evaluate(evt)
    with pytest.raises(SystemExit) as exc:
        emit(decision, "monitor")
    assert exc.value.code == 0

    w = wiring.default_wiring()
    assert w.chain.tail() is not None


def test_unparsable_policy_refuses_a_footprinted_call(tmp_path, monkeypatch):
    from agent_gate.gate.hook import evaluate

    bad = tmp_path / "bad.lg"
    bad.write_bytes(b"\xff\xfe\x00bad")
    monkeypatch.setenv("AGENT_GATE_POLICY", str(bad))
    monkeypatch.setenv("AGENT_GATE_HOOK_MODE", "enforce")
    evt = {"session_id": "sess-unparsable", "tool_name": "Bash",
          "tool_input": {"command": "sudo rm -rf /"}}
    decision = evaluate(evt)
    assert decision.kind != "allow"
    w = wiring.default_wiring()
    assert w.policy_loaded is False


def test_unreadable_root_fails_closed(tmp_path, monkeypatch):
    root = tmp_path / "locked-home"
    root.mkdir()
    os.chmod(root, 0o000)
    monkeypatch.setenv("AGENT_GATE_HOME", str(root / "nested"))
    try:
        with pytest.raises(Exception):
            wiring.default_wiring()
    finally:
        os.chmod(root, 0o700)


def test_unreadable_key_fails_closed_through_hook_evaluate(tmp_path, monkeypatch):
    from agent_gate.gate.hook import evaluate

    home = tmp_path / "home"
    wiring.default_wiring()
    kp = home / "host_ed25519.key"
    os.chmod(kp, 0o000)
    wiring.reset_default_wiring()
    try:
        evt = {"session_id": "sess-x", "tool_name": "Bash", "tool_input": {"command": "sudo ls"}}
        decision = evaluate(evt)
        assert decision.kind == "fail"
    finally:
        os.chmod(kp, 0o600)


def test_unreadable_nonce_store_fails_closed_never_allows(tmp_path):
    from datetime import datetime, timedelta, timezone

    from a2a_compliance.wire.admission import AdmissionDecision, admit, issue_permit
    from a2a_compliance.wire.executor import bind_constraints
    from a2a_compliance import ComplianceTeam, ControlRequest, GovernanceBlock, GroundingContext, GroundingResult
    from a2a_compliance.grounding import ACTION_NO_STEER
    from a2a_compliance.team import CapabilityInventory, TeamProfile

    from agent_gate.gate.executor import Gate, HostMediatedExecutor

    now = datetime(2026, 10, 7, tzinfo=timezone.utc)
    w = wiring.default_wiring()
    w.identity.bind("sess-1")

    governance = GovernanceBlock.from_dict({"actions": [{"kind": "Bash"}]})
    context = GroundingContext(maker_id="sess-1", proposed_action={"bearer": "sess-1", "action": "Bash"})
    request = ControlRequest(context, "Bash", governance, profile=TeamProfile.PROTOCOL)
    result = GroundingResult([], None, ACTION_NO_STEER, "test")
    plan = ComplianceTeam(CapabilityInventory()).assess(request, result)
    admission = admit(plan, (), governance=governance, trust_store=w.trust_store, now=now)
    assert admission.decision is AdmissionDecision.ADMITTED
    constraints = bind_constraints("Bash", {"command": "ls"}, extra={"actor": "sess-1"})
    issued = issue_permit(
        admission, issuer=w.issuer, enforcement_grade="mediated", adapter="agent-gate",
        run_id="r1", nonce="r1:n1", expires_at=now + timedelta(minutes=5),
        nonce_store=w.nonce_store, constraints=constraints, issued_at=now,
    )
    assert issued.ok, issued.reasons

    from agent_gate.host import home as host_home

    nonces_root = host_home.home_root() / "nonces"
    nonces_root.mkdir(parents=True, exist_ok=True)
    os.chmod(nonces_root, 0o000)
    gate = Gate(
        identity=w.identity, trust_store=w.trust_store, nonce_store=w.nonce_store,
        executor=HostMediatedExecutor(), signer=w.issuer, chain=w.chain,
        revocation_store=w.revocation_store,
    )
    try:
        with pytest.raises(Exception):
            gate.call(session_id="sess-1", tool="Bash", arguments={"command": "ls"},
                     permit=issued.permit, dispatch_id="r1", now=now)
    finally:
        os.chmod(nonces_root, 0o700)


def test_init_home_idempotent_via_wiring(tmp_path):
    w1 = wiring.default_wiring()
    key_id_1 = w1.issuer.key_id
    wiring.reset_default_wiring()
    w2 = wiring.default_wiring()
    assert w2.issuer.key_id == key_id_1
