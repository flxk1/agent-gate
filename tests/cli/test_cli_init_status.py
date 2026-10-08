from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from agent_gate.cli import main
from agent_gate.host import home as host_home


@pytest.fixture
def home(tmp_path, monkeypatch):
    root = tmp_path / "gate-home"
    monkeypatch.setenv("AGENT_GATE_HOME", str(root))
    monkeypatch.delenv("AGENT_GATE_POLICY", raising=False)
    monkeypatch.delenv("AGENT_GATE_HOOK_MODE", raising=False)
    return root


def _run(capsys, *argv):
    rc = main(list(argv))
    return rc, capsys.readouterr().out


def test_init_creates_key_and_is_idempotent(home, capsys):
    rc, out = _run(capsys, "init")
    assert rc == 0
    first = json.loads(out)
    assert first["root"] == str(home)
    assert (home / host_home.KEY_FILE).is_file()
    assert (home / host_home.KEY_FILE).stat().st_mode & 0o777 == 0o600
    assert first["key_id"]

    rc, out = _run(capsys, "init")
    assert rc == 0
    assert json.loads(out)["key_id"] == first["key_id"]


def test_status_nonzero_before_init_zero_after(home, capsys):
    rc, out = _run(capsys, "status")
    assert rc != 0
    assert json.loads(out)["initialized"] is False
    assert not (home / host_home.KEY_FILE).exists()

    _run(capsys, "init")
    rc, out = _run(capsys, "status")
    assert rc == 0
    status = json.loads(out)
    assert status["initialized"] is True
    assert status["mode"] == "monitor"
    assert status["policy_loaded"] is False


def _gate_chain(home):
    from agent_gate.gate.executor import Gate
    from agent_gate.host import stores
    from agent_gate.identity import SessionIdentity
    from agent_gate.identity.agent_keys import AgentKeyTrustStore
    from agent_gate.ops.backup import JsonlChain

    info = host_home.init_home()
    gate = Gate(
        identity=SessionIdentity(root=info["root"]),
        trust_store=AgentKeyTrustStore(root=info["keys_root"]),
        nonce_store=stores.FileNonceStore(info["root"]),
        executor=None,
        signer=host_home.host_issuer(),
        chain=JsonlChain(info["chain_path"]),
        revocation_store=stores.FileRevocationStore(info["root"]),
    )
    for i in range(3):
        gate.call(session_id="s1", tool="Bash", arguments={"command": f"sudo x{i}"},
                  permit=None, dispatch_id=f"d{i}", now=datetime.now(timezone.utc))
    return info


def test_status_nonzero_when_chain_does_not_verify(home, capsys):
    info = _gate_chain(home)
    rc, out = _run(capsys, "status")
    assert rc == 0 and json.loads(out)["chain_verified"] is True

    path = home / "chain.jsonl"
    lines = path.read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[1])
    rec["tool"] = "Write"
    lines[1] = json.dumps(rec)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    rc, out = _run(capsys, "status")
    assert rc != 0
    assert json.loads(out)["chain_verified"] is False


def test_audit_tail_n_zero_prints_nothing(home, capsys):
    info = _gate_chain(home)
    chain, keys = info["chain_path"], info["keys_root"]

    rc, out = _run(capsys, "audit", "tail", chain, "--keys-root", keys, "-n", "0")
    assert rc == 0
    assert out == ""

    rc, out = _run(capsys, "audit", "tail", chain, "--keys-root", keys, "-n", "2")
    assert rc == 0
    tail = [json.loads(line) for line in out.splitlines()]
    assert [r["dispatch_id"] for r in tail] == ["d1", "d2"]

    rc, out = _run(capsys, "audit", "tail", chain, "--keys-root", keys, "-n", "10")
    assert rc == 0
    assert len(out.splitlines()) == 3


def _revoke_host_key(capsys):
    from agent_gate.identity import agent_keys
    assert main(["init"]) == 0
    info = json.loads(capsys.readouterr().out)
    assert agent_keys.revoke_agent_key(info["key_id"], root=info["keys_root"])
    return info


def test_init_exits_1_when_the_host_key_is_revoked(home, capsys):
    _revoke_host_key(capsys)
    assert main(["init"]) == 1
    assert "is revoked" in capsys.readouterr().err


def test_status_exits_1_when_the_host_key_is_revoked(home, capsys):
    _revoke_host_key(capsys)
    assert main(["status"]) == 1
    assert json.loads(capsys.readouterr().out)["key_live"] is False
