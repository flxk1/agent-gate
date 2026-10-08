from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

import pytest

from a2a_compliance.wire.admission import AdmissionDecision, admit, dev_issuer, issue_permit
from a2a_compliance.wire.executor import bind_constraints
from a2a_compliance.wire.signing import generate_dev_keypair
from a2a_compliance import ComplianceTeam, ControlRequest, GovernanceBlock, GroundingContext, GroundingResult
from a2a_compliance.grounding import ACTION_NO_STEER
from a2a_compliance.team import CapabilityInventory, TeamProfile

from loomground_drift.breaker import Breaker, BreakerState, Lease

from agent_gate.cli import main as cli_main
from agent_gate.gate.executor import Gate, HostMediatedExecutor
from agent_gate.gate.verdict import Verdict
from agent_gate.identity import agent_keys
from agent_gate.ops import backup as backup_ops
from agent_gate.ops import guardian_watch
from agent_gate.records import chain_receipt

NOW = datetime(2026, 10, 7, tzinfo=timezone.utc)


def _plan(actor, kind, governance):
    context = GroundingContext(maker_id=actor, proposed_action={"bearer": actor, "action": kind})
    request = ControlRequest(context, kind, governance, profile=TeamProfile.PROTOCOL)
    result = GroundingResult([], None, ACTION_NO_STEER, "test")
    return ComplianceTeam(CapabilityInventory()).assess(request, result)


def _issue(*, actor, tool, arguments, trust_store, nonce_store, issuer, run_id):
    governance = GovernanceBlock.from_dict({"actions": [{"kind": tool}]})
    plan = _plan(actor, tool, governance)
    admission = admit(plan, (), governance=governance, trust_store=trust_store, now=NOW)
    assert admission.decision is AdmissionDecision.ADMITTED
    constraints = bind_constraints(tool, arguments, extra={"actor": actor})
    issued = issue_permit(
        admission, issuer=issuer, enforcement_grade="mediated", adapter="agent-gate",
        run_id=run_id, nonce=f"{run_id}:nonce", expires_at=NOW + timedelta(minutes=5),
        nonce_store=nonce_store, constraints=constraints, issued_at=NOW,
    )
    assert issued.ok, issued.reasons
    return issued.permit


@pytest.fixture
def real_chain_setup(tmp_path, identity, nonce_store, revocation_store):
    keys_root = tmp_path / "keys"
    private_key, public_key = generate_dev_keypair()
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    priv = Ed25519PrivateKey.from_private_bytes(private_key)
    pub_pem = priv.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    rec = agent_keys.register_agent_key(
        "agent-gate:test", pub_pem,
        object_types=["ExecutionPermit", "ToolReceipt"], root=str(keys_root),
    )
    issuer = dev_issuer(rec["keyid"], "agent-gate:test", private_key)
    trust_store = agent_keys.AgentKeyTrustStore(root=str(keys_root))
    chain_path = tmp_path / "chain.jsonl"
    chain = backup_ops.JsonlChain(chain_path)
    gate = Gate(
        identity=identity, trust_store=trust_store, nonce_store=nonce_store,
        executor=HostMediatedExecutor(), signer=issuer, chain=chain,
        revocation_store=revocation_store,
    )
    return {
        "keys_root": keys_root, "chain_path": chain_path, "chain": chain,
        "gate": gate, "issuer": issuer, "trust_store": trust_store,
        "nonce_store": nonce_store, "identity": identity,
    }


def test_real_gate_chain_cli_audit_tail_roundtrip(real_chain_setup, capsys):
    s = real_chain_setup
    s["identity"].bind("sess-1")
    gate, chain = s["gate"], s["chain"]

    gate.call(session_id="sess-1", tool="Bash", arguments={"command": "ls"},
             permit=None, dispatch_id="d1", now=NOW)
    permit = _issue(actor="sess-1", tool="Bash", arguments={"command": "pwd"},
                    trust_store=s["trust_store"], nonce_store=s["nonce_store"],
                    issuer=s["issuer"], run_id="run-1")
    gate.call(session_id="sess-1", tool="Bash", arguments={"command": "pwd"},
             permit=permit, dispatch_id="d2", now=NOW + timedelta(seconds=1))

    rc = cli_main(["audit", "tail", str(s["chain_path"]), "-n", "0",
                  "--keys-root", str(s["keys_root"])])
    assert rc == 0
    capsys.readouterr()

    lines = s["chain_path"].read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[0])
    rec["tool"] = "Write"
    lines[0] = json.dumps(rec)
    s["chain_path"].write_text("\n".join(lines) + "\n", encoding="utf-8")

    rc2 = cli_main(["audit", "tail", str(s["chain_path"]), "-n", "0",
                   "--keys-root", str(s["keys_root"])])
    assert rc2 == 1


def test_real_gate_chain_guardian_watch_trips_only_when_tampered(real_chain_setup):
    s = real_chain_setup
    s["identity"].bind("sess-1")
    gate, chain = s["gate"], s["chain"]

    gate.call(session_id="sess-1", tool="Bash", arguments={"command": "ls"},
             permit=None, dispatch_id="d1", now=NOW)
    permit = _issue(actor="sess-1", tool="Bash", arguments={"command": "pwd"},
                    trust_store=s["trust_store"], nonce_store=s["nonce_store"],
                    issuer=s["issuer"], run_id="run-2")
    gate.call(session_id="sess-1", tool="Bash", arguments={"command": "pwd"},
             permit=permit, dispatch_id="d2", now=NOW + timedelta(seconds=1))

    breaker = Breaker(Lease(agent="sess-1", granted_grade="L2", expires_at=time.time() + 10_000))
    rule = guardian_watch.WatchRule("g", "budget", 1000.0)
    status = guardian_watch.watch(chain, "sess-1", breaker, [rule], trust_store=s["trust_store"])
    assert status.state is not BreakerState.QUARANTINED

    lines = s["chain_path"].read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[-1])
    rec["tool"] = "Write"
    lines[-1] = json.dumps(rec)
    s["chain_path"].write_text("\n".join(lines) + "\n", encoding="utf-8")

    breaker2 = Breaker(Lease(agent="sess-1", granted_grade="L2", expires_at=time.time() + 10_000))
    status2 = guardian_watch.watch(chain, "sess-1", breaker2, [rule], trust_store=s["trust_store"])
    assert status2.state is BreakerState.QUARANTINED
