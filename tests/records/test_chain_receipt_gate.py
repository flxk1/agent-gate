from __future__ import annotations

from datetime import datetime, timedelta, timezone

from a2a_compliance.wire.admission import AdmissionDecision, admit, issue_permit
from a2a_compliance.wire.executor import bind_constraints
from a2a_compliance import ComplianceTeam, ControlRequest, GovernanceBlock, GroundingContext, GroundingResult
from a2a_compliance.grounding import ACTION_NO_STEER
from a2a_compliance.team import CapabilityInventory, TeamProfile

from agent_gate.gate.executor import Gate, HostMediatedExecutor
from agent_gate.gate.verdict import Verdict
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


def _gate(identity, trust_store, nonce_store, revocation_store, issuer, chain):
    return Gate(
        identity=identity, trust_store=trust_store, nonce_store=nonce_store,
        executor=HostMediatedExecutor(), signer=issuer, chain=chain,
        revocation_store=revocation_store,
    )


def test_real_gate_chain_verifies_with_host_trust_store(
    identity, trust_store, nonce_store, revocation_store, issuer, chain,
):
    identity.bind("sess-1")
    gate = _gate(identity, trust_store, nonce_store, revocation_store, issuer, chain)

    hold = gate.call(session_id="sess-1", tool="Bash", arguments={"command": "ls"},
                     permit=None, dispatch_id="d1", now=NOW)
    permit = _issue(actor="sess-1", tool="Bash", arguments={"command": "pwd"},
                    trust_store=trust_store, nonce_store=nonce_store, issuer=issuer, run_id="run-1")
    ok = gate.call(session_id="sess-1", tool="Bash", arguments={"command": "pwd"},
                   permit=permit, dispatch_id="d2", now=NOW + timedelta(seconds=1))

    assert hold.verdict is Verdict.HOLD
    assert ok.verdict is Verdict.PERMIT

    result = chain_receipt.verify(chain, trust_store=trust_store, now=NOW + timedelta(seconds=2))
    assert result.ok, result.errors


def test_real_gate_bare_receipt_forgery_is_refused(
    identity, trust_store, nonce_store, revocation_store, issuer, chain,
):
    identity.bind("sess-1")
    gate = _gate(identity, trust_store, nonce_store, revocation_store, issuer, chain)
    hold = gate.call(session_id="sess-1", tool="Bash", arguments={"command": "ls"},
                     permit=None, dispatch_id="d1", now=NOW)
    assert hold.verdict is Verdict.HOLD

    tail = chain.all()[-1]
    tail["tool"] = "Write"
    result = chain_receipt.verify(chain, trust_store=trust_store, now=NOW + timedelta(seconds=1))
    assert result.ok is False


def test_real_gate_refusal_chain_verifies_without_trust_store_required_to_reject(
    identity, trust_store, nonce_store, revocation_store, issuer, chain,
):
    identity.bind("sess-1")
    gate = _gate(identity, trust_store, nonce_store, revocation_store, issuer, chain)
    gate.call(session_id="sess-1", tool="Bash", arguments={"command": "ls"},
             permit=None, dispatch_id="d1", now=NOW)
    assert chain_receipt.verify(chain).ok is False


def test_gate_receipt_after_a_record_envelope_links_and_verifies(
    identity, trust_store, nonce_store, revocation_store, issuer, chain,
):
    chain_receipt.build_record(signer=issuer, chain=chain, tool="card.override", payload={"v": 1},
                               executor_id="felix", executor_role="human", now=NOW)
    identity.bind("sess-1")
    gate = _gate(identity, trust_store, nonce_store, revocation_store, issuer, chain)
    gate.call(session_id="sess-1", tool="Bash", arguments={"command": "ls"},
              permit=None, dispatch_id="d1", now=NOW)
    result = chain_receipt.verify(chain, trust_store=trust_store, now=NOW + timedelta(seconds=1))
    assert result.ok, result.errors


def test_backup_restore_keeps_a_real_gate_chain_verifiable(
    identity, trust_store, nonce_store, revocation_store, issuer, chain, tmp_path,
):
    from agent_gate.ops import backup
    identity.bind("sess-1")
    gate = _gate(identity, trust_store, nonce_store, revocation_store, issuer, chain)
    gate.call(session_id="sess-1", tool="Bash", arguments={"command": "ls"},
              permit=None, dispatch_id="d1", now=NOW)
    chain_receipt.build_record(signer=issuer, chain=chain, tool="card.override", payload={"v": 1},
                               executor_id="felix", executor_role="human", now=NOW)
    later = NOW + timedelta(seconds=1)
    assert chain_receipt.verify(chain, trust_store=trust_store, now=later).ok
    out = tmp_path / "b.enc"
    backup.create_backup(str(out), passphrase="pw", chain=chain, keys_root=str(tmp_path / "k"))
    restored = backup.JsonlChain(tmp_path / "restored.jsonl")
    backup.restore_backup(str(out), passphrase="pw", chain=restored, keys_root=str(tmp_path / "k2"))
    result = chain_receipt.verify(restored, trust_store=trust_store, now=later)
    assert result.ok, result.errors


def test_guards_count_a_sessions_real_gate_calls(
    identity, trust_store, nonce_store, revocation_store, issuer, chain,
):
    from agent_gate.ops import guardian_watch
    identity.bind("sess-1")
    identity.bind("sess-2")
    gate = _gate(identity, trust_store, nonce_store, revocation_store, issuer, chain)
    for i in range(5):
        gate.call(session_id="sess-1", tool="Bash", arguments={"command": "ls"},
                  permit=None, dispatch_id=f"a{i}", now=NOW)
    permit = _issue(actor="sess-1", tool="Bash", arguments={"command": "pwd"},
                    trust_store=trust_store, nonce_store=nonce_store, issuer=issuer, run_id="run-p")
    gate.call(session_id="sess-1", tool="Bash", arguments={"command": "pwd"},
              permit=permit, dispatch_id="p1", now=NOW)
    gate.call(session_id="sess-2", tool="Bash", arguments={"command": "ls"},
              permit=None, dispatch_id="b0", now=NOW)
    rules = [guardian_watch.WatchRule("rate", "rate", 100, window_seconds=10_000_000)]
    kw = {"trust_store": trust_store, "now": NOW.timestamp() + 1}
    assert guardian_watch.watch_metrics(chain, "sess-1", rules, **kw)["rate"] == 6.0
    assert guardian_watch.watch_metrics(chain, "sess-2", rules, **kw)["rate"] == 1.0


def test_refusals_for_an_unbound_session_do_not_count_toward_it(
    identity, trust_store, nonce_store, revocation_store, issuer, chain,
):
    from agent_gate.ops import guardian_watch
    identity.bind("victim")
    gate = _gate(identity, trust_store, nonce_store, revocation_store, issuer, chain)
    gate.call(session_id="victim", tool="Bash", arguments={"command": "ls"},
              permit=None, dispatch_id="own", now=NOW)
    for i in range(4):
        gate.refuse(session_id="victim", tool="Bash", arguments={"command": "sudo ls"},
                    dispatch_id=f"x{i}", reasons=("not bound to this process",), now=NOW)
        gate.call(session_id="ghost", tool="Bash", arguments={"command": "ls"},
                  permit=None, dispatch_id=f"g{i}", now=NOW)
    rules = [guardian_watch.WatchRule("rate", "rate", 100, window_seconds=10_000_000)]
    kw = {"trust_store": trust_store, "now": NOW.timestamp() + 1}
    assert guardian_watch.watch_metrics(chain, "victim", rules, **kw)["rate"] == 1.0
    assert guardian_watch.watch_metrics(chain, "ghost", rules, **kw)["rate"] == 0.0
