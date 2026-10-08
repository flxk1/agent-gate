from __future__ import annotations

from datetime import datetime, timedelta, timezone

from a2a_compliance.wire.admission import AdmissionDecision, admit, issue_permit
from a2a_compliance.wire.chain import verify_chain
from a2a_compliance.wire.executor import bind_constraints
from a2a_compliance import ComplianceTeam, ControlRequest, GovernanceBlock, GroundingContext, GroundingResult
from a2a_compliance.grounding import ACTION_NO_STEER
from a2a_compliance.team import CapabilityInventory, TeamProfile

from agent_gate.gate.executor import Gate, HostMediatedExecutor
from agent_gate.gate.verdict import Verdict

NOW = datetime(2026, 10, 7, tzinfo=timezone.utc)


def _plan(actor: str, kind: str, governance: GovernanceBlock):
    context = GroundingContext(maker_id=actor, proposed_action={"bearer": actor, "action": kind})
    request = ControlRequest(context, kind, governance, profile=TeamProfile.PROTOCOL)
    result = GroundingResult([], None, ACTION_NO_STEER, "test")
    return ComplianceTeam(CapabilityInventory()).assess(request, result)


def _issue(*, actor, tool, arguments, trust_store, nonce_store, issuer, run_id, now=NOW):
    governance = GovernanceBlock.from_dict({"actions": [{"kind": tool}]})
    plan = _plan(actor, tool, governance)
    admission = admit(plan, (), governance=governance, trust_store=trust_store, now=now)
    assert admission.decision is AdmissionDecision.ADMITTED
    constraints = bind_constraints(tool, arguments, extra={"actor": actor})
    issued = issue_permit(
        admission, issuer=issuer, enforcement_grade="mediated", adapter="agent-gate",
        run_id=run_id, nonce=f"{run_id}:nonce", expires_at=now + timedelta(minutes=5),
        nonce_store=nonce_store, constraints=constraints, issued_at=now,
    )
    assert issued.ok, issued.reasons
    return issued.permit


def _gate(identity, trust_store, nonce_store, revocation_store, issuer, chain):
    return Gate(
        identity=identity, trust_store=trust_store, nonce_store=nonce_store,
        executor=HostMediatedExecutor(), signer=issuer, chain=chain,
        revocation_store=revocation_store,
    )


def test_missing_permit_holds(identity, trust_store, nonce_store, revocation_store, issuer, chain):
    identity.bind("sess-1")
    gate = _gate(identity, trust_store, nonce_store, revocation_store, issuer, chain)
    result = gate.call(session_id="sess-1", tool="Bash", arguments={"command": "ls"},
                       permit=None, dispatch_id="d1", now=NOW)
    assert result.verdict is Verdict.HOLD
    assert chain.tail() is result.receipt


def test_action_digest_mismatch_is_refused(identity, trust_store, nonce_store, revocation_store, issuer, chain):
    identity.bind("sess-1")
    permit = _issue(actor="sess-1", tool="Bash", arguments={"command": "ls"},
                    trust_store=trust_store, nonce_store=nonce_store, issuer=issuer, run_id="run-mismatch")
    gate = _gate(identity, trust_store, nonce_store, revocation_store, issuer, chain)
    result = gate.call(session_id="sess-1", tool="Bash", arguments={"command": "rm -rf /"},
                       permit=permit, dispatch_id="d2", now=NOW)
    assert result.verdict is Verdict.DENY
    assert any("argument mutation" in r or "mismatch" in r for r in result.reasons)


def test_never_bound_session_with_actorless_permit_is_refused(
    identity, trust_store, nonce_store, revocation_store, issuer, chain,
):
    governance = GovernanceBlock.from_dict({"actions": [{"kind": "Bash"}]})
    plan = _plan("never-bound", "Bash", governance)
    admission = admit(plan, (), governance=governance, trust_store=trust_store, now=NOW)
    assert admission.decision is AdmissionDecision.ADMITTED
    constraints = bind_constraints("Bash", {"command": "ls"})
    issued = issue_permit(
        admission, issuer=issuer, enforcement_grade="mediated", adapter="agent-gate",
        run_id="run-unbound", nonce="run-unbound:nonce", expires_at=NOW + timedelta(minutes=5),
        nonce_store=nonce_store, constraints=constraints, issued_at=NOW,
    )
    assert issued.ok, issued.reasons
    gate = _gate(identity, trust_store, nonce_store, revocation_store, issuer, chain)
    result = gate.call(session_id="never-bound", tool="Bash", arguments={"command": "ls"},
                       permit=issued.permit, dispatch_id="d-unbound", now=NOW)
    assert result.verdict in (Verdict.HOLD, Verdict.DENY)
    assert result.reasons == ("session 'never-bound' is not bound to any identity",)


def test_bound_session_with_actorless_permit_is_refused(
    identity, trust_store, nonce_store, revocation_store, issuer, chain,
):
    identity.bind("sess-1")
    governance = GovernanceBlock.from_dict({"actions": [{"kind": "Bash"}]})
    plan = _plan("sess-1", "Bash", governance)
    admission = admit(plan, (), governance=governance, trust_store=trust_store, now=NOW)
    assert admission.decision is AdmissionDecision.ADMITTED
    constraints = bind_constraints("Bash", {"command": "ls"})
    issued = issue_permit(
        admission, issuer=issuer, enforcement_grade="mediated", adapter="agent-gate",
        run_id="run-noactor", nonce="run-noactor:nonce", expires_at=NOW + timedelta(minutes=5),
        nonce_store=nonce_store, constraints=constraints, issued_at=NOW,
    )
    assert issued.ok, issued.reasons
    gate = _gate(identity, trust_store, nonce_store, revocation_store, issuer, chain)
    result = gate.call(session_id="sess-1", tool="Bash", arguments={"command": "ls"},
                       permit=issued.permit, dispatch_id="d-noactor", now=NOW)
    assert result.verdict in (Verdict.HOLD, Verdict.DENY)
    assert result.reasons == ("permit carries no constraints.actor",)


def test_permit_actor_mismatch_is_refused(identity, trust_store, nonce_store, revocation_store, issuer, chain):
    identity.bind("sess-1")
    identity.bind("sess-2")
    permit = _issue(actor="sess-1", tool="Bash", arguments={"command": "ls"},
                    trust_store=trust_store, nonce_store=nonce_store, issuer=issuer, run_id="run-actor")
    gate = _gate(identity, trust_store, nonce_store, revocation_store, issuer, chain)
    result = gate.call(session_id="sess-2", tool="Bash", arguments={"command": "ls"},
                       permit=permit, dispatch_id="d3", now=NOW)
    assert result.verdict is Verdict.DENY
    assert any("does not match" in r for r in result.reasons)


def test_matching_permit_executes_exactly_once_replay_refused(
    identity, trust_store, nonce_store, revocation_store, issuer, chain,
):
    identity.bind("sess-1")
    permit = _issue(actor="sess-1", tool="Bash", arguments={"command": "ls"},
                    trust_store=trust_store, nonce_store=nonce_store, issuer=issuer, run_id="run-ok")
    gate = _gate(identity, trust_store, nonce_store, revocation_store, issuer, chain)

    first = gate.call(session_id="sess-1", tool="Bash", arguments={"command": "ls"},
                      permit=permit, dispatch_id="d4", now=NOW)
    assert first.verdict is Verdict.PERMIT
    assert first.receipt["type"] == "ToolReceipt"

    replay = gate.call(session_id="sess-1", tool="Bash", arguments={"command": "ls"},
                       permit=permit, dispatch_id="d4", now=NOW)
    assert replay.verdict is Verdict.DENY
    assert any("reuse" in r or "already consumed" in r for r in replay.reasons)


def test_chain_with_a_refusal_verifies(identity, trust_store, nonce_store, revocation_store, issuer, chain):
    identity.bind("sess-1")
    gate = _gate(identity, trust_store, nonce_store, revocation_store, issuer, chain)

    hold = gate.call(session_id="sess-1", tool="Bash", arguments={"command": "ls"},
                     permit=None, dispatch_id="d5", now=NOW)
    permit = _issue(actor="sess-1", tool="Bash", arguments={"command": "pwd"},
                    trust_store=trust_store, nonce_store=nonce_store, issuer=issuer, run_id="run-chain")
    ok = gate.call(session_id="sess-1", tool="Bash", arguments={"command": "pwd"},
                   permit=permit, dispatch_id="d6", now=NOW + timedelta(seconds=1))

    assert hold.verdict is Verdict.HOLD
    assert ok.verdict is Verdict.PERMIT
    result = verify_chain(
        chain.all(), "ToolReceipt",
        trust_store=trust_store, revocation_store=revocation_store,
        now=NOW + timedelta(seconds=2),
    )
    assert result.ok, result.errors


def test_chain_with_hold_deny_and_permit_verifies(
    identity, trust_store, nonce_store, revocation_store, issuer, chain,
):
    identity.bind("sess-1")
    identity.bind("sess-2")
    gate = _gate(identity, trust_store, nonce_store, revocation_store, issuer, chain)

    hold = gate.call(session_id="sess-1", tool="Bash", arguments={"command": "ls"},
                     permit=None, dispatch_id="d-hold", now=NOW)

    permit = _issue(actor="sess-1", tool="Bash", arguments={"command": "ls"},
                    trust_store=trust_store, nonce_store=nonce_store, issuer=issuer, run_id="run-deny")
    deny = gate.call(session_id="sess-2", tool="Bash", arguments={"command": "ls"},
                     permit=permit, dispatch_id="d-deny", now=NOW + timedelta(seconds=1))

    permit2 = _issue(actor="sess-1", tool="Bash", arguments={"command": "pwd"},
                     trust_store=trust_store, nonce_store=nonce_store, issuer=issuer, run_id="run-permit")
    ok = gate.call(session_id="sess-1", tool="Bash", arguments={"command": "pwd"},
                   permit=permit2, dispatch_id="d-permit", now=NOW + timedelta(seconds=2))

    assert hold.verdict is Verdict.HOLD
    assert deny.verdict is Verdict.DENY
    assert ok.verdict is Verdict.PERMIT
    result = verify_chain(
        chain.all(), "ToolReceipt",
        trust_store=trust_store, revocation_store=revocation_store,
        now=NOW + timedelta(seconds=3),
    )
    assert result.ok, result.errors
