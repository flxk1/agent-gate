from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

from a2a_compliance.wire.admission import AdmissionDecision, admit, issue_permit
from a2a_compliance.wire.executor import bind_constraints
from a2a_compliance import ComplianceTeam, ControlRequest, GovernanceBlock, GroundingContext, GroundingResult
from a2a_compliance.grounding import ACTION_NO_STEER
from a2a_compliance.team import CapabilityInventory, TeamProfile

from agent_gate.gate.executor import Gate, HostMediatedExecutor
from agent_gate.gate.verdict import Verdict
from agent_gate.identity import SessionIdentity

NOW = datetime(2026, 10, 7, tzinfo=timezone.utc)


def test_session_identity_satisfies_identity_port():
    ident = SessionIdentity()
    assert hasattr(ident, "bind") and hasattr(ident, "resolve")
    actor = ident.bind("sess-1")
    assert actor == "sess-1"
    assert ident.resolve("sess-1") == "sess-1"


def test_resolve_before_bind_is_unbound():
    assert SessionIdentity().resolve("never-bound") is None


def test_resolve_after_process_dies_is_unbound():
    ident = SessionIdentity(pid_alive_fn=lambda pid: False)
    ident.bind("sess-1", pid=12345)
    assert ident.resolve("sess-1") is None


def test_reused_pid_different_start_time_is_not_bound():
    starts = iter([100.0, 999.0])
    ident = SessionIdentity(pid_alive_fn=lambda pid: True,
                            pid_start_time_fn=lambda pid: next(starts))
    ident.bind("sess-1", pid=os.getpid())
    assert ident.resolve("sess-1") is None


def test_resolve_fails_closed_when_start_time_unknown_at_bind():
    ident = SessionIdentity(pid_alive_fn=lambda pid: True,
                            pid_start_time_fn=lambda pid: None)
    ident.bind("sess-1", pid=os.getpid())
    assert ident.resolve("sess-1") is None


def test_resolve_fails_closed_when_start_time_unreadable_now():
    starts = iter([100.0, None])
    ident = SessionIdentity(pid_alive_fn=lambda pid: True,
                            pid_start_time_fn=lambda pid: next(starts))
    ident.bind("sess-1", pid=os.getpid())
    assert ident.resolve("sess-1") is None


def _plan(actor, kind, governance):
    context = GroundingContext(maker_id=actor, proposed_action={"bearer": actor, "action": kind})
    request = ControlRequest(context, kind, governance, profile=TeamProfile.PROTOCOL)
    result = GroundingResult([], None, ACTION_NO_STEER, "test")
    return ComplianceTeam(CapabilityInventory()).assess(request, result)


def _issue_permit_for(actor, *, tool, arguments, trust_store, nonce_store, issuer, run_id):
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


def test_permit_actor_mismatch_with_bound_session_is_refused(
    trust_store, nonce_store, revocation_store, issuer, chain,
):
    identity = SessionIdentity()
    identity.bind("sess-1", pid=os.getpid())

    gate = Gate(
        identity=identity, trust_store=trust_store, nonce_store=nonce_store,
        executor=HostMediatedExecutor(), signer=issuer, chain=chain,
        revocation_store=revocation_store,
    )
    permit = _issue_permit_for(
        "some-other-actor", tool="Bash", arguments={"command": "ls"},
        trust_store=trust_store, nonce_store=nonce_store, issuer=issuer, run_id="run-1",
    )
    result = gate.call(session_id="sess-1", tool="Bash", arguments={"command": "ls"},
                       permit=permit, dispatch_id="run-1", now=NOW)
    assert result.verdict is Verdict.DENY
    assert "does not match" in result.reasons[0]


def test_permit_actor_matching_bound_session_is_permitted(
    trust_store, nonce_store, revocation_store, issuer, chain,
):
    identity = SessionIdentity()
    identity.bind("sess-1", pid=os.getpid())

    gate = Gate(
        identity=identity, trust_store=trust_store, nonce_store=nonce_store,
        executor=HostMediatedExecutor(), signer=issuer, chain=chain,
        revocation_store=revocation_store,
    )
    permit = _issue_permit_for(
        "sess-1", tool="Bash", arguments={"command": "ls"},
        trust_store=trust_store, nonce_store=nonce_store, issuer=issuer, run_id="run-2",
    )
    result = gate.call(session_id="sess-1", tool="Bash", arguments={"command": "ls"},
                       permit=permit, dispatch_id="run-2", now=NOW)
    assert result.verdict is Verdict.PERMIT
