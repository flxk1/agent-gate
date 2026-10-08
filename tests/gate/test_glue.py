from __future__ import annotations

from policy_compiler.model import OP_PERMISSION, OP_PROHIBITION, CompiledPolicy, Norm

from agent_gate.gate.glue import decide_and_permit


def _policy(operator: str, bearer: str, action: str) -> CompiledPolicy:
    return CompiledPolicy(norms=[Norm(operator=operator, bearer=bearer, action=action)])


def test_quarantined_breaker_never_issues_a_permit(quarantined_breaker, trust_store, nonce_store, issuer):
    decision = decide_and_permit(
        breaker=quarantined_breaker, policy=None, actor="actor-1", target_kind="Bash",
        tool="Bash", arguments={"command": "ls"}, trust_store=trust_store,
        nonce_store=nonce_store, issuer=issuer, run_id="run-1",
    )
    assert decision.permit is None
    assert decision.reasons


def test_no_policy_is_reserved_to_a_human_not_steered(running_breaker, trust_store, nonce_store, issuer):
    decision = decide_and_permit(
        breaker=running_breaker, policy=None, actor="actor-1", target_kind="Bash",
        tool="Bash", arguments={"command": "ls"}, trust_store=trust_store,
        nonce_store=nonce_store, issuer=issuer, run_id="run-1",
    )
    assert decision.permit is None


def test_policy_permitted_action_is_admitted_and_issues_a_permit(
    running_breaker, trust_store, nonce_store, issuer,
):
    policy = _policy(OP_PERMISSION, "actor-1", "Bash")
    decision = decide_and_permit(
        breaker=running_breaker, policy=policy, actor="actor-1", target_kind="Bash",
        tool="Bash", arguments={"command": "ls"}, trust_store=trust_store,
        nonce_store=nonce_store, issuer=issuer, run_id="run-2",
    )
    assert decision.permit is not None
    assert decision.permit["enforcement_grade"] == "mediated"
    assert decision.permit["constraints"]["actor"] == "actor-1"
    assert decision.permit["constraints"]["tool"] == "Bash"


def test_policy_forbidden_action_is_refused_even_though_declared(
    running_breaker, trust_store, nonce_store, issuer,
):
    policy = _policy(OP_PROHIBITION, "actor-1", "Bash")
    decision = decide_and_permit(
        breaker=running_breaker, policy=policy, actor="actor-1", target_kind="Bash",
        tool="Bash", arguments={"command": "rm -rf /"}, trust_store=trust_store,
        nonce_store=nonce_store, issuer=issuer, run_id="run-3",
    )
    assert decision.permit is None


def test_permit_actor_is_bound_to_the_requesting_actor(
    running_breaker, trust_store, nonce_store, issuer,
):
    policy = _policy(OP_PERMISSION, "actor-1", "Bash")
    decision = decide_and_permit(
        breaker=running_breaker, policy=policy, actor="actor-1", target_kind="Bash",
        tool="Bash", arguments={"command": "ls"}, trust_store=trust_store,
        nonce_store=nonce_store, issuer=issuer, run_id="run-4",
    )
    other = decide_and_permit(
        breaker=running_breaker, policy=_policy(OP_PERMISSION, "actor-2", "Bash"),
        actor="actor-2", target_kind="Bash", tool="Bash", arguments={"command": "ls"},
        trust_store=trust_store, nonce_store=nonce_store, issuer=issuer, run_id="run-5",
    )
    assert decision.permit["constraints"]["actor"] != other.permit["constraints"]["actor"]
