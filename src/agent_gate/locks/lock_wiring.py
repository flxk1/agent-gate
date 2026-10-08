from __future__ import annotations

import uuid

from . import host_deps


def _key_root_dir():
    from ..identity.session_capability import _identity_dir
    return _identity_dir()


def _capability_verifier_factory():
    from ..identity.session_capability import CapabilityVerifier
    return CapabilityVerifier.from_key_dir()


def _record_audit_drop(where, exc, **context):
    from loomground_audit_chain.audit_drop import record
    return record(where, exc, **context)


def _record_capability_refusal(*, reason, path, log_root=None):
    from loomground_audit_chain.mutation_log import append_event, resolve_log_root
    log_dir = resolve_log_root(log_root) / "agent-gate-locks"
    return append_event(log_dir, {
        "kind": "Incident",
        "incident_type": "oversight-bypassed",
        "reason": reason,
        "path": path,
        "actor": "egress-proxy",
    })


def _verify_agent_identity(headers, *, authority="", method="", path="",
                           expected_agent=None, now=None):
    from ..identity.web_bot_auth import RequestContext, verify
    hlow = {str(k).lower(): v for k, v in dict(headers).items()}
    ctx = RequestContext(authority=authority, method=method, path=path, headers=hlow)
    v = verify(hlow, ctx=ctx, expected_agent=expected_agent, now=now)
    return {"verified": v.verified, "agent": v.agent, "keyid": v.keyid, "reason": v.reason}


def _policy_admit(*, actor, target_kind="egress.cloud-llm", **_ignored):
    from ..gate.glue import decide_and_permit
    from ..gate.wiring import default_wiring
    w = default_wiring()
    decision = decide_and_permit(
        breaker=w.breaker, policy=w.policy, actor=actor, target_kind=target_kind,
        tool=target_kind, arguments={}, trust_store=w.trust_store,
        nonce_store=w.nonce_store, issuer=w.issuer,
        run_id=f"locks:{uuid.uuid4().hex}")
    if decision.permit is not None:
        return {"light": "go", "reason": ""}
    reason = "; ".join(decision.reasons)
    if any("breaker" in r for r in decision.reasons):
        return {"light": "block", "reason": reason}
    return {"light": "ask", "reason": reason}


host_deps.key_root_dir = _key_root_dir
host_deps.capability_verifier_factory = _capability_verifier_factory
host_deps.record_audit_drop = _record_audit_drop
host_deps.record_capability_refusal = _record_capability_refusal
host_deps.verify_agent_identity = _verify_agent_identity
host_deps.policy_admit = _policy_admit
