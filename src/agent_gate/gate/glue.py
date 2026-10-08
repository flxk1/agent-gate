from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from a2a_compliance import (
    ComplianceTeam,
    ControlRequest,
    GovernanceBlock,
    GroundingContext,
    GroundingResult,
)
from a2a_compliance.grounding import ACTION_NO_STEER
from a2a_compliance.team import CapabilityInventory, TeamProfile
from a2a_compliance.wire.admission import AdmissionDecision, Issuer, admit, issue_permit
from a2a_compliance.wire.executor import bind_constraints
from a2a_compliance.wire.trust import TrustStore
from a2a_compliance.wire.verification import NonceStore

from loomground_drift.breaker import Breaker

ADAPTER = "agent-gate"
DEFAULT_PERMIT_TTL = timedelta(minutes=5)
ENFORCEMENT_GRADE = "mediated"


@dataclass(frozen=True)
class PermitDecision:
    permit: Optional[dict]
    reasons: tuple[str, ...] = ()


def _governance_for(target_kind: str, policy_verdict: str) -> GovernanceBlock:
    if policy_verdict == "forbidden":
        return GovernanceBlock.from_dict({"prohibited": [target_kind]})
    if policy_verdict == "permitted":
        return GovernanceBlock.from_dict({"actions": [{"kind": target_kind}]})
    return GovernanceBlock.from_dict({"reserved": [{"kind": target_kind, "by": "human"}]})


def _resolve_policy_verdict(policy: Any, actor: str, target_kind: str) -> str:
    if policy is None:
        return "undetermined"
    from policy_compiler.check import resolve as policy_resolve

    verdict, _matched_lg = policy_resolve(policy, actor, target_kind)
    return verdict


def decide_and_permit(
    *,
    breaker: Breaker,
    policy: Any,
    actor: str,
    target_kind: str,
    tool: str,
    arguments: dict,
    trust_store: TrustStore,
    nonce_store: NonceStore,
    issuer: Issuer,
    run_id: str,
    now: Optional[datetime] = None,
) -> PermitDecision:
    now = now or datetime.now(timezone.utc)
    status = breaker.status(now=now.timestamp())
    if not status.running:
        return PermitDecision(None, tuple(status.reasons) or ("breaker is not running",))

    policy_verdict = _resolve_policy_verdict(policy, actor, target_kind)
    governance = _governance_for(target_kind, policy_verdict)

    context = GroundingContext(maker_id=actor, proposed_action={"bearer": actor, "action": target_kind})
    request = ControlRequest(context, target_kind, governance, profile=TeamProfile.PROTOCOL)
    grounding_result = GroundingResult([], None, ACTION_NO_STEER, "agent_gate.gate.glue")
    plan = ComplianceTeam(CapabilityInventory()).assess(request, grounding_result)

    admission = admit(plan, (), governance=governance, trust_store=trust_store, now=now)
    if admission.decision is not AdmissionDecision.ADMITTED:
        return PermitDecision(None, admission.reasons)

    constraints = bind_constraints(tool, arguments, extra={"actor": actor})
    issued = issue_permit(
        admission,
        issuer=issuer,
        enforcement_grade=ENFORCEMENT_GRADE,
        adapter=ADAPTER,
        run_id=run_id,
        nonce=f"{run_id}:permit",
        expires_at=now + DEFAULT_PERMIT_TTL,
        nonce_store=nonce_store,
        constraints=constraints,
        issued_at=now,
    )
    if not issued.ok:
        return PermitDecision(None, issued.reasons)
    return PermitDecision(issued.permit, ())
