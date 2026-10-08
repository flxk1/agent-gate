from __future__ import annotations

from typing import Any, Optional

from a2a_compliance.wire.admission import Issuer

from ..ports import RecordSink
from ..records import chain_receipt

STAGES = ("lock", "analysis", "routing", "oversight")
_NEEDS_REVIEW_BANDS = ("low", "medium")


def review_card(
    *,
    node_id: str,
    stage: str,
    what: str,
    why: str,
    citations: Optional[list[dict]] = None,
    signals: Optional[dict[str, Any]] = None,
    inputs: Optional[list[dict]] = None,
    reserved_act: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    signals = signals or {}
    band = signals.get("completeness")
    if reserved_act is not None:
        status, human_required = "reserved", True
    elif band in _NEEDS_REVIEW_BANDS:
        status, human_required = "needs-review", True
    else:
        status, human_required = "auto", False
    return {
        "node_id": node_id,
        "stage": stage,
        "what": what,
        "why": why,
        "citations": list(citations or []),
        "signals": dict(signals),
        "inputs": list(inputs or []),
        "reserved_act": reserved_act,
        "status": status,
        "override": {"editable": True, "human_required": human_required},
    }


def record_override(
    *,
    chain: RecordSink,
    signer: Issuer,
    card: dict[str, Any],
    actor: str,
    field: str,
    new_value: Any,
    rationale: str,
    old_value: Any = None,
) -> dict[str, Any]:
    if not (actor or "").strip():
        raise ValueError("an override needs a named human actor")
    if not (rationale or "").strip():
        raise ValueError("an override needs a written rationale (why change it)")
    payload = {
        "kind": "NodeOverride",
        "node_id": card.get("node_id", ""),
        "stage": card.get("stage", ""),
        "field": field,
        "old_value": old_value,
        "new_value": new_value,
        "rationale": (rationale or "")[:500],
    }
    return chain_receipt.build_record(
        signer=signer, chain=chain, tool="agent_gate.card.override",
        payload=payload, executor_id=actor.strip(), executor_role="human",
        dispatch_id=f"override:{card.get('node_id', '')}",
    )


def overrides_for(chain: RecordSink, **verify_kwargs: Any) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for entry in chain_receipt.verified_entries(chain, **verify_kwargs):
        payload = entry.get("payload", {}) or {}
        if payload.get("kind") != "NodeOverride":
            continue
        receipt = entry.get("receipt", {}) or {}
        out.append({
            "node_id": payload.get("node_id", ""),
            "stage": payload.get("stage", ""),
            "field": payload.get("field", ""),
            "old_value": payload.get("old_value"),
            "new_value": payload.get("new_value"),
            "rationale": payload.get("rationale", ""),
            "actor": (receipt.get("executor") or {}).get("id", ""),
            "dispatch_id": receipt.get("dispatch_id", ""),
        })
    return out


def recurrence_flags(chain: RecordSink, threshold: int = 3, **verify_kwargs: Any) -> list[dict[str, Any]]:
    counts: dict[tuple, int] = {}
    for o in overrides_for(chain, **verify_kwargs):
        k = (o["stage"], o["field"])
        counts[k] = counts.get(k, 0) + 1
    return [{"kind": "propose-rule", "stage": s, "field": f, "count": n}
            for (s, f), n in sorted(counts.items()) if n >= threshold]
