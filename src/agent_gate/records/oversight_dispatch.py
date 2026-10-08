from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from a2a_compliance.wire.admission import Issuer

from ..ports import RecordSink
from . import chain_receipt


@dataclass
class DispatchResult:
    ok: bool
    dispatch_id: str = ""
    error: str = ""
    channel: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"ok": self.ok, "dispatch_id": self.dispatch_id,
                "error": self.error, "channel": self.channel}


def _dispatch_id(payload: dict[str, Any], channel: str) -> str:
    h = hashlib.sha256()
    for part in (channel, str(payload.get("action", "")),
                 str(payload.get("agent", "")), str(payload.get("link", ""))):
        h.update(part.encode())
        h.update(b"|")
    return "dispatch:" + h.hexdigest()[:24]


def dispatch(
    payload: dict[str, Any],
    *,
    chain: RecordSink,
    signer: Issuer,
    channel: str,
    recipient: str = "",
    actor: str = "system",
) -> DispatchResult:
    if payload.get("render") == "options":
        opts = payload.get("options") or []
        if len(opts) < 2:
            return DispatchResult(
                False, error="residual payload must carry >=2 options "
                "(anti-ratification); refusing to dispatch as binary",
                channel=channel)
        if not payload.get("link"):
            return DispatchResult(
                False, error="residual dispatch needs a link to the decision "
                "surface (notification != decision)", channel=channel)

    did = _dispatch_id(payload, channel)
    record_payload = {
        "kind": "escalation-dispatch",
        "dispatch_id": did,
        "channel": channel,
        "recipient": recipient,
        "render": payload.get("render", "ratify"),
        "payload": payload,
        "delivered": False,
    }
    chain_receipt.build_record(
        signer=signer, chain=chain, tool="agent_gate.records.dispatch",
        payload=record_payload, executor_id=actor, executor_role="system",
        dispatch_id=did,
    )
    return DispatchResult(True, dispatch_id=did, channel=channel)


def record_decision_return(
    *,
    chain: RecordSink,
    signer: Issuer,
    dispatch_id: str,
    surface_dispatch_id: str,
    chosen_option_id: str = "",
    actor: str = "",
) -> dict[str, Any]:
    if not surface_dispatch_id.strip():
        return {"error": "a decision return must reference a decision-surface "
                "record (surface_dispatch_id) -- a ticket reply cannot close "
                "an escalation"}
    if not actor.strip():
        return {"error": "the deciding actor must be named"}
    payload = {
        "kind": "escalation-return",
        "dispatch_id": dispatch_id,
        "surface_dispatch_id": surface_dispatch_id,
        "chosen_option_id": chosen_option_id,
        "actor": actor.strip(),
    }
    envelope = chain_receipt.build_record(
        signer=signer, chain=chain, tool="agent_gate.records.decision_return",
        payload=payload, executor_id=actor.strip(), executor_role="human",
        dispatch_id=f"return:{dispatch_id}",
    )
    return {**payload, "receipt_dispatch_id": envelope["receipt"]["dispatch_id"]}
