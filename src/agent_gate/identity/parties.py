from __future__ import annotations

import uuid
from typing import Any, Optional

from ..ports import RecordSink
from ..records import chain_receipt
from ..subject import Subject

PARTY_KINDS = ("human", "agent")
PARTY_STATUSES = ("active", "suspended", "killed")


def _append(log: RecordSink, signer: Any, actor: str, extra: dict) -> None:
    if signer is None:
        raise ValueError("register_party/set_party_status require a signer -- an unsigned party event would never verify on read")
    chain_receipt.build_record(signer=signer, chain=log, tool="PartyEvent", payload=extra,
                               executor_id=actor, executor_role="party-registry")


def _verify_kwargs(trust_store, nonce_store, revocation_store, genesis_prev_digest):
    return {"trust_store": trust_store, "nonce_store": nonce_store,
            "revocation_store": revocation_store, "genesis_prev_digest": genesis_prev_digest}


def register_party(
    log: RecordSink, subject: Subject, kind: str, *,
    signer: Any = None,
    name: str = "", role: str = "", competences: Optional[list[str]] = None,
    channels: Optional[list[str]] = None, owner: str = "", purpose: str = "",
    grade: str = "", agent_uid: str = "", actor: str = "user",
    trust_store: Any = None, nonce_store: Any = None,
    revocation_store: Any = None, genesis_prev_digest: Optional[str] = None,
) -> dict[str, Any]:
    if kind not in PARTY_KINDS:
        raise ValueError(f"kind must be one of {PARTY_KINDS}, got {kind!r}")
    party_id = str(subject)
    if kind == "agent":
        vk = _verify_kwargs(trust_store, nonce_store, revocation_store, genesis_prev_digest)
        if log.tail() is not None and not chain_receipt.verify(log, **vk).ok:
            raise ValueError("party log does not verify: refusing to mint or reuse an agent_uid")
        prior = _list_parties_local(log, **_verify_kwargs(trust_store, nonce_store, revocation_store, genesis_prev_digest))
        previous = next((p for p in prior["parties"]
                         if p.get("party_id") == party_id and p.get("party_kind") == "agent"), None)
        agent_uid = agent_uid or (previous or {}).get("agent_uid", "")
        if not agent_uid:
            agent_uid = str(uuid.uuid4())
        try:
            agent_uid = str(uuid.UUID(agent_uid))
        except (ValueError, AttributeError, TypeError) as exc:
            raise ValueError("agent_uid must be a UUID") from exc
    else:
        agent_uid = ""
    _append(log, signer, actor, {
        "kind": "PartyRegistered", "party_id": party_id, "party_kind": kind,
        "name": name, "role": role, "competences": list(competences or []),
        "channels": list(channels or []), "owner": owner, "purpose": purpose,
        "grade": grade, "agent_uid": agent_uid,
    })
    result: dict[str, Any] = {"ok": True, "party_id": party_id}
    if agent_uid:
        result["agent_uid"] = agent_uid
    return result


def set_party_status(
    log: RecordSink, subject: Subject, status: str, *,
    signer: Any = None, reason: str = "", actor: str = "user",
) -> dict[str, Any]:
    if status not in PARTY_STATUSES:
        raise ValueError(f"status must be one of {PARTY_STATUSES}, got {status!r}")
    party_id = str(subject)
    _append(log, signer, actor, {"kind": "PartyStatus", "party_id": party_id,
                                 "status": status, "reason": reason})
    return {"ok": True, "party_id": party_id, "status": status}


def _list_parties_local(
    log: RecordSink, kind: str = "", competence: str = "", *,
    trust_store: Any = None, nonce_store: Any = None,
    revocation_store: Any = None, genesis_prev_digest: Optional[str] = None,
) -> dict[str, Any]:
    records: dict[str, dict[str, Any]] = {}
    for extra in chain_receipt.verified_payloads(
        log, **_verify_kwargs(trust_store, nonce_store, revocation_store, genesis_prev_digest),
    ):
        k = extra.get("kind")
        pid = extra.get("party_id", "")
        if k == "PartyRegistered":
            rec = {f: extra.get(f) for f in (
                "party_id", "party_kind", "name", "role", "competences",
                "channels", "owner", "purpose", "grade", "agent_uid")}
            rec["status"] = records.get(pid, {}).get("status", "active")
            records[pid] = rec
        elif k == "PartyStatus" and pid in records:
            records[pid]["status"] = extra.get("status", "active")
    rows = list(records.values())
    if kind:
        rows = [r for r in rows if r.get("party_kind") == kind]
    if competence:
        rows = [r for r in rows if competence in (r.get("competences") or [])]
    return {"ok": True, "count": len(rows), "parties": rows}


def list_parties(log: RecordSink, kind: str = "", competence: str = "", **verify_kwargs: Any) -> dict[str, Any]:
    from .party_resolver import get_resolver
    return get_resolver().list_parties(log, kind=kind, competence=competence, **verify_kwargs)


BUILTIN_ACTORS = ("user", "system")


def route_approvers(log: RecordSink, competence: str, **verify_kwargs: Any) -> dict[str, Any]:
    from .party_resolver import get_resolver
    return get_resolver().route_approvers(log, competence, **verify_kwargs)


def _route_approvers_local(log: RecordSink, competence: str, **verify_kwargs: Any) -> dict[str, Any]:
    res = _list_parties_local(log, kind="human", competence=competence, **verify_kwargs)
    rows = [r for r in res["parties"] if r.get("status") == "active"]
    return {"ok": True, "competence": competence, "count": len(rows), "approvers": rows}
