from __future__ import annotations

import time
from collections import defaultdict
from typing import Any, Callable, Optional

from ..ports import RecordSink
from ..records import chain_receipt
from .connected_agents import list_connected

_VERDICT_RANK = {
    "prohibited": 5, "refused": 4, "reserved": 3, "human": 2, "auto": 1, "unfired": 0,
}


def _agent_boundary(actor: str, lane_capabilities_fn: Optional[Callable[[str], dict]]) -> dict[str, Any]:
    if lane_capabilities_fn is None:
        return {"verdict": "refused", "grade": None, "escalation": False}
    try:
        cap = lane_capabilities_fn(actor)
    except Exception:
        return {"verdict": "refused", "grade": None, "escalation": False}
    caps = (cap or {}).get("capabilities") or []
    if not (cap or {}).get("ok") or not caps:
        return {"verdict": "refused", "grade": None, "escalation": False}
    verdict = "unfired"
    escalation = False
    for entry in caps:
        cells = list(entry["by_risk"].values()) if "by_risk" in entry else [entry]
        for cell in cells:
            v = cell.get("verdict") or "unfired"
            if _VERDICT_RANK.get(v, 0) > _VERDICT_RANK.get(verdict, 0):
                verdict = v
            if cell.get("escalation"):
                escalation = True
    grade = (cap.get("provenance") or {}).get("max_grade")
    return {"verdict": verdict, "grade": grade, "escalation": escalation}


def _default_session_of(receipt: dict[str, Any]) -> Optional[str]:
    return receipt.get("run_id") or None


def session_governance(
    *, chain: RecordSink,
    lane_capabilities_fn: Optional[Callable[[str], dict]] = None,
    session_of: Callable[[dict], Optional[str]] = _default_session_of,
    chain_limit: int = 10, now: Optional[float] = None, root: Optional[str] = None,
    trust_store: Any = None, nonce_store: Any = None,
    revocation_store: Any = None, genesis_prev_digest: Optional[str] = None,
) -> dict[str, Any]:
    now = time.time() if now is None else float(now)
    buckets: dict[str, list[dict[str, Any]]] = defaultdict(list)
    try:
        receipts = chain_receipt.verified_receipts(
            chain, trust_store=trust_store, nonce_store=nonce_store,
            revocation_store=revocation_store, genesis_prev_digest=genesis_prev_digest,
        )
        for idx, receipt in enumerate(receipts):
            sid = session_of(receipt)
            if not sid:
                continue
            buckets[sid].append({
                "seq": idx, "tool": receipt.get("tool"),
                "dispatch_id": receipt.get("dispatch_id"),
                "issued_at": receipt.get("issued_at"),
            })
    except Exception:
        buckets = defaultdict(list)

    conns = list_connected(root=root)
    by_session: dict[str, dict[str, Any]] = {}
    session_conn_count: dict[str, int] = defaultdict(int)
    for c in conns:
        sid = str(c.get("session_id") or "").strip()
        if sid:
            session_conn_count[sid] += 1
            if sid not in by_session:
                by_session[sid] = c

    sessions: list[dict[str, Any]] = []
    for sid, events in buckets.items():
        boundary = _agent_boundary(sid, lane_capabilities_fn)
        recent = list(reversed(events))[:chain_limit]
        conn = by_session.get(sid)
        sessions.append({
            "session_id": sid,
            "identity_tier": "witnessed",
            "verdict": boundary.get("verdict"),
            "grade": boundary.get("grade"),
            "escalation": bool(boundary.get("escalation")),
            "event_count": len(events),
            "recent": recent,
            "connected": conn is not None,
            "presence_ambiguous": session_conn_count.get(sid, 0) > 1,
            "connid": conn.get("connid") if conn else None,
            "pid": conn.get("pid") if conn else None,
        })
    sessions.sort(key=lambda s: s.get("event_count", 0), reverse=True)

    idle = [
        {"connid": c.get("connid"), "agent": c.get("agent"),
         "transport": c.get("transport"), "pid": c.get("pid"),
         "session_id": (str(c.get("session_id") or "") or None),
         "connected_at": c.get("connected_at")}
        for c in conns if not buckets.get(str(c.get("session_id") or ""))
    ]

    return {"ok": True, "session_count": len(sessions), "sessions": sessions,
            "connected_only": idle}
