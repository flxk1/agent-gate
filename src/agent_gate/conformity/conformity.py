from __future__ import annotations

import time
from typing import Any, Optional

from ..ports import RecordSink
from ..records import chain_receipt
from ..records.oversight_log import STAKE_FOOTPRINTS

__all__ = ["evidence_pack", "oversight_attestation", "trigger_map",
           "drift_report", "risk_register", "threat_model", "OPS"]

OPS = ("evidence_pack", "oversight_attestation", "trigger_map",
       "drift_report", "risk_register", "threat_model")

_NEUTRAL_BASIS = {
    "evidence_pack": "operations projected from the signed chain; "
                     "no regime loaded -- legal-basis labels omitted.",
    "oversight_attestation": "human determinations + rationale projected "
                     "from the chain; no regime loaded.",
    "trigger_map": "action/kind inventory from the chain; no regime loaded "
                   "-- instruments omitted.",
    "drift_report": "operation counts by kind, current window vs baseline; "
                    "no regime loaded.",
    "risk_register": "stake-bearing footprint classes from the chain; no "
                     "regime loaded.",
    "threat_model": "ingest-quarantine threat coverage by category; no "
                    "regime loaded -- framework mapping omitted.",
}

NOT_SPECIFIED = "not-specified-in-runtime"


def _basis(op: str, regime: Optional[dict]) -> str:
    if regime:
        return regime.get("op_basis", {}).get(op) or _NEUTRAL_BASIS.get(op, "")
    return _NEUTRAL_BASIS.get(op, "")


def _regime_id(regime: Optional[dict]) -> str:
    return regime.get("id", "custom") if regime else "none"


def _iso(ts: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def _actor_kind(actor: str) -> str:
    if actor in ("user", ""):
        return "user" if actor else "system"
    if str(actor).startswith("agent"):
        return "agent"
    return "system"


def _entries(chain: RecordSink, *, since: Optional[str] = None,
            until: Optional[str] = None, verify_kwargs: Optional[dict] = None) -> list[dict[str, Any]]:
    out = []
    for e in chain_receipt.verified_entries(chain, **(verify_kwargs or {})):
        issued_at = (e.get("receipt") or {}).get("issued_at", "")
        if since is not None and issued_at < since:
            continue
        if until is not None and issued_at > until:
            continue
        out.append(e)
    return out


def _envelope(op: str, regime: Optional[dict], *, records: list[dict[str, Any]],
             chain: RecordSink, extra: Optional[dict[str, Any]] = None,
             verify_kwargs: Optional[dict] = None) -> dict[str, Any]:
    chain_result = chain_receipt.verify(chain, **(verify_kwargs or {}))
    return {
        "op": op,
        "basis": _basis(op, regime),
        "regime_id": _regime_id(regime),
        "generated_at": _iso(time.time()),
        "chain_intact": bool(chain_result.ok),
        "chain_errors": list(chain_result.errors),
        "record_count": len(records),
        "records": records,
        **(extra or {}),
    }


def evidence_pack(chain: RecordSink, *, since: Optional[str] = None,
                  until: Optional[str] = None, regime: Optional[dict] = None,
                  **verify_kwargs: Any) -> dict[str, Any]:
    records = []
    for e in _entries(chain, since=since, until=until, verify_kwargs=verify_kwargs):
        receipt, payload = e.get("receipt", {}), e.get("payload", {})
        actor = (receipt.get("executor") or {}).get("id", "")
        records.append({
            "dispatch_id": receipt.get("dispatch_id", ""),
            "tool": receipt.get("tool", ""),
            "kind": payload.get("kind", NOT_SPECIFIED),
            "actor": actor,
            "actor_kind": _actor_kind(actor),
            "issued_at": receipt.get("issued_at", ""),
            "signed": bool(receipt.get("signature")),
        })
    return _envelope("evidence_pack", regime, records=records, chain=chain, verify_kwargs=verify_kwargs)


_HUMAN_KINDS = {"NodeOverride", "escalation-return"}


def oversight_attestation(chain: RecordSink, *, regime: Optional[dict] = None,
                          **verify_kwargs: Any) -> dict[str, Any]:
    records = []
    for e in chain_receipt.verified_entries(chain, **verify_kwargs):
        receipt, payload = e.get("receipt", {}), e.get("payload", {})
        kind = payload.get("kind", "")
        bypassed = bool(payload.get("oversight_bypassed"))
        if kind not in _HUMAN_KINDS and not bypassed:
            continue
        records.append({
            "dispatch_id": receipt.get("dispatch_id", ""),
            "kind": kind,
            "actor": (receipt.get("executor") or {}).get("id", ""),
            "rationale": payload.get("rationale", ""),
            "oversight_bypassed": bypassed,
        })
    return _envelope("oversight_attestation", regime, records=records, chain=chain, verify_kwargs=verify_kwargs)


def trigger_map(chain: RecordSink, *, regime: Optional[dict] = None,
                **verify_kwargs: Any) -> dict[str, Any]:
    counts: dict[str, int] = {}
    records = []
    for e in chain_receipt.verified_entries(chain, **verify_kwargs):
        receipt, payload = e.get("receipt", {}), e.get("payload", {})
        tool = receipt.get("tool", "")
        kind = payload.get("kind", NOT_SPECIFIED)
        key = f"{tool}::{kind}"
        counts[key] = counts.get(key, 0) + 1
    for key, n in sorted(counts.items()):
        tool, _, kind = key.partition("::")
        instrument = (regime or {}).get("triggers", {}).get(tool, NOT_SPECIFIED)
        records.append({"tool": tool, "kind": kind, "count": n, "instrument": instrument})
    return _envelope("trigger_map", regime, records=records, chain=chain, verify_kwargs=verify_kwargs)


def drift_report(chain: RecordSink, *, baseline_until: Optional[str] = None,
                 regime: Optional[dict] = None, **verify_kwargs: Any) -> dict[str, Any]:
    baseline: dict[str, int] = {}
    current: dict[str, int] = {}
    for e in chain_receipt.verified_entries(chain, **verify_kwargs):
        receipt, payload = e.get("receipt", {}), e.get("payload", {})
        kind = payload.get("kind", NOT_SPECIFIED)
        issued_at = receipt.get("issued_at", "")
        bucket = baseline if (baseline_until and issued_at <= baseline_until) else current
        bucket[kind] = bucket.get(kind, 0) + 1
    records = []
    for kind in sorted(set(baseline) | set(current)):
        records.append({"kind": kind, "baseline_count": baseline.get(kind, 0),
                        "current_count": current.get(kind, 0),
                        "delta": current.get(kind, 0) - baseline.get(kind, 0)})
    return _envelope("drift_report", regime, records=records, chain=chain,
                     extra={"baseline_until": baseline_until or NOT_SPECIFIED},
                     verify_kwargs=verify_kwargs)


def risk_register(chain: RecordSink, *, regime: Optional[dict] = None,
                  **verify_kwargs: Any) -> dict[str, Any]:
    counts: dict[str, int] = {}
    for payload in chain_receipt.verified_payloads(chain, **verify_kwargs):
        for f in payload.get("footprint", []) or []:
            if f in STAKE_FOOTPRINTS:
                counts[f] = counts.get(f, 0) + 1
    records = [{"footprint": f, "count": n} for f, n in sorted(counts.items())]
    return _envelope("risk_register", regime, records=records, chain=chain, verify_kwargs=verify_kwargs)


def threat_model(chain: RecordSink, *, regime: Optional[dict] = None,
                 **verify_kwargs: Any) -> dict[str, Any]:
    counts: dict[str, int] = {}
    for payload in chain_receipt.verified_payloads(chain, **verify_kwargs):
        if payload.get("kind") != "ingest-quarantine":
            continue
        for t in payload.get("threats", []) or []:
            key = f"{t.get('kind', '')}:{t.get('label', '')}"
            counts[key] = counts.get(key, 0) + 1
    records = []
    for key, n in sorted(counts.items()):
        kind, _, label = key.partition(":")
        records.append({"kind": kind, "label": label, "count": n})
    return _envelope("threat_model", regime, records=records, chain=chain, verify_kwargs=verify_kwargs)
