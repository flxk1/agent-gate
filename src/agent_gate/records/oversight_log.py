from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Optional

from a2a_compliance.wire.admission import Issuer

from ..gate.verdict import Verdict
from ..ports import RecordSink
from . import chain_receipt

STAKE_FOOTPRINTS = frozenset({
    "personal-data", "financial", "irreversible",
    "external-publish", "security-control",
})


def record_admission(
    verdict: Verdict,
    *,
    chain: RecordSink,
    signer: Issuer,
    content_hash: str,
    cls: str = "",
    reason: str = "",
    aggregate_only: bool = False,
    triggers: Optional[list[str]] = None,
    grounds: Optional[list[str]] = None,
    footprint: Optional[list[str]] = None,
    actor: str = "system",
) -> dict[str, Any]:
    payload = {
        "kind": "learning-admission",
        "class": cls,
        "admission": verdict.value,
        "reason": reason,
        "aggregate_only": aggregate_only,
        "triggers": list(triggers or []),
        "grounds": list(grounds or []),
        "footprint": list(footprint or []),
    }
    return chain_receipt.build_record(
        signer=signer, chain=chain, tool="agent_gate.oversight.admission",
        payload=payload, executor_id=actor, executor_role="system",
        dispatch_id=f"learn:{content_hash}",
    )


@dataclass
class TaintFinding:

    dispatch_id: str
    actor: str
    issued_at: str
    cited: str
    kind: str
    stake_bearing: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "dispatch_id": self.dispatch_id, "actor": self.actor,
            "issued_at": self.issued_at, "cited": self.cited,
            "kind": self.kind, "stake_bearing": self.stake_bearing,
        }


def _cited_grounds(payload: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for key in ("obligation_pairs", "grounds", "cited"):
        v = payload.get(key)
        if isinstance(v, list):
            for item in v:
                if isinstance(item, str):
                    out.append(item)
                elif isinstance(item, dict) and "id" in item:
                    out.append(item["id"])
        elif isinstance(v, str):
            out.append(v)
    return out


def taint_walk(chain_entries: Iterable[dict[str, Any]], failed_ground: str) -> list[TaintFinding]:
    findings: list[TaintFinding] = []
    for entry in chain_entries:
        payload = entry.get("payload", {}) or {}
        cited = _cited_grounds(payload)
        if failed_ground not in cited:
            continue
        receipt = entry.get("receipt", {}) or {}
        footprint = payload.get("footprint", []) or []
        stake = any(f in STAKE_FOOTPRINTS for f in footprint)
        findings.append(TaintFinding(
            dispatch_id=str(receipt.get("dispatch_id", "")),
            actor=str((receipt.get("executor") or {}).get("id", "")),
            issued_at=str(receipt.get("issued_at", "")),
            cited=failed_ground, kind=str(payload.get("kind", "")),
            stake_bearing=stake,
        ))
    return findings


def taint_walk_chain(chain: RecordSink, failed_ground: str, **verify_kwargs: Any) -> list[TaintFinding]:
    return taint_walk(chain_receipt.verified_entries(chain, **verify_kwargs), failed_ground)


def mark_tainted(
    findings: Iterable[TaintFinding],
    *,
    chain: RecordSink,
    signer: Issuer,
    failed_ground: str,
    reason: str = "",
    actor: str = "system",
) -> dict[str, Any]:
    findings = list(findings)
    stake = [f for f in findings if f.stake_bearing]
    payload = {
        "kind": "ground-taint",
        "failed_ground": failed_ground,
        "reason": reason,
        "tainted_count": len(findings),
        "stake_bearing_count": len(stake),
        "tainted_dispatch_ids": [f.dispatch_id for f in findings],
        "incidents": [f.to_dict() for f in stake],
    }
    return chain_receipt.build_record(
        signer=signer, chain=chain, tool="agent_gate.oversight.taint",
        payload=payload, executor_id=actor, executor_role="system",
        dispatch_id=f"taint:{failed_ground}",
    )
