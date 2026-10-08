from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Optional

from loomground_drift.breaker import Breaker, BreakerStatus, Tripwire

from ..ports import RecordSink
from ..records import chain_receipt

_KINDS = ("rate", "loop", "budget")


@dataclass(frozen=True)
class WatchRule:
    name: str
    kind: str
    limit: float
    window_seconds: float = 60.0

    def __post_init__(self) -> None:
        if self.kind not in _KINDS:
            raise ValueError(f"unknown WatchRule kind: {self.kind!r}; expected one of {_KINDS}")


def _entries_for(chain: RecordSink, actor: str, **verify_kwargs: Any) -> list[dict[str, Any]]:
    out = []
    for e in chain_receipt.verified_entries(chain, **verify_kwargs):
        eid = str((e.get("receipt", {}) or {}).get("executor", {}).get("id", ""))
        parts = eid.split(":", 2)
        gate_session = parts[2] if len(parts) == 3 and parts[0] == "agent-gate" and parts[1] in ("gate", "host") else None
        if eid == actor or gate_session == actor:
            out.append(e)
    return out


def _issued_ts(receipt: dict[str, Any]) -> float:
    raw = receipt.get("issued_at")
    if not isinstance(raw, str):
        return 0.0
    try:
        text = raw[:-1] + "+00:00" if raw.endswith("Z") else raw
        return datetime.fromisoformat(text).timestamp()
    except ValueError:
        return 0.0


def _rate_metric(chain: RecordSink, actor: str, window_seconds: float, *,
                 now: Optional[float] = None, **verify_kwargs: Any) -> float:
    now = now if now is not None else time.time()
    cutoff = now - window_seconds
    return float(sum(1 for e in _entries_for(chain, actor, **verify_kwargs)
                     if _issued_ts(e.get("receipt", {})) >= cutoff))


def _loop_metric(chain: RecordSink, actor: str, **verify_kwargs: Any) -> float:
    entries = _entries_for(chain, actor, **verify_kwargs)
    if not entries:
        return 0.0
    digests = [e.get("receipt", {}).get("action_digest") for e in entries]
    last = digests[-1]
    run = 0
    for d in reversed(digests):
        if d != last:
            break
        run += 1
    return float(run)


def _budget_metric(chain: RecordSink, actor: str, **verify_kwargs: Any) -> float:
    return float(sum(
        float((e.get("payload", {}) or {}).get("cost_usd", 0) or 0)
        for e in _entries_for(chain, actor, **verify_kwargs)
    ))


def watch_metrics(chain: RecordSink, actor: str, rules: list[WatchRule], *,
                  now: Optional[float] = None, **verify_kwargs: Any) -> dict[str, float]:
    if not chain_receipt.verify(chain, **verify_kwargs).ok:
        return {rule.name: float("inf") for rule in rules}
    metrics: dict[str, float] = {}
    for rule in rules:
        if rule.kind == "rate":
            metrics[rule.name] = _rate_metric(chain, actor, rule.window_seconds, now=now, **verify_kwargs)
        elif rule.kind == "loop":
            metrics[rule.name] = _loop_metric(chain, actor, **verify_kwargs)
        else:
            metrics[rule.name] = _budget_metric(chain, actor, **verify_kwargs)
    return metrics


def _tripwires_for(rules: list[WatchRule]) -> list[Tripwire]:
    return [Tripwire(rule.name, rule.name, rule.limit, "max") for rule in rules]


def watch(chain: RecordSink, actor: str, breaker: Breaker, rules: list[WatchRule], *,
         now: Optional[float] = None, **verify_kwargs: Any) -> BreakerStatus:
    metrics = watch_metrics(chain, actor, rules, now=now, **verify_kwargs)
    existing = {t.metric for t in breaker.tripwires}
    for tw in _tripwires_for(rules):
        if tw.metric not in existing:
            breaker.tripwires.append(tw)
            existing.add(tw.metric)
    return breaker.status(metrics=metrics, now=now)


__all__ = ["WatchRule", "watch_metrics", "watch"]
