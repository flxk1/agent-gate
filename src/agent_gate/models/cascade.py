from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Optional
from urllib.parse import urlparse

from ..ports import CAPABILITY_HEADER
from . import local_llm

__all__ = ["Tier", "Verifier", "TierAttempt", "CascadeResult", "run_cascade",
           "always_accept", "nonempty_verifier", "UPSTREAM_HEADER", "TRACK_HEADER",
           "CAPABILITY_HEADER"]

UPSTREAM_HEADER = "X-Lock-Upstream"
TRACK_HEADER = "X-Lock-Track"


@dataclass
class Tier:
    name: str
    url: str
    model: str
    api_key: str = ""
    is_cloud: bool = False
    price_per_1k: float = 0.0
    timeout: float = 30.0
    proxy_url: str = ""
    capability_token: str = ""
    track_id: str = ""

    @property
    def configured(self) -> bool:
        if self.is_cloud:
            return bool(self.url and self.model and self.proxy_url
                        and self.capability_token and self.track_id)
        return bool(self.url and self.model)


Verifier = Callable[[str, str], "tuple[bool, str, Optional[float]]"]
Shield = Callable[[str], "tuple[str, str]"]


def always_accept(prompt: str, response: str):
    return True, "no verification requested", None


def nonempty_verifier(prompt: str, response: str):
    r = (response or "").strip()
    if not r:
        return False, "empty response", 0.0
    if r.lower().startswith(("i cannot", "i can't", "i'm sorry", "as an ai")):
        return False, "refusal / non-answer", 0.0
    return True, "non-empty answer", 1.0


@dataclass
class TierAttempt:
    tier: str
    is_cloud: bool
    ran: bool
    accepted: bool
    reason: str
    tokens: int = 0
    cost: float = 0.0
    price_per_1k: float = 0.0
    latency_ms: int = 0
    score: Optional[float] = None
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {k: getattr(self, k) for k in (
            "tier", "is_cloud", "ran", "accepted", "reason", "tokens",
            "cost", "price_per_1k", "latency_ms", "score", "note")}


@dataclass
class CascadeResult:
    ok: bool
    response: str
    served_by: str
    served_is_cloud: bool
    attempts: list[TierAttempt] = field(default_factory=list)
    escalation_withheld: bool = False
    error: str = ""

    def ledger(self, *, cloud_price_per_1k: Optional[float] = None) -> dict[str, Any]:
        local_tokens = sum(a.tokens for a in self.attempts if a.ran and not a.is_cloud)
        cloud_tokens = sum(a.tokens for a in self.attempts if a.ran and a.is_cloud)
        actual_cost = sum(a.cost for a in self.attempts if a.ran)
        served = next((a for a in self.attempts if a.accepted), None)
        cf_rate = cloud_price_per_1k
        if cf_rate is None:
            cloud_rates = [a.price_per_1k for a in self.attempts if a.is_cloud]
            cf_rate = max(cloud_rates) if cloud_rates else 0.0
        served_tokens = served.tokens if served else 0
        cloud_only_cost = (served_tokens / 1000.0) * cf_rate if cf_rate else 0.0
        ran = [a for a in self.attempts if a.ran]
        accepted_local = bool(served and not served.is_cloud)
        return {
            "served_by": self.served_by,
            "served_is_cloud": self.served_is_cloud,
            "accepted_locally": accepted_local,
            "local_tokens": local_tokens,
            "cloud_tokens": cloud_tokens,
            "actual_cost": round(actual_cost, 6),
            "cloud_only_cost_estimate": round(cloud_only_cost, 6),
            "estimated_saving": round(max(0.0, cloud_only_cost - actual_cost), 6),
            "agent_tokens_offloaded_to_local": local_tokens if accepted_local else 0,
            "tiers_run": len(ran),
            "local_deferrals": sum(1 for a in ran if not a.is_cloud and not a.accepted),
            "escalated_to_cloud": any(a.ran and a.is_cloud for a in self.attempts),
            "escalation_withheld": self.escalation_withheld,
        }

    def to_dict(self) -> dict[str, Any]:
        return {"ok": self.ok, "response": self.response,
                "served_by": self.served_by, "served_is_cloud": self.served_is_cloud,
                "escalation_withheld": self.escalation_withheld, "error": self.error,
                "attempts": [a.to_dict() for a in self.attempts],
                "ledger": self.ledger()}


def default_shield(prompt: str) -> "tuple[str, str]":
    try:
        from loomground_lock.lock_classify import _lock_string
        d = _lock_string(prompt, context="cascade-egress")
        action = d.get("action", "refuse")
        if action == "allow":
            return "allow", prompt
        if action == "minimise":
            return "minimise", d.get("text") or ""
        return "refuse", ""
    except Exception:  # noqa: BLE001
        return "unavailable", ""


def run_cascade(
    prompt: str,
    tiers: list[Tier],
    *,
    verifier: Verifier = nonempty_verifier,
    shield: Shield = default_shield,
    allow_unscreened_cloud: bool = False,
    max_tokens: int = 512,
    temperature: float = 0.0,
    completer: Callable[..., dict[str, Any]] = local_llm.complete_via,
) -> CascadeResult:
    res = CascadeResult(ok=False, response="", served_by="", served_is_cloud=False)
    best_local = None

    for idx, tier in enumerate(tiers):
        if not tier.configured:
            res.attempts.append(TierAttempt(
                tier=tier.name, is_cloud=tier.is_cloud, ran=False, accepted=False,
                reason="not configured", price_per_1k=tier.price_per_1k, note="skipped"))
            continue

        send_prompt = prompt
        if tier.is_cloud:
            action, screened = shield(prompt)
            if action == "refuse":
                res.attempts.append(TierAttempt(
                    tier=tier.name, is_cloud=True, ran=False, accepted=False,
                    reason="shield refused egress - confidential content",
                    price_per_1k=tier.price_per_1k, note="cloud hop blocked by Shield"))
                continue
            if action == "unavailable" and not allow_unscreened_cloud:
                res.attempts.append(TierAttempt(
                    tier=tier.name, is_cloud=True, ran=False, accepted=False,
                    reason="shield unavailable - cloud hop refused (fail-closed)",
                    price_per_1k=tier.price_per_1k,
                    note="set allow_unscreened_cloud to override (not advised)"))
                continue
            if action not in ("allow", "minimise", "unavailable"):
                res.attempts.append(TierAttempt(
                    tier=tier.name, is_cloud=True, ran=False, accepted=False,
                    reason=f"shield returned unknown action {action!r} - refused",
                    price_per_1k=tier.price_per_1k, note="cloud hop blocked by Shield"))
                continue
            if action == "minimise":
                send_prompt = screened
            out = completer(
                tier.proxy_url, tier.model, send_prompt, api_key="",
                extra_headers={
                    UPSTREAM_HEADER: urlparse(tier.url).hostname or "",
                    TRACK_HEADER: tier.track_id,
                    CAPABILITY_HEADER: tier.capability_token,
                },
                temperature=temperature, max_tokens=max_tokens, timeout=tier.timeout,
            )
        else:
            out = completer(
                tier.url, tier.model, send_prompt, api_key=tier.api_key,
                temperature=temperature, max_tokens=max_tokens, timeout=tier.timeout,
            )
        if not out.get("ok"):
            res.attempts.append(TierAttempt(
                tier=tier.name, is_cloud=tier.is_cloud, ran=True, accepted=False,
                reason=f"call failed: {out.get('error', 'unknown')}",
                price_per_1k=tier.price_per_1k,
                latency_ms=int(out.get("latency_ms", 0)), note="error"))
            continue

        text = out.get("response", "")
        usage = out.get("usage", {}) or {}
        tokens = int(usage.get("total_tokens")
                     or (usage.get("prompt_tokens", 0) + usage.get("completion_tokens", 0)))
        accepted, reason, score = verifier(prompt, text)
        res.attempts.append(TierAttempt(
            tier=tier.name, is_cloud=tier.is_cloud, ran=True, accepted=accepted,
            reason=reason, tokens=tokens, cost=(tokens / 1000.0) * tier.price_per_1k,
            price_per_1k=tier.price_per_1k,
            latency_ms=int(out.get("latency_ms", 0)), score=score))

        if accepted:
            res.ok = True
            res.response = text
            res.served_by = tier.name
            res.served_is_cloud = tier.is_cloud
            for later in tiers[idx + 1:]:
                res.attempts.append(TierAttempt(
                    tier=later.name, is_cloud=later.is_cloud, ran=False,
                    accepted=False, reason="not reached - earlier tier accepted",
                    price_per_1k=later.price_per_1k, note="unreached"))
            return res
        if not tier.is_cloud and best_local is None:
            best_local = (tier.name, text)

    cloud_ran = any(a.ran and a.is_cloud for a in res.attempts)
    if not cloud_ran and best_local is not None:
        res.escalation_withheld = True
        res.response = best_local[1]
        res.served_by = best_local[0]
        res.error = ("all local tiers deferred and no cloud tier was available "
                     "(not configured, air-gapped, or Shield blocked); returning best "
                     "local attempt unverified - escalate manually")
        return res
    res.error = "all tiers ran and none passed the verifier"
    return res
