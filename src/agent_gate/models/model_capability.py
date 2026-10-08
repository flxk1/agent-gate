from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any, Iterable, Optional

CAPS = ("classification", "json", "instruction_following", "long_context", "reasoning", "general")
DEGRADES = ("deterministic", "capture_first", "escalate_human", "escalate_cloud", "keyword_only")


@dataclass(frozen=True)
class TaskReq:
    task: str
    requires: frozenset
    on_miss: str


TASKS: dict[str, TaskReq] = {
    "privacy_semantic": TaskReq("privacy_semantic", frozenset({"classification"}), "deterministic"),
    "extraction": TaskReq("extraction", frozenset({"json", "instruction_following"}), "deterministic"),
    "interpretation": TaskReq("interpretation", frozenset({"long_context", "reasoning"}), "escalate_human"),
    "ask_routing": TaskReq("ask_routing", frozenset({"classification"}), "keyword_only"),
    "intake": TaskReq("intake", frozenset({"classification"}), "capture_first"),
    "completion": TaskReq("completion", frozenset({"general"}), "escalate_cloud"),
}


@dataclass
class ModelProfile:
    model_id: str
    capabilities: frozenset
    tier: str = "small"
    probed: bool = False

    def as_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["capabilities"] = sorted(self.capabilities)
        return d


_TIER_CAPS = {
    "large": frozenset(CAPS),
    "medium": frozenset({"classification", "json", "instruction_following", "general"}),
    "small": frozenset({"classification", "general"}),
}
_TIER_ORDER = {"large": 0, "medium": 1, "small": 2}


def tier_for_params(billions: float) -> str:
    return "large" if billions >= 30 else "medium" if billions >= 7 else "small"


def infer_profile(model_id: str, *, params_billions: Optional[float] = None,
                  tier: Optional[str] = None) -> ModelProfile:
    t = tier or (tier_for_params(params_billions) if params_billions is not None else "small")
    if t not in _TIER_CAPS:
        t = "small"
    return ModelProfile(model_id, _TIER_CAPS[t], tier=t, probed=False)


@dataclass
class Match:
    task: str
    model_id: Optional[str]
    capable: bool
    action: str
    missing: list[str] = field(default_factory=list)
    reason: str = ""

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _req(task: str) -> TaskReq:
    req = TASKS.get(task)
    if req is None:
        raise ValueError(f"unknown task {task!r}; one of {sorted(TASKS)}")
    return req


def match(task: str, profile: Optional[ModelProfile]) -> Match:
    req = _req(task)
    if profile is None:
        return Match(task, None, False, req.on_miss, sorted(req.requires),
                     f"no model registered for {task} - degrade to {req.on_miss}")
    missing = sorted(req.requires - profile.capabilities)
    if missing:
        return Match(task, profile.model_id, False, req.on_miss, missing,
                     f"{profile.model_id} lacks {missing} - degrade to {req.on_miss}")
    note = "meets the requirement" + ("" if profile.probed else " (inferred from size, not probed)")
    return Match(task, profile.model_id, True, "run_local", [], f"{profile.model_id} {note}")


def select(task: str, profiles: Iterable[ModelProfile]) -> Match:
    req = _req(task)
    profiles = list(profiles)
    capable = [p for p in profiles if not (req.requires - p.capabilities)]
    if not capable:
        best = min(profiles, key=lambda p: _TIER_ORDER.get(p.tier, 9), default=None)
        return match(task, best)
    return match(task, min(capable, key=lambda p: (0 if p.probed else 1, _TIER_ORDER.get(p.tier, 9))))


def profile_from_registry_id(model_id: str) -> ModelProfile:
    m = re.search(r"(\d+(?:\.\d+)?)\s*b\b", model_id.lower())
    return infer_profile(model_id, params_billions=float(m.group(1)) if m else None)


def for_task(task: str) -> Match:
    try:
        from . import models_registry
        profiles = [profile_from_registry_id(e.id) for e in models_registry.list_models()]
    except Exception:  # noqa: BLE001
        profiles = []
    return select(task, profiles)


def readiness() -> dict[str, Any]:
    tasks = {t: for_task(t).as_dict() for t in TASKS}
    return {"version": "model_capability/v1",
            "ready": sorted(t for t, m in tasks.items() if m["capable"]),
            "degraded": sorted(t for t, m in tasks.items() if not m["capable"]),
            "tasks": tasks}
