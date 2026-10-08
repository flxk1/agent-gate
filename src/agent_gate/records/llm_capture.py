from __future__ import annotations

import hashlib
import math
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional

from a2a_compliance.wire.admission import Issuer

from ..ports import RecordSink
from . import chain_receipt


class IngestMode(Enum):
    INTERACTIVE = "interactive"
    AGENTIC = "agentic"


class OversightLevel(Enum):
    AUTONOMOUS = 1
    NOTIFY = 2
    REVIEW = 3
    APPROVE = 4
    SUPERVISED = 5
    MANUAL = 6


_OVERSIGHT_BY_NAME = {ol.name.lower(): ol for ol in OversightLevel}


def coerce_oversight(value) -> OversightLevel:
    if isinstance(value, OversightLevel):
        return value
    if isinstance(value, int):
        return OversightLevel(value)
    if isinstance(value, str):
        v = value.strip().lower()
        if v in _OVERSIGHT_BY_NAME:
            return _OVERSIGHT_BY_NAME[v]
    raise ValueError(f"invalid oversight value: {value!r}")


class VerbosityLevel(Enum):
    METADATA = "metadata"
    PREVIEW = "preview"
    PREVIEW_PLUS_CITATIONS = "preview+citations"
    FULL = "full"
    FULL_PLUS_TRACE = "full+trace"
    NONE = "none"


_AGENTIC_MATRIX = {
    OversightLevel.AUTONOMOUS: VerbosityLevel.METADATA,
    OversightLevel.NOTIFY: VerbosityLevel.PREVIEW,
    OversightLevel.REVIEW: VerbosityLevel.PREVIEW_PLUS_CITATIONS,
    OversightLevel.APPROVE: VerbosityLevel.FULL,
    OversightLevel.SUPERVISED: VerbosityLevel.FULL_PLUS_TRACE,
    OversightLevel.MANUAL: VerbosityLevel.FULL_PLUS_TRACE,
}

_INTERACTIVE_MATRIX: dict[OversightLevel, tuple[VerbosityLevel, bool]] = {
    OversightLevel.AUTONOMOUS: (VerbosityLevel.NONE, False),
    OversightLevel.NOTIFY: (VerbosityLevel.NONE, False),
    OversightLevel.REVIEW: (VerbosityLevel.FULL, True),
    OversightLevel.APPROVE: (VerbosityLevel.FULL, True),
    OversightLevel.SUPERVISED: (VerbosityLevel.FULL, True),
    OversightLevel.MANUAL: (VerbosityLevel.FULL, True),
}


def decide_verbosity(mode: IngestMode, oversight: OversightLevel, *,
                     oversight_active: bool = True) -> tuple[VerbosityLevel, bool]:
    if not oversight_active:
        if mode == IngestMode.AGENTIC:
            return VerbosityLevel.FULL_PLUS_TRACE, False
        return VerbosityLevel.NONE, False
    if mode == IngestMode.AGENTIC:
        return _AGENTIC_MATRIX[oversight], False
    return _INTERACTIVE_MATRIX[oversight]


@dataclass
class LLMExchange:
    model: str
    prompt_context: str
    response: str
    cited_sources: list[str] = field(default_factory=list)
    cost_estimate_cents: Optional[float] = None
    tool_call_trace: list[dict[str, Any]] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)
    request_id: str = ""


@dataclass
class CaptureResult:
    captured: bool
    dispatch_id: Optional[str]
    verbosity: VerbosityLevel
    prompted_user: bool
    mode: IngestMode
    skipped_reason: str = ""
    oversight_bypassed: bool = False


_SECRET_PATTERNS = (
    re.compile(r"\b[A-Za-z0-9_-]*api[_-]?key[A-Za-z0-9_-]*\s*[:=]\s*\S+", re.I),
    re.compile(r"\bsk-[A-Za-z0-9]{16,}\b"),
    re.compile(r"[?&](?:api_key|token|secret)=[^&\s]+", re.I),
)


def redact_for_capture(text: str) -> str:
    if not text:
        return text
    out = text
    for rx in _SECRET_PATTERNS:
        out = rx.sub("[REDACTED]", out)
    return out


def _short(text: str, n: int = 200) -> str:
    return " ".join(text.split())[:n]


def _hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def _redact_obj(obj: Any, redact: Callable[[str], str]) -> Any:
    if isinstance(obj, str):
        return redact(obj)
    if isinstance(obj, list):
        return [_redact_obj(x, redact) for x in obj]
    if isinstance(obj, tuple):
        return tuple(_redact_obj(x, redact) for x in obj)
    if isinstance(obj, dict):
        return {(redact(k) if isinstance(k, str) else k): _redact_obj(v, redact)
                for k, v in obj.items()}
    return obj


def _project_pair(exchange: LLMExchange, verbosity: VerbosityLevel) -> dict[str, Any]:
    p_ctx = redact_for_capture(exchange.prompt_context)
    resp = redact_for_capture(exchange.response)
    prompt_hash = _hash(exchange.prompt_context)
    response_hash = _hash(exchange.response)

    facets: dict[str, Any] = {
        "model": exchange.model,
        "prompt_context_hash": prompt_hash,
        "prompt_context_length": len(p_ctx),
        "response_hash": response_hash,
        "response_length": len(resp),
        "verbosity_level": verbosity.value,
    }
    if exchange.cost_estimate_cents is not None:
        facets["cost_estimate_cents"] = exchange.cost_estimate_cents
    if exchange.request_id:
        facets["request_id"] = exchange.request_id

    if verbosity == VerbosityLevel.METADATA:
        body = ""
    elif verbosity in (VerbosityLevel.PREVIEW, VerbosityLevel.PREVIEW_PLUS_CITATIONS):
        body = _short(resp, 200)
    elif verbosity in (VerbosityLevel.FULL, VerbosityLevel.FULL_PLUS_TRACE):
        body = resp
    else:
        body = ""

    cited: list[str] = []
    if verbosity in (VerbosityLevel.PREVIEW_PLUS_CITATIONS, VerbosityLevel.FULL, VerbosityLevel.FULL_PLUS_TRACE):
        cited = [redact_for_capture(s) for s in exchange.cited_sources]

    if verbosity in (VerbosityLevel.FULL, VerbosityLevel.FULL_PLUS_TRACE):
        facets["prompt_context"] = p_ctx

    payload: dict[str, Any] = {
        "kind": "llm_exchange", "scope": "llm", "body": body,
        "cited_sources": cited, "facets": facets,
    }
    if verbosity == VerbosityLevel.FULL_PLUS_TRACE:
        payload["tool_call_trace"] = _redact_obj(list(exchange.tool_call_trace), redact_for_capture)
    return payload


def capture_llm_exchange(
    exchange: LLMExchange, *, mode: IngestMode, oversight,
    chain: RecordSink, signer: Issuer,
    oversight_active: bool = True,
    user_decision_callback: Optional[Callable[[LLMExchange, OversightLevel, VerbosityLevel], bool]] = None,
    actor: str = "agent",
) -> CaptureResult:
    oversight_level = coerce_oversight(oversight)
    verbosity, will_prompt = decide_verbosity(mode, oversight_level, oversight_active=oversight_active)

    prompted = False
    if mode == IngestMode.INTERACTIVE and will_prompt:
        prompted = True
        user_says_yes = bool(user_decision_callback(exchange, oversight_level, verbosity)) \
            if user_decision_callback is not None else True
        if not user_says_yes:
            return CaptureResult(False, None, VerbosityLevel.NONE, True, mode,
                                 skipped_reason="user_declined",
                                 oversight_bypassed=not oversight_active)

    if verbosity == VerbosityLevel.NONE:
        return CaptureResult(False, None, VerbosityLevel.NONE, prompted, mode,
                             skipped_reason=("low_oversight_interactive"
                                            if mode == IngestMode.INTERACTIVE
                                            else "verbosity_none"),
                             oversight_bypassed=not oversight_active)

    payload = _project_pair(exchange, verbosity)
    envelope = chain_receipt.build_record(
        signer=signer, chain=chain, tool="agent_gate.records.llm_capture",
        payload=payload, executor_id=actor,
        executor_role="agent" if mode == IngestMode.AGENTIC else "user",
        dispatch_id=f"llm:{_hash(exchange.prompt_context)}:{exchange.request_id or _hash(exchange.response)}",
    )
    return CaptureResult(True, envelope["receipt"]["dispatch_id"], verbosity, prompted, mode,
                         oversight_bypassed=not oversight_active)


def _is_spend_payload(payload: dict[str, Any]) -> bool:
    scope = payload.get("scope") or ""
    kind = payload.get("kind") or ""
    return scope in ("llm", "web", "websearch") or str(kind).endswith(("exchange", "search"))


def _payload_cost(payload: dict[str, Any]) -> float:
    cost = (payload.get("facets") or {}).get("cost_estimate_cents")
    if isinstance(cost, bool) or not isinstance(cost, (int, float)):
        return 0.0
    c = float(cost)
    return c if math.isfinite(c) and c >= 0 else 0.0


def recorded_spend_cents(chain: RecordSink, **verify_kwargs: Any) -> float:
    if not chain_receipt.verify(chain, **verify_kwargs).ok:
        return float("inf")
    spend = 0.0
    for payload in chain_receipt.verified_payloads(chain, **verify_kwargs):
        if _is_spend_payload(payload):
            spend += _payload_cost(payload)
    return round(spend, 4)
