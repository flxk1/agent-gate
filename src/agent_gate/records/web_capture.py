from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from a2a_compliance.wire.admission import Issuer

from ..ports import RecordSink
from . import chain_receipt
from .llm_capture import (
    CaptureResult,
    IngestMode,
    VerbosityLevel,
    coerce_oversight,
    decide_verbosity,
    redact_for_capture,
)


@dataclass
class WebSearchResult:
    url: str
    title: str = ""
    snippet: str = ""
    full_text: str = ""
    rank: int = 0


@dataclass
class WebSearchExchange:
    query: str
    engine: str
    results: list[WebSearchResult] = field(default_factory=list)
    cost_estimate_cents: Optional[float] = None
    timestamp: float = field(default_factory=time.time)
    request_id: str = ""
    trace: list[dict[str, Any]] = field(default_factory=list)


def _hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def _short(text: str, n: int = 200) -> str:
    return " ".join(text.split())[:n]


def _project_pair(exchange: WebSearchExchange, verbosity: VerbosityLevel) -> dict[str, Any]:
    query_hash = _hash(exchange.query)
    facets: dict[str, Any] = {
        "engine": exchange.engine,
        "query_hash": query_hash,
        "result_count": len(exchange.results),
        "verbosity_level": verbosity.value,
    }
    if exchange.cost_estimate_cents is not None:
        facets["cost_estimate_cents"] = exchange.cost_estimate_cents
    if exchange.request_id:
        facets["request_id"] = exchange.request_id

    results: list[dict[str, Any]] = []
    if verbosity in (VerbosityLevel.PREVIEW, VerbosityLevel.PREVIEW_PLUS_CITATIONS,
                     VerbosityLevel.FULL, VerbosityLevel.FULL_PLUS_TRACE):
        facets["query"] = redact_for_capture(exchange.query)
        for r in exchange.results:
            row = {"url": redact_for_capture(r.url), "title": redact_for_capture(r.title), "rank": r.rank}
            if verbosity in (VerbosityLevel.FULL, VerbosityLevel.FULL_PLUS_TRACE):
                row["full_text"] = redact_for_capture(r.full_text)
            else:
                row["snippet"] = _short(redact_for_capture(r.snippet), 200)
            results.append(row)

    payload: dict[str, Any] = {"kind": "web_search", "scope": "web", "facets": facets, "results": results}
    if verbosity == VerbosityLevel.FULL_PLUS_TRACE:
        payload["trace"] = list(exchange.trace)
    return payload


def capture_web_exchange(
    exchange: WebSearchExchange, *, mode: IngestMode, oversight,
    chain: RecordSink, signer: Issuer,
    oversight_active: bool = True, actor: str = "agent",
) -> CaptureResult:
    oversight_level = coerce_oversight(oversight)
    verbosity, prompted = decide_verbosity(mode, oversight_level, oversight_active=oversight_active)
    if verbosity == VerbosityLevel.NONE:
        return CaptureResult(False, None, VerbosityLevel.NONE, prompted, mode,
                             skipped_reason=("low_oversight_interactive"
                                            if mode == IngestMode.INTERACTIVE
                                            else "verbosity_none"),
                             oversight_bypassed=not oversight_active)
    payload = _project_pair(exchange, verbosity)
    envelope = chain_receipt.build_record(
        signer=signer, chain=chain, tool="agent_gate.records.web_capture",
        payload=payload, executor_id=actor,
        executor_role="agent" if mode == IngestMode.AGENTIC else "user",
        dispatch_id=f"web:{_hash(exchange.query)}:{exchange.request_id or _hash(exchange.engine)}",
    )
    return CaptureResult(True, envelope["receipt"]["dispatch_id"], verbosity, prompted, mode,
                         oversight_bypassed=not oversight_active)
