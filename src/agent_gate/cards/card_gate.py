from __future__ import annotations

from typing import Any, Iterable, Optional

from ..gate import verdict as _v

ALLOW, HOLD, DENY = _v.Verdict.PERMIT.value, _v.Verdict.HOLD.value, _v.Verdict.DENY.value


def normalise(word: str) -> str:
    w = (word or "").strip().lower()
    for table in (_v.ADMISSION, _v.LIGHT):
        if w in table:
            return table[w].value
    if w.upper() in _v.GATE:
        return _v.GATE[w.upper()].value
    return _v.coerce(w, default=_v.Verdict.HOLD).value


def strictest(verdicts: Iterable[str]) -> str:
    return _v.strictest_of(_v.Verdict(normalise(v)) for v in verdicts).value


def check_envelope(envelope: dict[str, Any], candidate: dict[str, Any]) -> tuple[str, str]:
    if not envelope:
        return ALLOW, "no envelope"
    dis = envelope.get("disallow") or {}
    for facet, banned in dis.items():
        v = candidate.get(facet)
        if v is not None and v in set(banned):
            return DENY, f"disallow {facet}={v}"
    max_size = envelope.get("max_size")
    if max_size is not None:
        try:
            size = int(candidate.get("size", 0) or 0)
        except (TypeError, ValueError):
            return DENY, f"size {candidate.get('size')!r} unverifiable against max {max_size}"
        if size > int(max_size):
            return DENY, f"size {candidate.get('size')} > max {max_size}"
    allow = envelope.get("allow") or {}
    for facet, permitted in allow.items():
        v = candidate.get(facet)
        if v is None or v not in set(permitted):
            return DENY, f"not in allowlist {facet}={v!r}"
    return ALLOW, "envelope permits"


def enforce(rules: dict[str, Any], *, candidate: dict[str, Any],
           text: Optional[str] = None, data: Optional[bytes] = None,
           filename: Optional[str] = None) -> dict[str, Any]:
    rules = rules or {}
    reasons: list[str] = []
    env_verdict, env_reason = check_envelope(rules.get("envelope") or {}, candidate)
    reasons.append(f"envelope:{env_verdict} ({env_reason})")
    sig_verdict = ALLOW
    sig_threats: list[dict[str, Any]] = []
    if rules.get("signatures") and (text or data):
        from ..records import ingest_quarantine as _iq
        v = _iq.scan(text=text, data=data, filename=filename)
        sig_verdict = v.admission
        sig_threats = v.threats
        reasons.append(f"signatures:{sig_verdict} ({v.reason})")
    verdict = strictest([env_verdict, sig_verdict])
    return {"verdict": verdict, "reasons": reasons,
            "envelope": env_verdict, "signatures": sig_verdict, "threats": sig_threats}
