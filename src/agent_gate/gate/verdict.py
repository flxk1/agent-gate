from __future__ import annotations

from enum import Enum
from typing import Iterable


class Verdict(str, Enum):
    PERMIT = "permit"
    HOLD = "hold"
    DENY = "deny"


_SEV = {Verdict.PERMIT: 0, Verdict.HOLD: 1, Verdict.DENY: 2}

GATE = {"GO": Verdict.PERMIT, "CONDITIONAL": Verdict.HOLD, "NO-GO": Verdict.DENY}
LIGHT = {"go": Verdict.PERMIT, "ask": Verdict.HOLD, "block": Verdict.DENY}
ADMISSION = {"admit": Verdict.PERMIT, "hold": Verdict.HOLD, "reject": Verdict.DENY}

_TO_GATE = {v: k for k, v in GATE.items()}
_TO_LIGHT = {v: k for k, v in LIGHT.items()}
_TO_ADMISSION = {v: k for k, v in ADMISSION.items()}


def severity(v: Verdict) -> int:
    return _SEV[v]


def strictest(*verdicts: Verdict) -> Verdict:
    vs = [v for v in verdicts if v is not None]
    if not vs:
        return Verdict.PERMIT
    return max(vs, key=lambda v: _SEV[v])


def strictest_of(verdicts: Iterable[Verdict]) -> Verdict:
    return strictest(*list(verdicts))


def from_gate(s: str | None) -> Verdict:
    if not s:
        return Verdict.PERMIT
    return GATE.get(s.upper(), Verdict.DENY)


def from_light(s: str | None) -> Verdict:
    if not s:
        return Verdict.PERMIT
    return LIGHT.get(s.lower(), Verdict.DENY)


def from_admission(s: str | None) -> Verdict:
    return ADMISSION.get((s or "").lower(), Verdict.HOLD)


def coerce(s: str | None, *, default: Verdict = Verdict.DENY) -> Verdict:
    try:
        return Verdict((s or "").strip().lower())
    except (ValueError, AttributeError):
        return default


def to_gate(v: Verdict) -> str:
    return _TO_GATE[v]


def to_light(v: Verdict) -> str:
    return _TO_LIGHT[v]


def to_admission(v: Verdict) -> str:
    return _TO_ADMISSION[v]
