from __future__ import annotations

import json
import os
import re
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

from ..subject import Subject

_SAFE_KEY_RE = re.compile(r"[A-Za-z0-9_.:-]{1,256}")


class SettingsError(ValueError):
    pass


@dataclass
class Acknowledgement:
    by: str
    rationale: str
    at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class HostSettings:
    subject: str
    air_gapped: bool = False
    cost_cap_usd: Optional[float] = None
    lock_opt_out: bool = False
    lock_opt_out_ack: Optional[dict] = None
    oversight_opt_out: bool = False
    oversight_opt_out_ack: Optional[dict] = None
    updated: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return asdict(self)


def _settings_dir(root: Optional[str] = None) -> Path:
    if root:
        base = Path(root)
    else:
        env = os.environ.get("AGENT_GATE_SETTINGS_DIR")
        base = Path(env) if env else Path.home() / ".agent-gate" / "settings"
    return base


def _safe_key(subject: Subject) -> str:
    key = str(subject)
    return key if _SAFE_KEY_RE.fullmatch(key) else ""


def _path(subject: Subject, root: Optional[str]) -> Path:
    key = _safe_key(subject)
    if not key:
        raise SettingsError(f"unsafe subject key: {subject!r}")
    return _settings_dir(root) / f"{key.replace(':', '__')}.json"


def get_settings(subject: Subject, *, root: Optional[str] = None) -> HostSettings:
    p = _path(subject, root)
    if not p.exists():
        return HostSettings(subject=str(subject))
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return HostSettings(subject=str(subject))
    data.pop("subject", None)
    return HostSettings(subject=str(subject), **data)


def _save(subject: Subject, settings: HostSettings, *, root: Optional[str]) -> HostSettings:
    d = _settings_dir(root)
    d.mkdir(parents=True, exist_ok=True)
    _path(subject, root).write_text(json.dumps(settings.to_dict()), encoding="utf-8")
    return settings


def set_air_gap(subject: Subject, enabled: bool, *, root: Optional[str] = None) -> HostSettings:
    s = get_settings(subject, root=root)
    s.air_gapped = bool(enabled)
    s.updated = time.time()
    return _save(subject, s, root=root)


def set_cost_cap(subject: Subject, usd: Optional[float], *, root: Optional[str] = None) -> HostSettings:
    if usd is not None and float(usd) < 0:
        raise SettingsError("a cost cap cannot be negative")
    s = get_settings(subject, root=root)
    s.cost_cap_usd = None if usd is None else float(usd)
    s.updated = time.time()
    return _save(subject, s, root=root)


def set_lock_opt_out(
    subject: Subject, enabled: bool, *,
    acknowledged_by: str = "", rationale: str = "",
    root: Optional[str] = None,
) -> HostSettings:
    s = get_settings(subject, root=root)
    if enabled:
        if not (acknowledged_by or "").strip() or not (rationale or "").strip():
            raise SettingsError(
                "a lock opt-out requires a named human acknowledgement and rationale")
        s.lock_opt_out_ack = Acknowledgement(
            by=acknowledged_by.strip(), rationale=rationale.strip()).to_dict()
    else:
        s.lock_opt_out_ack = None
    s.lock_opt_out = bool(enabled)
    s.updated = time.time()
    return _save(subject, s, root=root)


def set_oversight_opt_out(
    subject: Subject, enabled: bool, *,
    acknowledged_by: str = "", rationale: str = "",
    root: Optional[str] = None,
) -> HostSettings:
    s = get_settings(subject, root=root)
    if enabled:
        if not (acknowledged_by or "").strip() or not (rationale or "").strip():
            raise SettingsError(
                "an oversight opt-out requires a named human acknowledgement and rationale")
        s.oversight_opt_out_ack = Acknowledgement(
            by=acknowledged_by.strip(), rationale=rationale.strip()).to_dict()
    else:
        s.oversight_opt_out_ack = None
    s.oversight_opt_out = bool(enabled)
    s.updated = time.time()
    return _save(subject, s, root=root)


__all__ = [
    "Acknowledgement", "HostSettings", "SettingsError",
    "get_settings", "set_air_gap", "set_cost_cap",
    "set_lock_opt_out", "set_oversight_opt_out",
]
