from __future__ import annotations

import contextvars as _contextvars
import os
from pathlib import Path
from typing import Optional


def _log_root() -> Optional[Path]:
    v = os.environ.get("AGENT_GATE_LOG_ROOT")
    return Path(v) if v else None


_request_principal: _contextvars.ContextVar[Optional[dict]] = \
    _contextvars.ContextVar("request_principal", default=None)


def set_request_principal(principal: str, party: Optional[str],
                          rung: str = "proxy-verified") -> None:
    _request_principal.set({"principal": principal, "party": party,
                            "rung": rung if party else ""})


def get_request_principal() -> Optional[dict]:
    return _request_principal.get()


def clear_request_principal() -> None:
    _request_principal.set(None)


_FOLDER_ADDRESSING_KEYS = ("folder_context", "folder", "path")
_REMOTE_STORAGE_ROOT_KEYS = ("log_root", "user_root", "store_root", "key_dir")


def apply_principal_to_params(fn, params: dict) -> Optional[dict]:
    ctx = get_request_principal()
    if ctx is None:
        return None
    supplied_roots = sorted(set(params or {}).intersection(_REMOTE_STORAGE_ROOT_KEYS))
    if supplied_roots:
        return {
            "ok": False,
            "error": "server-owned storage roots cannot be overridden by a remote request",
            "refused_params": supplied_roots,
        }
    if fn is None:
        accepts_actor = True
    else:
        import inspect
        try:
            accepts_actor = "actor" in inspect.signature(fn).parameters
        except (TypeError, ValueError):
            accepts_actor = False
    if ctx.get("party"):
        if accepts_actor:
            params["actor"] = ctx["party"]
        return None
    addresses_folder = any((params or {}).get(k) for k in _FOLDER_ADDRESSING_KEYS)
    if addresses_folder or (fn is not None and accepts_actor):
        return {"ok": False,
                "error": f"principal {ctx.get('principal')!r} is not a"
                         " registered party -- the operation is refused,"
                         " reads included (fail-closed: an unmatched"
                         " principal reads nothing here, never everything)."}
    return None
