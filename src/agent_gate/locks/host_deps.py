from __future__ import annotations

from typing import Any, Callable, Optional

key_root_dir: Optional[Callable[[], Any]] = None
capability_verifier_factory: Optional[Callable[[], Any]] = None
record_audit_drop: Optional[Callable[..., Any]] = None
record_capability_refusal: Optional[Callable[..., Any]] = None
verify_agent_identity: Optional[Callable[..., Any]] = None
policy_admit: Optional[Callable[..., Any]] = None

_wired = False


def ensure_wired() -> None:
    global _wired
    if _wired:
        return
    _wired = True
    try:
        from . import lock_wiring  # noqa: F401
    except Exception:
        pass
