from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

POLICY_ENV = "AGENT_GATE_POLICY"


@dataclass(frozen=True)
class PolicyLoadResult:
    policy: Optional[Any]
    loaded: bool
    error: Optional[str]
    path: Optional[str]


def policy_path() -> Optional[Path]:
    env = os.environ.get(POLICY_ENV)
    return Path(env) if env else None


def load_policy() -> PolicyLoadResult:
    path = policy_path()
    if path is None:
        return PolicyLoadResult(None, False, f"{POLICY_ENV} is not set", None)
    if not path.exists():
        return PolicyLoadResult(None, False, f"policy file not found: {path}", str(path))
    try:
        from policy_compiler.compile import compile as compile_policy

        policy = compile_policy(path)
    except Exception as exc:
        return PolicyLoadResult(None, False, f"{type(exc).__name__}: {exc}", str(path))
    return PolicyLoadResult(policy, True, None, str(path))


__all__ = ["POLICY_ENV", "PolicyLoadResult", "policy_path", "load_policy"]
