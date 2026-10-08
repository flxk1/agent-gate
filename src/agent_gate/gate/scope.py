from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

_FILE_PATH_TOOLS = ("Write", "Edit", "MultiEdit")
_NOTEBOOK_PATH_TOOL = "NotebookEdit"


@dataclass(frozen=True)
class ScopeCoordinate:

    cwd: str
    targets: tuple[str, ...] = ()


def _resolve_target_path(raw: Any, cwd: str) -> Optional[str]:
    if not isinstance(raw, str) or not raw:
        return None
    p = Path(raw).expanduser()
    if not p.is_absolute():
        base = Path(str(cwd or os.getcwd())).expanduser()
        p = base / p
    return str(p.resolve())


def resolve_targets(cwd: str, tool_name: str, tool_input: dict[str, Any]) -> tuple[str, ...]:
    try:
        name = str(tool_name or "")
        ti = tool_input if isinstance(tool_input, dict) else {}
        if name in _FILE_PATH_TOOLS:
            raw = ti.get("file_path")
        elif name == _NOTEBOOK_PATH_TOOL:
            raw = ti.get("notebook_path")
        else:
            return ()
        resolved = _resolve_target_path(raw, cwd)
        return (resolved,) if resolved else ()
    except BaseException:  # noqa: BLE001
        return ()


def scope_for(cwd: str, tool_name: str, tool_input: dict[str, Any]) -> ScopeCoordinate:
    try:
        targets = resolve_targets(cwd, tool_name, tool_input)
    except BaseException:  # noqa: BLE001
        targets = ()
    return ScopeCoordinate(cwd=str(cwd or ""), targets=targets)
