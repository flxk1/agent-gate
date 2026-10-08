from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Optional

import pytest

_BIN = Path(sys.executable).parent
AGENT_GATE_BIN = str(_BIN / "agent-gate")
AGENT_GATE_HOOK_BIN = str(_BIN / "agent-gate-hook")


@pytest.fixture(autouse=True, scope="module")
def _require_console_scripts():
    missing = [b for b in (AGENT_GATE_BIN, AGENT_GATE_HOOK_BIN) if not Path(b).exists()]
    assert not missing, f"console scripts not installed next to {sys.executable}: {missing}"


def run_cli(args: list[str], *, env: dict[str, str], input_text: Optional[str] = None,
           timeout: float = 30.0) -> subprocess.CompletedProcess:
    return subprocess.run(
        [AGENT_GATE_BIN, *args], env=env, input=input_text,
        capture_output=True, text=True, timeout=timeout,
    )


def run_hook(evt: dict[str, Any], *, env: dict[str, str],
            timeout: float = 30.0) -> subprocess.CompletedProcess:
    return subprocess.run(
        [AGENT_GATE_HOOK_BIN], env=env, input=json.dumps(evt),
        capture_output=True, text=True, timeout=timeout,
    )


def base_env(home: Path, *, mode: str = "monitor",
             policy: Optional[Path] = None, extra: Optional[dict[str, str]] = None) -> dict[str, str]:
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": os.environ.get("HOME", ""),
        "AGENT_GATE_HOME": str(home),
        "AGENT_GATE_HOOK_MODE": mode,
    }
    if policy is not None:
        env["AGENT_GATE_POLICY"] = str(policy)
    if extra:
        env.update(extra)
    return env


def pretooluse_event(*, session_id: str, tool_name: str, tool_input: dict[str, Any],
                     cwd: str, transcript_path: str) -> dict[str, Any]:
    return {
        "session_id": session_id,
        "transcript_path": transcript_path,
        "cwd": cwd,
        "hook_event_name": "PreToolUse",
        "tool_name": tool_name,
        "tool_input": tool_input,
    }


def posttooluse_event(*, session_id: str, tool_name: str, tool_input: dict[str, Any],
                      tool_response: dict[str, Any], cwd: str,
                      transcript_path: str) -> dict[str, Any]:
    return {
        "session_id": session_id,
        "transcript_path": transcript_path,
        "cwd": cwd,
        "hook_event_name": "PostToolUse",
        "tool_name": tool_name,
        "tool_input": tool_input,
        "tool_response": tool_response,
    }


@pytest.fixture
def gate_home(tmp_path):
    home = tmp_path / "gate-home"
    env = base_env(home)
    init = run_cli(["init"], env=env)
    assert init.returncode == 0, init.stderr
    status_proc = run_cli(["status"], env=env)
    status = json.loads(status_proc.stdout)
    assert status["initialized"] is True
    return home, status


@pytest.fixture
def transcript(tmp_path):
    p = tmp_path / "transcript.jsonl"
    p.write_text("", encoding="utf-8")
    return str(p)
