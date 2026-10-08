from __future__ import annotations

import json
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _manifest() -> dict:
    return json.loads((ROOT / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8"))


def _resolve(rel: str) -> Path:
    assert isinstance(rel, str) and rel.startswith("./")
    return (ROOT / rel).resolve()


def check_manifest(manifest: dict) -> None:
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert manifest["name"] == "agent-gate"
    assert manifest["version"] == pyproject["project"]["version"]
    if "agents" in manifest:
        agents = manifest["agents"]
        assert isinstance(agents, list)
        for entry in agents:
            assert _resolve(entry).is_file()

    hooks_file = _resolve(manifest["hooks"])
    assert hooks_file.is_file()
    hooks = json.loads(hooks_file.read_text(encoding="utf-8"))["hooks"]
    for event in ("PreToolUse", "PostToolUse"):
        commands = [h for entry in hooks[event] for h in entry["hooks"]]
        assert commands
        assert all(h["type"] == "command" for h in commands)
        assert any(h["command"].split()[0] == "agent-gate-hook" for h in commands)
    blob = hooks_file.read_text(encoding="utf-8")
    assert "AGENT_GATE_HOOK_MODE" not in blob
    assert "enforce" not in blob

    skills_dir = _resolve(manifest["skills"])
    skill = skills_dir / "agent-gate-setup" / "SKILL.md"
    assert skill.is_file()
    assert skill.read_text(encoding="utf-8").startswith("---\nname: agent-gate-setup\n")


def test_manifest_is_valid():
    check_manifest(_manifest())


@pytest.mark.parametrize("mutate", [
    lambda m: m.update(version="9.9.9"),
    lambda m: m.update(agents="./agents/"),
    lambda m: m.update(agents=["./agents/missing.md"]),
    lambda m: m.update(hooks="./hooks/missing.json"),
    lambda m: m.update(skills="./missing/"),
    lambda m: m.update(name="other"),
])
def test_manifest_mutants_fail(mutate):
    manifest = _manifest()
    mutate(manifest)
    with pytest.raises((AssertionError, KeyError)):
        check_manifest(manifest)
