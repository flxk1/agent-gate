from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

import agent_gate

PKG = Path(agent_gate.__file__).parent
MODELS = PKG / "models"
ALLOWED_CORE = {"agent_gate.subject", "agent_gate.ports"}


def _imports(path: Path) -> set[str]:
    rel = path.relative_to(PKG.parent).with_suffix("")
    parts = list(rel.parts)
    if parts[-1] == "__init__":
        parts = parts[:-1]
    package = parts if path.name == "__init__.py" else parts[:-1]
    out: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.Import):
            out.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                base = package[: len(package) - node.level + 1]
                mod = ".".join(base + ([node.module] if node.module else []))
                if node.module is None:
                    out.update(f"{mod}.{a.name}" for a in node.names)
                    continue
            else:
                mod = node.module or ""
            out.add(mod)
    return out


def test_nothing_outside_models_imports_models():
    offenders = {}
    for f in PKG.rglob("*.py"):
        if MODELS in f.parents:
            continue
        hits = {m for m in _imports(f) if m == "agent_gate.models" or m.startswith("agent_gate.models.")}
        if hits:
            offenders[str(f.relative_to(PKG))] = hits
    assert offenders == {}


def test_models_reach_core_only_through_subject_and_ports():
    for f in MODELS.rglob("*.py"):
        core = {m for m in _imports(f) if m.startswith("agent_gate")
                and not m.startswith("agent_gate.models")}
        assert core <= ALLOWED_CORE, (f.name, core)


def test_gate_hook_imports_with_models_absent():
    code = (
        "import sys, importlib.abc\n"
        "class Block(importlib.abc.MetaPathFinder):\n"
        "    def find_spec(self, name, path=None, target=None):\n"
        "        if name == 'agent_gate.models' or name.startswith('agent_gate.models.'):\n"
        "            raise ImportError('models extra absent')\n"
        "sys.meta_path.insert(0, Block())\n"
        "import agent_gate.gate.hook\n"
        "try:\n"
        "    import agent_gate.models\n"
        "except ImportError:\n"
        "    print('hook-ok models-blocked')\n"
    )
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                       env={"PYTHONPATH": str(PKG.parent), "PYTHONDONTWRITEBYTECODE": "1"})
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "hook-ok models-blocked"


def test_gate_hook_does_not_load_models():
    code = "import sys, agent_gate.gate.hook; print(any(m.startswith('agent_gate.models') for m in sys.modules))"
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                       env={"PYTHONPATH": str(PKG.parent), "PYTHONDONTWRITEBYTECODE": "1"})
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "False"
