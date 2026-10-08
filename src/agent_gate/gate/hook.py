from __future__ import annotations

import json
import os
import re
import signal
import sys
from collections import namedtuple
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

from .executor import Gate, GateResult, HostMediatedExecutor
from .glue import decide_and_permit
from .scope import scope_for
from .verdict import Verdict

IRREVERSIBLE = "irreversible"
SECURITY_CONTROL = "security-control"

_IRREVERSIBLE_PATTERNS = (
    r"\brm\s+-[a-z]*r[a-z]*f",
    r"\brm\s+-[a-z]*f[a-z]*r",
    r"\bgit\s+.*\b(reset\s+--hard|clean\s+-[a-z]*f|push\s+.*(--force|-f)\b)",
    r"\bmkfs\b", r"\bshred\b", r"\bdd\s+if=", r">\s*/dev/(sd|disk|nvme)",
    r"\b(truncate|fdisk|parted)\b", r":\(\)\s*\{\s*:\|:",
)
_SECURITY_PATTERNS = (
    r"\bsudo\b", r"\bdoas\b", r"\bchmod\s+-?R?\s*777\b", r"\bchown\b",
    r"\b(launchctl|systemctl|service)\b", r"\bcsrutil\b", r"\bspctl\b",
    r"curl\s+[^|]*\|\s*(sudo\s+)?(ba)?sh", r"wget\s+[^|]*\|\s*(ba)?sh",
    r"\bpip\s+install\b.*--break-system-packages",
)
_SENSITIVE_PATHS = (
    "/etc/", "/usr/", "/bin/", "/sbin/", "/System/", "/Library/LaunchDaemons",
)
_SENSITIVE_HOME = (".ssh", ".aws", ".gnupg", ".claude", ".config/gcloud")


def _norm(s: str) -> str:
    return " ".join((s or "").split())


def _touches_sensitive(path: str) -> bool:
    if not path:
        return False
    p = path.strip()
    if any(p.startswith(pre) or f" {pre}" in f" {p}" for pre in _SENSITIVE_PATHS):
        return True
    home = str(Path.home())
    try:
        rel = os.path.relpath(os.path.abspath(os.path.expanduser(p)), home)
    except Exception:
        rel = ""
    first = rel.split(os.sep)[0] if rel and not rel.startswith("..") else ""
    second = os.sep.join(rel.split(os.sep)[:2]) if rel else ""
    return first in _SENSITIVE_HOME or second in _SENSITIVE_HOME


def classify(tool_name: str, tool_input: dict[str, Any], cwd: str = "") -> tuple[
        str, tuple[str, ...], tuple[str, ...], list[dict[str, Any]]]:
    name = tool_name or ""
    ti = tool_input if isinstance(tool_input, dict) else {}
    foot: set[str] = set()
    evidence: list[dict[str, Any]] = []

    def _flag(tag: str, matched: str, start: int = -1, end: int = -1) -> None:
        foot.add(tag)
        evidence.append({"tag": tag, "matched": matched, "start": start, "end": end})

    if name == "Bash":
        action_class = "shell.exec"
        cmd = _norm(str(ti.get("command", "")))
        low = cmd.lower()
        for p in _IRREVERSIBLE_PATTERNS:
            m = re.search(p, low)
            if m:
                _flag(IRREVERSIBLE, m.group(0), m.start(), m.end())
        for p in _SECURITY_PATTERNS:
            m = re.search(p, low)
            if m:
                _flag(SECURITY_CONTROL, m.group(0), m.start(), m.end())
        for m in re.finditer(r"(?:>>?|\btee\s+|\binto\s+)\s*([^\s;|&]+)", low):
            if _touches_sensitive(m.group(1)):
                _flag(SECURITY_CONTROL, m.group(1), m.start(1), m.end(1))
    elif name in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
        action_class = "fs.write"
        target = str(ti.get("file_path", "") or ti.get("notebook_path", ""))
        if _touches_sensitive(target):
            _flag(SECURITY_CONTROL, target)
    elif name in ("Read", "Glob", "Grep"):
        action_class = "fs.read"
    elif name == "WebFetch":
        action_class = "net.fetch"
    elif name == "WebSearch":
        action_class = "net.search"
    elif name.startswith("mcp__"):
        parts = name.split("__", 2)
        server = parts[1] if len(parts) > 1 else "?"
        tool = parts[2] if len(parts) > 2 else "?"
        action_class = f"mcp.{server}.{tool}"
    else:
        action_class = f"tool.{name.lower() or 'unknown'}"

    return action_class, tuple(sorted(foot)), (), evidence


Decision = namedtuple("Decision", "kind reason detail")

_VERDICT_TO_KIND = {Verdict.PERMIT: "allow", Verdict.HOLD: "ask", Verdict.DENY: "deny"}


def _agent(evt: dict[str, Any]) -> str:
    return (os.environ.get("AGENT_GATE_AGENT")
            or evt.get("agent_id") or evt.get("session_id") or "claude-code")


def _unblock_hint(footprint: tuple[str, ...]) -> str:
    if not footprint:
        return ""
    return "to proceed: obtain an admitted permit for this action -- a human sign-off or a policy change"


def _default_decide(evt: dict[str, Any], *, action_class: str,
                    footprint: tuple[str, ...]) -> GateResult:
    from . import wiring as _wiring_mod
    from ..identity import session_owner_pid

    w = _wiring_mod.default_wiring()
    session_id = str(evt.get("session_id") or "")
    tool_name = str(evt.get("tool_name", ""))
    tool_input = evt.get("tool_input") or {}
    dispatch_id = str(evt.get("tool_use_id") or f"{tool_name}:{id(evt)}")
    gate = Gate(
        identity=w.identity, trust_store=w.trust_store, nonce_store=w.nonce_store,
        executor=w.executor, signer=w.issuer, chain=w.chain, revocation_store=w.revocation_store,
    )
    actor = w.identity.claim(session_id, pid=session_owner_pid())
    if not actor:
        return gate.refuse(session_id=session_id, tool=tool_name, arguments=tool_input, dispatch_id=dispatch_id,
                           reasons=(f"session {session_id!r} is not bound to this process",))
    decision = decide_and_permit(
        breaker=w.breaker, policy=w.policy, actor=actor, target_kind=action_class,
        tool=tool_name, arguments=tool_input, trust_store=w.trust_store,
        nonce_store=w.nonce_store, issuer=w.issuer, run_id=dispatch_id,
    )
    return gate.call(session_id=session_id, tool=tool_name, arguments=tool_input,
                     permit=decision.permit, dispatch_id=dispatch_id, run_id=dispatch_id)


def evaluate(evt: dict[str, Any],
             *, decide: Optional[Callable[..., GateResult]] = None) -> Decision:
    try:
        tool_name = str(evt.get("tool_name", ""))
        tool_input = evt.get("tool_input") or {}
        cwd = str(evt.get("cwd") or os.getcwd())
        action_class, footprint, affected, evidence = classify(tool_name, tool_input, cwd)
        scope_for(cwd, tool_name, tool_input)

        strict = os.environ.get("AGENT_GATE_HOOK_STRICT", "").strip() in ("1", "true", "yes")
        if not footprint and not strict:
            return Decision("allow", f"benign ({action_class}); no risk footprint",
                            {"action_class": action_class, "footprint": []})

        if decide is None:
            decide = _default_decide

        result = decide(evt, action_class=action_class, footprint=footprint)
        detail = {"action_class": action_class, "footprint": list(footprint),
                  "evidence": evidence, "reasons": list(result.reasons)}
        kind = _VERDICT_TO_KIND.get(result.verdict)
        if kind is None:
            return Decision("fail", f"unrecognised verdict {result.verdict!r}", detail)
        if kind == "allow":
            return Decision("allow", "permitted", detail)
        if kind == "ask":
            reason = "; ".join(result.reasons) or "requires human sign-off"
            return Decision("ask", f"{reason} -- approve to proceed, or decline", detail)
        hint = _unblock_hint(footprint)
        reason = "; ".join(result.reasons) or "blocked by policy"
        return Decision("deny", f"{reason}" + (f". {hint}" if hint else ""), detail)
    except SystemExit:
        raise
    except BaseException as e:  # noqa: BLE001
        return Decision("fail", f"{type(e).__name__}: {e}", {})


def _mode() -> str:
    return os.environ.get("AGENT_GATE_HOOK_MODE", "monitor").strip().lower() or "monitor"


def emit(decision: Decision, mode: Optional[str] = None) -> None:
    mode = mode or _mode()
    kind = decision.kind
    if kind == "allow":
        sys.exit(0)

    if kind == "ask":
        if mode == "monitor":
            print(f"[agent-gate:monitor] would ASK (sign-off): {decision.reason}", file=sys.stderr)
            sys.exit(0)
        print(json.dumps({"hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "ask",
            "permissionDecisionReason": f"[agent-gate] {decision.reason}",
        }}))
        sys.exit(0)

    if kind == "deny":
        if mode == "monitor":
            print(f"[agent-gate:monitor] would BLOCK: {decision.reason}", file=sys.stderr)
            sys.exit(0)
        print(f"[agent-gate] blocked: {decision.reason}", file=sys.stderr)
        sys.exit(2)

    if mode == "monitor":
        print(f"[agent-gate:monitor] evaluation error (would fail closed): {decision.reason}",
              file=sys.stderr)
        sys.exit(0)
    print(f"[agent-gate] failing closed -- gate unavailable: {decision.reason}. "
          f"Remove the agent-gate PreToolUse hook from .claude/settings.json to disable.",
          file=sys.stderr)
    sys.exit(2)


def _arm_deadline(mode: str) -> None:
    if not hasattr(signal, "SIGALRM"):
        return
    try:
        seconds = int(os.environ.get("AGENT_GATE_HOOK_DEADLINE", "15"))
    except ValueError:
        seconds = 15

    def _on_timeout(signum, frame):  # noqa: ANN001
        emit(Decision("fail", "gate evaluation exceeded deadline", {}), mode)

    signal.signal(signal.SIGALRM, _on_timeout)
    signal.alarm(max(1, seconds))


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _run_posttooluse(evt: dict[str, Any]) -> None:
    try:
        from . import wiring as _wiring_mod
        w = _wiring_mod.default_wiring()
        receipt = w.chain.tail()
        if not receipt or receipt.get("type") != "ToolReceipt":
            return
    except Exception:
        pass


def run_hook(stdin_text: Optional[str] = None) -> None:
    mode = _mode()
    if mode == "off":
        sys.exit(0)
    raw = sys.stdin.read() if stdin_text is None else stdin_text
    try:
        evt = json.loads(raw) if raw and raw.strip() else {}
        if not isinstance(evt, dict):
            raise ValueError("hook input is not a JSON object")
    except Exception as e:
        emit(Decision("fail", f"unparseable hook input: {e}", {}), mode)
        return

    if str(evt.get("hook_event_name") or "PreToolUse") == "PostToolUse":
        _run_posttooluse(evt)
        sys.exit(0)

    _arm_deadline(mode)
    decision = evaluate(evt)
    emit(decision, mode)


_MATCHER_ALL = "*"
_MARKER = "agent-gate-hook"
_EVENTS = ("PreToolUse", "PostToolUse")


def _settings_path(scope: str, base_dir: Optional[str]) -> Path:
    if scope == "user":
        return Path.home() / ".claude" / "settings.json"
    return Path(base_dir or os.getcwd()) / ".claude" / "settings.json"


def _hook_command() -> str:
    import shutil
    argv0 = Path(sys.argv[0]) if sys.argv and sys.argv[0] else None
    if argv0 and argv0.name.startswith("agent-gate-hook") and argv0.exists():
        return str(argv0.resolve())
    which = shutil.which("agent-gate-hook")
    if which:
        return which
    return f"{sys.executable} -m agent_gate.gate.hook"


def _is_ours(entry: dict[str, Any]) -> bool:
    for h in entry.get("hooks", []) or []:
        command = str(h.get("command", ""))
        if _MARKER in command or "agent_gate.gate.hook" in command:
            return True
    return False


def _install(scope: str, base_dir: Optional[str], timeout: int,
             command: Optional[str] = None) -> Path:
    path = _settings_path(scope, base_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    data: dict[str, Any] = {}
    if path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8") or "{}")
        except Exception as e:
            raise SystemExit(f"refusing to edit unparseable {path}: {e}")
        bak = path.with_suffix(".json.agent-gate-bak")
        if not bak.exists():
            bak.write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
    cmd = command or _hook_command()
    hooks = data.setdefault("hooks", {})
    for event in _EVENTS:
        arr = hooks.setdefault(event, [])
        if any(e.get("matcher") in (_MATCHER_ALL, "", None) and _is_ours(e) for e in arr):
            continue
        arr.append({
            "matcher": _MATCHER_ALL,
            "hooks": [{"type": "command", "command": cmd, "timeout": timeout}],
        })
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return path


def _uninstall(scope: str, base_dir: Optional[str]) -> tuple[Path, int]:
    path = _settings_path(scope, base_dir)
    if not path.exists():
        return path, 0
    try:
        data = json.loads(path.read_text(encoding="utf-8") or "{}")
    except Exception as e:
        raise SystemExit(f"refusing to edit unparseable {path}: {e}")
    hooks = data.get("hooks") or {}
    removed = 0
    for event in _EVENTS:
        arr = hooks.get(event) or []
        kept = [e for e in arr if not _is_ours(e)]
        removed += len(arr) - len(kept)
        if len(kept) != len(arr):
            if kept:
                hooks[event] = kept
            else:
                hooks.pop(event, None)
    if removed:
        if not hooks:
            data.pop("hooks", None)
        path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return path, removed


def _installed_at(path: Path) -> bool:
    if not path.exists():
        return False
    try:
        data = json.loads(path.read_text(encoding="utf-8") or "{}")
    except Exception:
        return False
    hooks = data.get("hooks") or {}
    return any(_is_ours(e) for event in _EVENTS for e in (hooks.get(event) or []))


def _scan(base_dir: Optional[str]) -> list[tuple[str, Path, bool]]:
    return [(scope, p, _installed_at(p)) for scope, p in (
        ("project", _settings_path("project", base_dir)),
        ("user", _settings_path("user", None)),
    )]


def _cli(argv: list[str]) -> int:
    import argparse
    ap = argparse.ArgumentParser(
        prog="agent-gate-hook",
        description="Manage the agent-gate PreToolUse enforcement hook. "
                    "With no arguments, runs AS the hook.")
    ap.add_argument("--install", action="store_true")
    ap.add_argument("--uninstall", action="store_true")
    ap.add_argument("--status", action="store_true")
    ap.add_argument("--scope", choices=("project", "user"), default=None)
    ap.add_argument("--dir", default=None)
    ap.add_argument("--timeout", type=int, default=30)
    ap.add_argument("--command", default=None)
    args = ap.parse_args(argv)

    if args.install:
        scope = args.scope or "project"
        path = _install(scope, args.dir, args.timeout, args.command)
        print(f"installed ({scope}): {path}  mode={_mode()}")
        return 0
    if args.uninstall:
        scope = args.scope or "project"
        path, n = _uninstall(scope, args.dir)
        print(f"removed {n} entr{'y' if n == 1 else 'ies'} from {path}")
        return 0
    if args.status:
        scopes = [args.scope] if args.scope else ["project", "user"]
        for sc in scopes:
            p = _settings_path(sc, args.dir)
            print(f"{'installed' if _installed_at(p) else 'not installed'} ({sc}): {p}")
        return 0
    ap.print_help()
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv:
        return _cli(argv)
    run_hook()
    return 0


if __name__ == "__main__":
    sys.exit(main())
