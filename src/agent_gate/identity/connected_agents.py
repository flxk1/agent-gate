from __future__ import annotations

import json
import os
import re
import secrets
import subprocess
import time
from pathlib import Path
from typing import Optional


def _agents_dir(root: Optional[str] = None) -> Path:
    if root:
        base = Path(root)
    else:
        env = os.environ.get("AGENT_GATE_IDENTITY_DIR")
        base = Path(env) if env else Path.home() / ".agent-gate" / "identity"
    return base / "connected"


_LSTART_FMT = "%a %b %d %H:%M:%S %Y"


def pid_start_time(pid: int) -> Optional[float]:
    if not pid:
        return None
    try:
        p = subprocess.run(
            ["ps", "-o", "lstart=", "-p", str(int(pid))],
            capture_output=True, text=True, timeout=3.0, check=False,
            env={**os.environ, "LC_ALL": "C", "LANG": "C"},
        )
    except Exception:
        return None
    out = (p.stdout or "").strip()
    if not out:
        return None
    try:
        import datetime
        return datetime.datetime.strptime(out, _LSTART_FMT).timestamp()
    except Exception:
        return None


def pid_alive(pid: int) -> bool:
    if not pid:
        return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except Exception:
        return True


def pid_state(pid: int, recorded_start: Optional[float], *,
              now_start: Optional[float] = None) -> str:
    if not pid_alive(pid):
        return "gone"
    if recorded_start is None:
        return "unknown"
    current = now_start if now_start is not None else pid_start_time(pid)
    if current is None:
        return "unknown"
    return "same" if abs(current - recorded_start) < 2.0 else "recycled"


def pid_still_same(pid: int, recorded_start: Optional[float], *,
                   now_start: Optional[float] = None) -> bool:
    if not pid_alive(pid):
        return False
    if recorded_start is None:
        return False
    current = now_start if now_start is not None else pid_start_time(pid)
    if current is None:
        return False
    return abs(current - recorded_start) < 2.0


def register_connection(*, agent: str, transport: str = "stdio",
                        pid: Optional[int] = None, now: Optional[float] = None,
                        session_id: Optional[str] = None,
                        root: Optional[str] = None) -> str:
    connid = secrets.token_hex(8)
    sid = (session_id if session_id is not None
           else os.environ.get("CLAUDE_CODE_SESSION_ID") or "")
    rpid = int(pid if pid is not None else os.getpid())
    rec = {
        "connid": connid,
        "agent": (agent or "").strip() or "unnamed-agent",
        "transport": transport,
        "pid": rpid,
        "pid_start": pid_start_time(rpid),
        "session_id": (sid or "").strip(),
        "client_name": "",
        "client_version": "",
        "connected_at": float(now if now is not None else time.time()),
    }
    try:
        d = _agents_dir(root)
        d.mkdir(parents=True, exist_ok=True)
        (d / f"{connid}.json").write_text(json.dumps(rec), encoding="utf-8")
    except Exception:
        pass
    return connid


def deregister_connection(connid: str, *, root: Optional[str] = None) -> None:
    try:
        (_agents_dir(root) / f"{connid}.json").unlink(missing_ok=True)
    except Exception:
        pass


def update_client_info(connid: str, *, name: str, version: str,
                       root: Optional[str] = None) -> bool:
    nm = (name or "").strip()
    if not nm:
        return False
    ver = (version or "").strip()
    try:
        f = _agents_dir(root) / f"{connid}.json"
        if not f.exists():
            return False
        rec = json.loads(f.read_text(encoding="utf-8"))
        if (rec.get("client_name") or "").strip():
            return False
        rec["client_name"] = nm
        rec["client_version"] = ver
        f.write_text(json.dumps(rec), encoding="utf-8")
        return True
    except Exception:
        return False


_SID_RE = re.compile(r"CLAUDE_CODE_SESSION_ID=([0-9A-Za-z._-]+)")


def _pid_session_id(pid: int) -> Optional[str]:
    if not pid:
        return None
    try:
        p = subprocess.run(
            ["ps", "eww", "-o", "command=", str(int(pid))],
            capture_output=True, text=True, timeout=3.0, check=False)
    except Exception:
        return None
    m = _SID_RE.search(p.stdout or "")
    return m.group(1) if m else None


def backfill_session_ids(*, root: Optional[str] = None) -> int:
    updated = 0
    try:
        d = _agents_dir(root)
        if not d.exists():
            return 0
        for f in d.glob("*.json"):
            try:
                rec = json.loads(f.read_text(encoding="utf-8"))
            except Exception:
                continue
            if (rec.get("session_id") or "").strip():
                continue
            pid = int(rec.get("pid", 0) or 0)
            if not pid_still_same(pid, rec.get("pid_start")):
                continue
            sid = _pid_session_id(pid)
            if not sid:
                continue
            rec["session_id"] = sid
            try:
                f.write_text(json.dumps(rec), encoding="utf-8")
                updated += 1
            except Exception:
                pass
    except Exception:
        return updated
    return updated


def list_connected(*, now: Optional[float] = None, root: Optional[str] = None,
                   ttl_seconds: float = 86400.0) -> list[dict]:
    now = float(now if now is not None else time.time())
    out: list[dict] = []
    try:
        backfill_session_ids(root=root)
    except Exception:
        pass
    try:
        d = _agents_dir(root)
        if not d.exists():
            return []
        for f in d.glob("*.json"):
            try:
                rec = json.loads(f.read_text(encoding="utf-8"))
            except Exception:
                continue
            pid = int(rec.get("pid", 0) or 0)
            state = pid_state(pid, rec.get("pid_start")) if pid else "same"
            if state in ("gone", "recycled"):
                try:
                    f.unlink(missing_ok=True)
                except Exception:
                    pass
                continue
            if state == "unknown":
                continue
            if not pid and now - float(rec.get("connected_at", 0) or 0) > ttl_seconds:
                continue
            out.append(rec)
    except Exception:
        return out
    out.sort(key=lambda r: r.get("connected_at", 0), reverse=True)
    return out
