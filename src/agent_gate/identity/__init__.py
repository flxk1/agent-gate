from __future__ import annotations

import contextlib
import fcntl
import json
import os
import subprocess
from pathlib import Path
from typing import Callable, Iterator, Optional

from .connected_agents import pid_alive, pid_start_time

_PID_MATCH_TOLERANCE = 2.0
_SHELLS = frozenset({"sh", "bash", "zsh", "dash", "fish", "ksh", "tcsh", "csh"})


class IdentityStoreError(RuntimeError):
    pass


def _parent_and_name(pid: int) -> tuple[int, str]:
    out = subprocess.run(["ps", "-o", "ppid=,comm=", "-p", str(pid)], capture_output=True,
                         text=True, timeout=3.0, check=False,
                         env={**os.environ, "LC_ALL": "C", "LANG": "C"}).stdout.strip()
    if not out:
        return 0, ""
    ppid, _, comm = out.partition(" ")
    return int(ppid), os.path.basename(comm.strip()).lstrip("-")


def session_owner_pid(start: Optional[int] = None) -> int:
    pid = start if start is not None else os.getppid()
    for _ in range(16):
        parent, name = _parent_and_name(pid)
        if name not in _SHELLS or parent <= 1:
            return pid
        pid = parent
    return pid


class SessionIdentity:

    def __init__(self, *, root: Optional[str | Path] = None,
                 pid_alive_fn: Callable[[int], bool] = pid_alive,
                 pid_start_time_fn: Callable[[int], Optional[float]] = pid_start_time) -> None:
        self._bindings: dict[str, tuple[int, Optional[float], str]] = {}
        self._pid_alive = pid_alive_fn
        self._pid_start_time = pid_start_time_fn
        self._path = Path(root) / "sessions.json" if root is not None else None

    @contextlib.contextmanager
    def _locked(self) -> Iterator[None]:
        if self._path is None:
            yield
            return
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._path.with_suffix(".lock"), "a") as fh:
            fcntl.flock(fh, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(fh, fcntl.LOCK_UN)

    def _load(self) -> dict[str, tuple[int, Optional[float], str]]:
        if self._path is None:
            return dict(self._bindings)
        if not self._path.exists():
            return {}
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
            return {k: (int(v[0]), v[1], str(v[2])) for k, v in raw.items()}
        except Exception as exc:
            raise IdentityStoreError(f"unreadable session store {self._path}") from exc

    def _save(self, data: dict[str, tuple[int, Optional[float], str]]) -> None:
        if self._path is None:
            self._bindings = data
            return
        tmp = self._path.with_name(f".sessions.{os.getpid()}.tmp")
        tmp.write_text(json.dumps(data), encoding="utf-8")
        os.replace(tmp, self._path)

    def _live(self, binding: tuple[int, Optional[float], str]) -> bool:
        pid, start, _actor = binding
        if not self._pid_alive(pid) or start is None:
            return False
        current = self._pid_start_time(pid)
        return current is not None and abs(current - start) < _PID_MATCH_TOLERANCE

    def bind(self, session_id: str, *, pid: Optional[int] = None) -> str:
        if not session_id:
            raise ValueError("session_id is required")
        rpid = pid if pid is not None else os.getpid()
        with self._locked():
            data = self._load()
            data[session_id] = (rpid, self._pid_start_time(rpid), session_id)
            self._save(data)
        return session_id

    def claim(self, session_id: str, *, pid: int) -> Optional[str]:
        if not session_id:
            return None
        with self._locked():
            data = self._load()
            binding = data.get(session_id)
            if binding is not None and self._live(binding):
                return session_id if binding[0] == pid else None
            start = self._pid_start_time(pid)
            if start is None:
                return None
            data[session_id] = (pid, start, session_id)
            self._save(data)
        return session_id

    def resolve(self, session_id: str) -> Optional[str]:
        binding = self._load().get(session_id)
        if binding is None or not self._live(binding):
            return None
        return binding[2]


__all__ = ["SessionIdentity", "IdentityStoreError", "session_owner_pid"]
