from __future__ import annotations

import fcntl
import hashlib
import json
import os
from datetime import datetime
from pathlib import Path


def _digest(*parts: str) -> str:
    return hashlib.sha256("\x00".join(parts).encode("utf-8")).hexdigest()


class FileNonceStore:
    def __init__(self, root: str | Path) -> None:
        self._root = Path(root) / "nonces"

    def _seen_path(self, run_id: str, nonce: str) -> Path:
        return self._root / "seen" / f"{_digest(run_id, nonce)}.marker"

    def _consumed_path(self, run_id: str, nonce: str) -> Path:
        return self._root / "consumed" / f"{_digest(run_id, nonce)}.marker"

    def seen(self, run_id: str, nonce: str) -> bool:
        return self._seen_path(run_id, nonce).exists()

    def record(self, run_id: str, nonce: str) -> None:
        p = self._seen_path(run_id, nonce)
        p.parent.mkdir(parents=True, exist_ok=True)
        try:
            fd = os.open(p, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.close(fd)
        except FileExistsError:
            pass

    def consume(self, run_id: str, nonce: str) -> bool:
        p = self._consumed_path(run_id, nonce)
        p.parent.mkdir(parents=True, exist_ok=True)
        try:
            fd = os.open(p, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.close(fd)
            return True
        except FileExistsError:
            return False


def _parse_iso(value: str) -> datetime:
    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    return datetime.fromisoformat(text)


class FileRevocationStore:
    def __init__(self, root: str | Path) -> None:
        self._path = Path(root) / "revocations.jsonl"
        self._lock_path = Path(root) / "revocations.jsonl.lock"

    def revoke(self, revoked_type: str, revoked_id: str, effective_at: datetime) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        rec = {
            "revoked_type": revoked_type, "revoked_id": revoked_id,
            "effective_at": effective_at.isoformat(),
        }
        with open(self._lock_path, "a+") as lockf:
            fcntl.flock(lockf.fileno(), fcntl.LOCK_EX)
            try:
                with open(self._path, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(rec) + "\n")
            finally:
                fcntl.flock(lockf.fileno(), fcntl.LOCK_UN)

    def record(self, revocation_obj: dict) -> None:
        effective_at = revocation_obj["effective_at"]
        if isinstance(effective_at, str):
            effective_at = _parse_iso(effective_at)
        self.revoke(revocation_obj["revoked_type"], revocation_obj["revoked_id"], effective_at)

    def _entries(self) -> list[dict]:
        if not self._path.exists():
            return []
        out = []
        with open(self._path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    out.append(json.loads(line))
        return out

    def is_revoked(self, revoked_type: str, revoked_id: str, *, at: datetime) -> bool:
        for rec in self._entries():
            if rec.get("revoked_type") != revoked_type or rec.get("revoked_id") != revoked_id:
                continue
            eff = rec.get("effective_at")
            if isinstance(eff, str):
                eff = _parse_iso(eff)
            if eff <= at:
                return True
        return False


__all__ = ["FileNonceStore", "FileRevocationStore"]
