from __future__ import annotations

import fcntl
import json
import time
from pathlib import Path
from typing import Any, Optional

from loomground_lock.seal import SealError, decrypt_record, encrypt_record

from ..identity import agent_keys
from ..ports import RecordSink

_MAGIC = "agent-gate-backup"
_VERSION = 1
_AAD_FOLDER = "/agent-gate/backup"


class BackupError(RuntimeError):
    pass


class _AppendLock:
    def __init__(self, path: Path) -> None:
        self._path = path
        self._fh = None

    def __enter__(self) -> "_AppendLock":
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = open(self._path, "a+")
        fcntl.flock(self._fh.fileno(), fcntl.LOCK_EX)
        return self

    def __exit__(self, *exc: Any) -> None:
        fcntl.flock(self._fh.fileno(), fcntl.LOCK_UN)
        self._fh.close()
        self._fh = None


class JsonlChain:
    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)

    def _lock_path(self) -> Path:
        return self._path.with_name(self._path.name + ".lock")

    def lock_for_append(self) -> _AppendLock:
        return _AppendLock(self._lock_path())

    def append(self, record: dict) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")

    def tail(self) -> Optional[dict]:
        records = self.all()
        return records[-1] if records else None

    def all(self) -> list[dict]:
        if not self._path.exists():
            return []
        out: list[dict] = []
        with open(self._path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    out.append(json.loads(line))
        return out


def create_backup(
    out_path: str | Path, *,
    passphrase: str,
    chain: RecordSink,
    keys_root: Optional[str] = None,
    backup_id: Optional[str] = None,
) -> dict[str, Any]:
    if not passphrase:
        raise BackupError("a passphrase is required to create a backup")
    backup_id = backup_id or f"backup-{int(time.time())}"
    manifest = {
        "magic": _MAGIC,
        "version": _VERSION,
        "backup_id": backup_id,
        "created": time.time(),
        "keys": agent_keys.list_agent_keys(include_dead=True, root=keys_root),
        "chain": chain.all(),
    }
    plaintext = json.dumps(manifest).encode("utf-8")
    blob = encrypt_record(plaintext, passphrase=passphrase, folder=_AAD_FOLDER)
    path = Path(out_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(blob)
    return {"backup_id": backup_id, "path": str(path),
            "keys": len(manifest["keys"]), "chain": len(manifest["chain"])}


def read_manifest(path: str | Path, *, passphrase: str) -> dict[str, Any]:
    if not passphrase:
        raise BackupError("a passphrase is required to read a backup")
    blob = Path(path).read_bytes()
    try:
        plaintext = decrypt_record(blob, passphrase=passphrase, folder=_AAD_FOLDER)
    except SealError as exc:
        raise BackupError(str(exc)) from exc
    try:
        manifest = json.loads(plaintext.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BackupError(f"backup payload is not valid JSON: {exc}") from exc
    if manifest.get("magic") != _MAGIC:
        raise BackupError("not an agent-gate backup")
    return manifest


def restore_backup(
    path: str | Path, *,
    passphrase: str,
    chain: RecordSink,
    keys_root: Optional[str] = None,
) -> dict[str, Any]:
    if chain.all():
        raise BackupError("refusing to restore onto a non-empty chain")
    manifest = read_manifest(path, passphrase=passphrase)
    keys = manifest.get("keys") or []
    chain_entries = manifest.get("chain") or []
    keys_dir = agent_keys._keys_dir(keys_root)
    keys_dir.mkdir(parents=True, exist_ok=True)
    for rec in keys:
        keyid = agent_keys._safe_keyid(str(rec.get("keyid") or ""))
        if not keyid:
            continue
        target = keys_dir / f"{keyid}.json"
        if target.exists():
            continue
        target.write_text(json.dumps(rec), encoding="utf-8")
    for entry in chain_entries:
        chain.append(entry)
    return {"backup_id": manifest.get("backup_id"), "keys": len(keys), "chain": len(chain_entries)}


__all__ = ["JsonlChain", "BackupError", "create_backup", "read_manifest", "restore_backup"]
