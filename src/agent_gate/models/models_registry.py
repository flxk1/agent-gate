from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import local_llm

_log = logging.getLogger(__name__)
_LEGACY_KEYS_WARNED: set[str] = set()

ROLE_SLOT_N1 = "order_n1"
ROLE_SLOT_N2 = "order_n2"
LEGACY_ROLE_SLOT_N1 = "primary"
LEGACY_ROLE_SLOT_N2 = "backup"

MODELS_DIR_ENV = "AGENT_GATE_MODELS_DIR"
REGISTRY_FILENAME = "registry.json"
DEFAULT_ROLE = "default"

VALID_ROLES = (DEFAULT_ROLE, "validator", "lock-tier-C", "lock-c", "drafter", "code-fix")


def models_dir() -> Path:
    override = os.environ.get(MODELS_DIR_ENV)
    return Path(override) if override else Path.home() / ".agent-gate" / "models"


def registry_path() -> Path:
    return models_dir() / REGISTRY_FILENAME


class ModelRegistryError(RuntimeError):
    pass


class ModelNotFoundError(ModelRegistryError):
    pass


class InvalidRoleError(ModelRegistryError):
    pass


@dataclass
class ModelEntry:
    id: str
    artifact_path: str = ""
    sha256_verified: str = ""
    registered_at: str = ""
    registered_via: str = "register"
    roles: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"artifact_path": self.artifact_path,
                "sha256_verified": self.sha256_verified,
                "registered_at": self.registered_at,
                "registered_via": self.registered_via,
                "roles": list(self.roles)}


def _entry(mid: str, m: dict[str, Any]) -> ModelEntry:
    return ModelEntry(id=mid, artifact_path=m.get("artifact_path", ""),
                      sha256_verified=m.get("sha256_verified", ""),
                      registered_at=m.get("registered_at", ""),
                      registered_via=m.get("registered_via", "register"),
                      roles=list(m.get("roles", [])))


def _migrate_legacy_role_slot_keys(role_map: dict[str, Any], source_label: str) -> bool:
    if not isinstance(role_map, dict):
        return False
    migrated = False
    for slot in role_map.values():
        if not isinstance(slot, dict):
            continue
        for legacy, new in ((LEGACY_ROLE_SLOT_N1, ROLE_SLOT_N1), (LEGACY_ROLE_SLOT_N2, ROLE_SLOT_N2)):
            if legacy in slot:
                value = slot.pop(legacy)
                slot.setdefault(new, value)
                migrated = True
    if migrated and source_label not in _LEGACY_KEYS_WARNED:
        _LEGACY_KEYS_WARNED.add(source_label)
        _log.warning("models_registry: legacy role-slot keys 'primary'/'backup' at %s "
                     "read as 'order_n1'/'order_n2'", source_label)
    return migrated


def load_registry() -> dict[str, Any]:
    path = registry_path()
    if not path.exists():
        return {"schema_version": 1, "models": {}, "role_map": {}}
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as e:
        raise ModelRegistryError(f"unable to read registry at {path}: {e}") from e
    data.setdefault("schema_version", 1)
    data.setdefault("models", {})
    data.setdefault("role_map", {})
    _migrate_legacy_role_slot_keys(data["role_map"], str(path))
    return data


def save_registry(data: dict[str, Any]) -> None:
    path = registry_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)
        fh.write("\n")
    tmp.replace(path)


def list_models() -> list[ModelEntry]:
    return [_entry(mid, m) for mid, m in sorted(load_registry()["models"].items())]


def get_model(model_id: str) -> ModelEntry:
    m = load_registry()["models"].get(model_id)
    if m is None:
        raise ModelNotFoundError(model_id)
    return _entry(model_id, m)


def models_for_role(role: str) -> list[str]:
    try:
        data = load_registry()
    except ModelRegistryError:
        return []
    slot = data.get("role_map", {}).get(role, {})
    out: list[str] = []
    if isinstance(slot, dict):
        for key in (ROLE_SLOT_N1, ROLE_SLOT_N2):
            mid = slot.get(key)
            if mid and mid not in out:
                out.append(mid)
    for mid, m in sorted(data.get("models", {}).items()):
        if role in m.get("roles", []) and mid not in out:
            out.append(mid)
    return out


def register_model(model_id: str, role: str, *, artifact_path: str = "",
                   sha256: str = "", via: str = "register") -> ModelEntry:
    role_canon = _canonicalise_role(role)
    data = load_registry()
    models = data["models"]
    if model_id not in models:
        models[model_id] = {"artifact_path": artifact_path, "sha256_verified": sha256,
                            "registered_at": _iso_now(), "registered_via": via,
                            "roles": [role_canon]}
    else:
        existing = models[model_id]
        if role_canon not in existing.get("roles", []):
            existing.setdefault("roles", []).append(role_canon)
        if artifact_path:
            existing["artifact_path"] = artifact_path
        if sha256:
            existing["sha256_verified"] = sha256
        existing["registered_at"] = _iso_now()
        existing["registered_via"] = via
    slot = data["role_map"].setdefault(role_canon, {})
    slot.setdefault(ROLE_SLOT_N1, "")
    slot.setdefault(ROLE_SLOT_N2, "")
    if not slot[ROLE_SLOT_N1]:
        slot[ROLE_SLOT_N1] = model_id
    elif slot[ROLE_SLOT_N1] != model_id and not slot[ROLE_SLOT_N2]:
        slot[ROLE_SLOT_N2] = model_id
    save_registry(data)
    return _entry(model_id, models[model_id])


def _probe_endpoint(model_id: str) -> dict[str, Any]:
    base = os.environ.get(local_llm.URL_ENV)
    if not base:
        return {"endpoint_reachable": None, "endpoint_url": "",
                "error": "no endpoint configured"}
    probe = local_llm.list_available()
    if not probe.get("reachable"):
        return {"endpoint_reachable": False, "endpoint_url": base,
                "error": probe.get("error", "unreachable")}
    if model_id in probe.get("models", []):
        return {"endpoint_reachable": True, "endpoint_url": base, "error": ""}
    return {"endpoint_reachable": False, "endpoint_url": base,
            "error": f"endpoint reachable but did not list {model_id!r}"}


def health_check(entry: ModelEntry) -> dict[str, Any]:
    base: dict[str, Any] = {"id": entry.id, "role": entry.roles[0] if entry.roles else ""}
    p = Path(entry.artifact_path).expanduser() if entry.artifact_path else None
    if p is None:
        base.update(status="missing", detail="no artifact_path recorded", size_bytes=0, exists=False)
    elif not p.exists():
        base.update(status="missing", detail=f"file not found at {p}", size_bytes=0, exists=False)
    else:
        size = p.stat().st_size
        base.update(status="ok" if size else "empty",
                    detail="artifact present" if size else "file exists but is zero bytes",
                    size_bytes=size, exists=True)
    base["artifact_exists"] = base["exists"]
    probe = _probe_endpoint(entry.id)
    base["endpoint_reachable"] = probe["endpoint_reachable"]
    base["endpoint_url"] = probe["endpoint_url"]
    base["endpoint_error"] = probe["error"]
    return base


def pull_model(model_id: str, *, package_root: Path, timeout: float = 600) -> dict[str, Any]:
    import subprocess

    script = Path(package_root) / "scripts" / "pull_models.sh"
    if not script.exists():
        return {"ok": False, "exit_code": -1, "stdout": "",
                "stderr": f"pull script not found at {script}"}
    try:
        result = subprocess.run(["bash", str(script), "--only", model_id],
                                capture_output=True, text=True, check=False, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as e:
        return {"ok": False, "exit_code": -1, "stdout": "", "stderr": f"subprocess error: {e}"}
    return {"ok": result.returncode == 0, "exit_code": result.returncode,
            "stdout": result.stdout, "stderr": result.stderr}


def _canonicalise_role(role: str) -> str:
    r = role.strip()
    if r.lower() == "lock-tier-c":
        return "lock-tier-C"
    if r not in VALID_ROLES:
        raise InvalidRoleError(f"role must be one of {VALID_ROLES!r}; got {role!r}")
    return r


def _iso_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
