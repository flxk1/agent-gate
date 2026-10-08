from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import time
from pathlib import Path
from typing import Optional

from a2a_compliance.wire.trust import ANY, TrustBinding

_KEYID_RE = re.compile(r"[A-Za-z0-9_-]{1,128}")


def _keys_dir(root: Optional[str] = None) -> Path:
    if root:
        base = Path(root)
    else:
        env = os.environ.get("AGENT_GATE_IDENTITY_DIR")
        base = Path(env) if env else Path.home() / ".agent-gate" / "identity"
    return base / "keys"


def _safe_keyid(keyid: str) -> str:
    keyid = (keyid or "").strip()
    return keyid if _KEYID_RE.fullmatch(keyid) else ""


def _load_ed25519_public(pem):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    data = pem.encode("utf-8") if isinstance(pem, str) else pem
    try:
        key = load_pem_public_key(data)
    except Exception as exc:
        raise ValueError(f"not a valid PEM public key: {exc}") from None
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("agent identity keys must be Ed25519")
    return key


def key_id_for(pem) -> str:
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    key = _load_ed25519_public(pem)
    raw = key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).rstrip(b"=").decode("ascii")


def _is_live(rec: dict, now: float) -> bool:
    if rec.get("revoked"):
        return False
    exp = rec.get("expires")
    return not (exp is not None and now > float(exp))


def register_agent_key(agent: str, public_key_pem, *,
                       expires: Optional[float] = None,
                       object_types: Optional[list[str]] = None,
                       roles: Optional[list[str]] = None,
                       now: Optional[float] = None,
                       root: Optional[str] = None) -> dict:
    agent = (agent or "").strip()
    if not agent:
        raise ValueError("agent id is required")
    _load_ed25519_public(public_key_pem)
    keyid = key_id_for(public_key_pem)
    pem_str = (public_key_pem if isinstance(public_key_pem, str)
               else public_key_pem.decode("utf-8"))
    rec = {
        "agent": agent,
        "keyid": keyid,
        "alg": "ed25519",
        "public_key_pem": pem_str,
        "created": float(now if now is not None else time.time()),
        "expires": (float(expires) if expires is not None else None),
        "revoked": False,
        "object_types": list(object_types or []),
        "roles": list(roles or []),
    }
    d = _keys_dir(root)
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{keyid}.json").write_text(json.dumps(rec), encoding="utf-8")
    return rec


def get_agent_key(keyid: str, *, now: Optional[float] = None,
                  root: Optional[str] = None) -> Optional[dict]:
    kid = _safe_keyid(keyid)
    if not kid:
        return None
    now = float(now if now is not None else time.time())
    try:
        f = _keys_dir(root) / f"{kid}.json"
        if not f.exists():
            return None
        rec = json.loads(f.read_text(encoding="utf-8"))
    except Exception:
        return None
    return rec if _is_live(rec, now) else None


def list_agent_keys(*, agent: Optional[str] = None, include_dead: bool = False,
                    now: Optional[float] = None,
                    root: Optional[str] = None) -> list[dict]:
    now = float(now if now is not None else time.time())
    out: list[dict] = []
    try:
        d = _keys_dir(root)
        if not d.exists():
            return []
        for f in d.glob("*.json"):
            try:
                rec = json.loads(f.read_text(encoding="utf-8"))
            except Exception:
                continue
            if agent is not None and rec.get("agent") != agent:
                continue
            if not include_dead and not _is_live(rec, now):
                continue
            out.append(rec)
    except Exception:
        return out
    out.sort(key=lambda r: r.get("created", 0), reverse=True)
    return out


def revoke_agent_key(keyid: str, *, root: Optional[str] = None) -> bool:
    kid = _safe_keyid(keyid)
    if not kid:
        return False
    try:
        f = _keys_dir(root) / f"{kid}.json"
        if not f.exists():
            return False
        rec = json.loads(f.read_text(encoding="utf-8"))
        rec["revoked"] = True
        f.write_text(json.dumps(rec), encoding="utf-8")
        return True
    except Exception:
        return False


class AgentKeyTrustStore:

    def __init__(self, *, root: Optional[str] = None) -> None:
        self._root = root

    def resolve(self, key_id: str) -> Optional[TrustBinding]:
        now = time.time()
        rec = get_agent_key(key_id, now=now, root=self._root)
        if rec is None:
            return None
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        public = _load_ed25519_public(rec["public_key_pem"])
        raw = public.public_bytes(Encoding.Raw, PublicFormat.Raw)
        return TrustBinding(
            public_key=raw,
            object_types=frozenset(rec.get("object_types") or ()),
            roles=frozenset(rec.get("roles") or ()),
        )


__all__ = [
    "register_agent_key", "get_agent_key", "list_agent_keys",
    "revoke_agent_key", "key_id_for", "AgentKeyTrustStore", "ANY",
]
