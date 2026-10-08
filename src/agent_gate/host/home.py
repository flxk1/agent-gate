from __future__ import annotations

import base64
import os
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, NoEncryption, PrivateFormat, PublicFormat,
)

from a2a_compliance.wire.admission import Issuer
from a2a_compliance.wire import signing

from ..identity import agent_keys
from ..records import chain_receipt
from .policy_load import load_policy

HOME_ENV = "AGENT_GATE_HOME"
_DEFAULT_HOME = Path.home() / ".agent-gate"
KEY_FILE = "host_ed25519.key"
KEYS_SUBDIR = "identity"
CHAIN_FILE = "chain.jsonl"
AGENT_ID = "agent-gate:host"
OBJECT_TYPES = ["ExecutionPermit", "ToolReceipt"]


class HostKeyRevoked(RuntimeError):
    pass


def home_root(root: Optional[str | Path] = None) -> Path:
    if root is not None:
        return Path(root)
    env = os.environ.get(HOME_ENV)
    return Path(env) if env else _DEFAULT_HOME


def keys_root(root: Optional[str | Path] = None) -> Path:
    return home_root(root) / KEYS_SUBDIR


def key_path(root: Optional[str | Path] = None) -> Path:
    return home_root(root) / KEY_FILE


def chain_path(root: Optional[str | Path] = None) -> Path:
    return home_root(root) / CHAIN_FILE


def _public_pem(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo,
    )


def _load_private_key(path: Path) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(path.read_bytes())


def init_home(root: Optional[str | Path] = None) -> dict:
    base = home_root(root)
    base.mkdir(parents=True, exist_ok=True)
    kp = key_path(root)
    kroot = keys_root(root)
    if kp.exists():
        priv = _load_private_key(kp)
    else:
        candidate = Ed25519PrivateKey.generate()
        tmp = kp.with_name(f".{KEY_FILE}.{os.getpid()}.{os.urandom(4).hex()}")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(candidate.private_bytes(
                encoding=Encoding.Raw, format=PrivateFormat.Raw,
                encryption_algorithm=NoEncryption(),
            ))
        try:
            os.link(tmp, kp)
            priv = candidate
        except FileExistsError:
            priv = _load_private_key(kp)
        finally:
            tmp.unlink()
    pub_pem = _public_pem(priv)
    key_id = agent_keys.key_id_for(pub_pem)
    existing = next((r for r in agent_keys.list_agent_keys(include_dead=True, root=str(kroot))
                     if r.get("keyid") == key_id), None)
    if existing is not None and existing.get("revoked"):
        raise HostKeyRevoked(f"host key {key_id} is revoked")
    if existing is None:
        agent_keys.register_agent_key(
            AGENT_ID, pub_pem, object_types=OBJECT_TYPES, root=str(kroot),
        )
    return {
        "root": str(base), "key_id": key_id, "keys_root": str(kroot),
        "chain_path": str(chain_path(root)),
    }


def host_issuer(root: Optional[str | Path] = None) -> Issuer:
    kp = key_path(root)
    if not kp.exists():
        raise RuntimeError(f"agent-gate home not initialized at {kp}")
    priv = _load_private_key(kp)
    key_id = agent_keys.key_id_for(_public_pem(priv))
    kroot = str(keys_root(root))

    def _sign(subject: dict) -> str:
        if agent_keys.get_agent_key(key_id, root=kroot) is None:
            raise HostKeyRevoked(f"host key {key_id} is revoked or unregistered")
        return base64.b64encode(priv.sign(signing.pae_bytes(subject))).decode("ascii")

    return Issuer(key_id=key_id, identity=AGENT_ID, sign=_sign)


def home_status(root: Optional[str | Path] = None) -> dict:
    base = home_root(root)
    kp = key_path(root)
    kroot = keys_root(root)
    cpath = chain_path(root)
    initialized = kp.exists()
    key_id = None
    key_live = False
    if initialized:
        try:
            pub_pem = _public_pem(_load_private_key(kp))
            key_id = agent_keys.key_id_for(pub_pem)
            key_live = agent_keys.get_agent_key(key_id, root=str(kroot)) is not None
        except Exception:
            key_id = None
    policy_result = load_policy()
    chain_verified = False
    if cpath.exists():
        try:
            from ..ops.backup import JsonlChain

            trust_store = agent_keys.AgentKeyTrustStore(root=str(kroot))
            chain_verified = chain_receipt.verify(
                JsonlChain(cpath), trust_store=trust_store,
            ).ok
        except Exception:
            chain_verified = False
    mode = os.environ.get("AGENT_GATE_HOOK_MODE", "monitor").strip().lower() or "monitor"
    return {
        "root": str(base), "initialized": initialized, "key_id": key_id, "key_live": key_live,
        "keys_root": str(kroot), "chain_path": str(cpath),
        "policy_path": policy_result.path, "policy_loaded": policy_result.loaded,
        "chain_verified": chain_verified, "mode": mode,
    }


__all__ = [
    "HostKeyRevoked", "HOME_ENV", "home_root", "keys_root", "key_path", "chain_path",
    "init_home", "host_issuer", "home_status",
]
