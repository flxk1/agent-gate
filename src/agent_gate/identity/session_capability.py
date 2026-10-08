from __future__ import annotations

import base64
import json
import os
import secrets
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Optional

PREFIX = "AGSC1"
MAX_TTL_SECONDS = 900
CLOCK_SKEW_SECONDS = 30


class CapabilityError(ValueError):
    ...


@dataclass(frozen=True)
class SessionClaims:
    party: str
    lane_id: str
    folder: str
    grade: str
    policy_fingerprint: str
    spec_fingerprint: str
    uid: int
    nonce: str
    iat: int
    exp: int
    kid: str


def _canonical(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode(value: str) -> bytes:
    padded = value + "=" * (-len(value) % 4)
    return base64.b64decode(padded.replace("-", "+").replace("_", "/"), validate=True)


def _identity_dir(root: Optional[str] = None) -> Path:
    if root:
        return Path(root)
    env = os.environ.get("AGENT_GATE_IDENTITY_DIR")
    return Path(env) if env else Path.home() / ".agent-gate" / "identity"


def generate_keypair() -> tuple[bytes, bytes]:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key = Ed25519PrivateKey.generate()
    private = key.private_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption())
    public = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    return private, public


def ensure_keypair(root: Optional[str] = None) -> tuple[bytes, bytes]:
    d = _identity_dir(root)
    priv_path, pub_path = d / "capability.priv", d / "capability.pub"
    if priv_path.exists() and pub_path.exists():
        return priv_path.read_bytes(), pub_path.read_bytes()
    private, public = generate_keypair()
    d.mkdir(parents=True, exist_ok=True)
    priv_path.write_bytes(private)
    pub_path.write_bytes(public)
    try:
        os.chmod(priv_path, 0o600)
    except Exception:
        pass
    return private, public


def fingerprint_of(public_key: bytes) -> str:
    import hashlib
    return base64.urlsafe_b64encode(hashlib.sha256(public_key).digest()).rstrip(b"=").decode("ascii")


def sign_bytes(payload: bytes, private_key: bytes) -> str:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key = Ed25519PrivateKey.from_private_bytes(private_key)
    return base64.b64encode(key.sign(payload)).decode("ascii")


def verify_signature(payload: bytes, signature_b64: str, public_key: bytes) -> bool:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        sig = base64.b64decode(signature_b64)
        Ed25519PublicKey.from_public_bytes(public_key).verify(sig, payload)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def mint(
    *, party: str, lane_id: str, folder: str, grade: str,
    policy_fingerprint: str, spec_fingerprint: str, uid: int,
    ttl_seconds: int = MAX_TTL_SECONDS,
    private_key: Optional[bytes] = None, public_key: Optional[bytes] = None,
    root: Optional[str] = None,
) -> tuple[str, SessionClaims]:
    if not 1 <= ttl_seconds <= MAX_TTL_SECONDS:
        raise CapabilityError("ttl outside allowed range")
    if private_key is None or public_key is None:
        private_key, public_key = ensure_keypair(root)
    now = int(time.time())
    claims = SessionClaims(
        party=party, lane_id=lane_id, folder=folder, grade=grade,
        policy_fingerprint=policy_fingerprint, spec_fingerprint=spec_fingerprint,
        uid=uid, nonce=secrets.token_hex(16), iat=now, exp=now + ttl_seconds,
        kid=fingerprint_of(public_key),
    )
    payload = _canonical(asdict(claims))
    token = f"{PREFIX}.{_encode(payload)}.{sign_bytes(payload, private_key)}"
    return token, claims


class CapabilityVerifier:

    def __init__(self, trust_root: bytes, *, revoked_nonces=None):
        self._root = trust_root
        self._kid = fingerprint_of(trust_root)
        self._revoked = revoked_nonces if revoked_nonces is not None else set()

    @classmethod
    def from_key_dir(cls, *, root: Optional[str] = None, **kwargs) -> "CapabilityVerifier":
        _, public = ensure_keypair(root)
        if "revoked_nonces" not in kwargs:
            kwargs["revoked_nonces"] = FileRevocationStore.default(root=root)
        return cls(public, **kwargs)

    def revoke(self, nonce: str) -> None:
        if hasattr(self._revoked, "revoke"):
            self._revoked.revoke("session_nonce", nonce)
        else:
            self._revoked.add(nonce)

    def verify(self, token: str, *, expected_folder: Optional[str] = None,
              expected_uid: Optional[int] = None, now: Optional[int] = None) -> SessionClaims:
        parts = token.split(".")
        if len(parts) != 3 or parts[0] != PREFIX:
            raise CapabilityError("malformed capability")
        try:
            payload = _decode(parts[1])
        except Exception as exc:
            raise CapabilityError("invalid capability encoding") from exc
        if not verify_signature(payload, parts[2], self._root):
            raise CapabilityError("invalid capability signature")
        try:
            claims = SessionClaims(**json.loads(payload))
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise CapabilityError("invalid capability claims") from exc
        current = int(time.time()) if now is None else int(now)
        if claims.kid != self._kid:
            raise CapabilityError("capability trust root mismatch")
        if claims.iat > current + CLOCK_SKEW_SECONDS:
            raise CapabilityError("capability issued in the future")
        if current > claims.exp + CLOCK_SKEW_SECONDS:
            raise CapabilityError("capability expired")
        if claims.exp - claims.iat > MAX_TTL_SECONDS:
            raise CapabilityError("capability ttl exceeds ceiling")
        if claims.nonce in self._revoked:
            raise CapabilityError("capability revoked")
        if expected_folder is not None and claims.folder != expected_folder:
            raise CapabilityError("capability folder mismatch")
        if expected_uid is not None and claims.uid != expected_uid:
            raise CapabilityError("capability uid mismatch")
        return claims


class FileRevocationStore:

    def __init__(self, path: str | os.PathLike[str]):
        self.path = Path(path)
        self._entries: list[tuple[str, str, float]] = []
        self._consumed: set[tuple[str, str]] = set()
        self._seen: set[tuple[str, str]] = set()
        self._lock = Lock()
        self._reload()

    @classmethod
    def default(cls, *, root: Optional[str] = None) -> "FileRevocationStore":
        configured = os.environ.get("AGENT_GATE_REVOCATIONS", "").strip()
        if configured:
            return cls(configured)
        return cls(_identity_dir(root) / "revocations")

    def _reload(self) -> None:
        if not self.path.exists():
            return
        self._entries = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split("\t")
            if len(parts) != 3:
                continue
            kind, ident, eff = parts
            try:
                self._entries.append((kind, ident, float(eff)))
            except ValueError:
                continue

    def revoke(self, revoked_type: str, revoked_id: str, effective_at: Optional[float] = None) -> None:
        eff = time.time() if effective_at is None else (
            effective_at.timestamp() if isinstance(effective_at, datetime) else float(effective_at))
        with self._lock:
            self._reload()
            if any(k == revoked_type and i == revoked_id for k, i, _ in self._entries):
                return
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.path, "a", encoding="utf-8") as stream:
                stream.write(f"{revoked_type}\t{revoked_id}\t{eff}\n")
                stream.flush()
                os.fsync(stream.fileno())
            self._entries.append((revoked_type, revoked_id, eff))

    def is_revoked(self, revoked_type: str, revoked_id: str, *, at: datetime) -> bool:
        self._reload()
        at_ts = at.timestamp() if isinstance(at, datetime) else float(at)
        return any(k == revoked_type and i == revoked_id and eff <= at_ts for k, i, eff in self._entries)

    def add(self, nonce: str) -> None:
        self.revoke("session_nonce", nonce)

    def __contains__(self, nonce: object) -> bool:
        return self.is_revoked("session_nonce", str(nonce), at=datetime.now(timezone.utc))

    def seen(self, run_id: str, nonce: str) -> bool:
        return (run_id, nonce) in self._seen

    def record(self, run_id: str, nonce: str) -> None:
        self._seen.add((run_id, nonce))

    def consume(self, run_id: str, nonce: str) -> bool:
        key = (run_id, nonce)
        with self._lock:
            if key in self._consumed:
                return False
            self._consumed.add(key)
            return True
