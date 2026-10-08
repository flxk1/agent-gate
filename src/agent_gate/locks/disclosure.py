from __future__ import annotations

import base64
import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from ..identity.session_capability import ensure_keypair, fingerprint_of, sign_bytes, verify_signature

__all__ = ["DisclosureEnvelope", "make_envelope", "verify_envelope",
           "MARKING_PROFILE", "MARKING_PROFILE_PROVISIONAL"]

MARKING_PROFILE_PROVISIONAL = "agent-gate-ai-origin-provisional-1"
MARKING_PROFILE = MARKING_PROFILE_PROVISIONAL
ENVELOPE_VERSION = 1


def _content_hash(content: str) -> str:
    return "sha256:" + hashlib.sha256(content.encode("utf-8")).hexdigest()


def _marker(profile: str) -> dict[str, Any]:
    return {"profile": profile, "ai_generated": True,
            "statement": "This content was produced by an AI system."}


@dataclass
class DisclosureEnvelope:

    content_hash: str
    originating_system: str
    affected_parties: list[str]
    action_class: str
    marking: dict[str, Any]
    created_at: str
    envelope_version: int = ENVELOPE_VERSION
    signature: str = ""
    public_key_b64: str = ""
    meta: dict[str, Any] = field(default_factory=dict)

    def signing_payload(self) -> bytes:
        body = {"content_hash": self.content_hash,
                "originating_system": self.originating_system,
                "affected_parties": sorted(self.affected_parties),
                "action_class": self.action_class,
                "marking": self.marking,
                "created_at": self.created_at,
                "envelope_version": self.envelope_version,
                "meta": self.meta}
        return json.dumps(body, sort_keys=True, ensure_ascii=False).encode("utf-8")

    def to_dict(self) -> dict[str, Any]:
        return {"content_hash": self.content_hash,
                "originating_system": self.originating_system,
                "affected_parties": sorted(self.affected_parties),
                "action_class": self.action_class,
                "marking": self.marking,
                "created_at": self.created_at,
                "envelope_version": self.envelope_version,
                "signature": self.signature,
                "public_key_b64": self.public_key_b64,
                "meta": self.meta}


def make_envelope(content: str, *, affected_parties: list[str],
                  action_class: str = "", marking_profile: str = MARKING_PROFILE,
                  meta: Optional[dict[str, Any]] = None,
                  root: Optional[str] = None) -> DisclosureEnvelope:
    parties = [p for p in (affected_parties or []) if str(p).strip()]
    if not parties:
        raise ValueError(
            "a disclosure envelope must name at least one affected party -- "
            "an output bound for a third party with no named recipient cannot "
            "be disclosed")
    private, public = ensure_keypair(root)
    env = DisclosureEnvelope(
        content_hash=_content_hash(content),
        originating_system=fingerprint_of(public),
        affected_parties=parties,
        action_class=action_class,
        marking=_marker(marking_profile),
        created_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        meta=meta or {})
    env.signature = sign_bytes(env.signing_payload(), private)
    env.public_key_b64 = base64.b64encode(public).decode("ascii")
    return env


def verify_envelope(envelope: dict[str, Any] | DisclosureEnvelope,
                    content: Optional[str] = None) -> dict[str, Any]:
    d = envelope.to_dict() if isinstance(envelope, DisclosureEnvelope) else dict(envelope)
    reasons: list[str] = []
    env = DisclosureEnvelope(
        content_hash=d.get("content_hash", ""),
        originating_system=d.get("originating_system", ""),
        affected_parties=d.get("affected_parties", []) or [],
        action_class=d.get("action_class", ""),
        marking=d.get("marking", {}) or {},
        created_at=d.get("created_at", ""),
        envelope_version=int(d.get("envelope_version", ENVELOPE_VERSION)),
        meta=d.get("meta", {}) or {})
    sig = d.get("signature", "")
    b64 = d.get("public_key_b64", "")
    signature_ok = False
    if not sig:
        reasons.append("no signature present")
    else:
        try:
            public = base64.b64decode(b64) if b64 else b""
            signature_ok = bool(public) and verify_signature(env.signing_payload(), sig, public)
            if not signature_ok:
                reasons.append("signature does not verify against payload")
        except Exception as exc:  # noqa: BLE001
            reasons.append(f"signature verification error: {exc}")
    content_ok: Optional[bool] = None
    if content is not None:
        content_ok = (_content_hash(content) == env.content_hash)
        if not content_ok:
            reasons.append("content hash does not match envelope")
    profile = (env.marking or {}).get("profile", "")
    stale = bool(profile) and profile != MARKING_PROFILE
    if stale:
        reasons.append(f"marking profile {profile!r} is not the current "
                       f"{MARKING_PROFILE!r} (re-mark when the governing marking "
                       "standard is finalised)")
    return {"signature_ok": signature_ok, "content_ok": content_ok,
            "profile": profile, "stale_profile": stale, "reasons": reasons}
