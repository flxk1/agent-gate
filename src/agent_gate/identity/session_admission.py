from __future__ import annotations

import hashlib
from typing import Optional

from .session_capability import CapabilityError, CapabilityVerifier, SessionClaims

SESSION_SPEC = b"agent-gate/session-admission/v1"


def runtime_spec_fingerprint() -> str:
    return "sha256:" + hashlib.sha256(SESSION_SPEC).hexdigest()


def reverify(
    token: str, *, verifier: CapabilityVerifier, expected_party: str,
    expected_folder: Optional[str] = None, expected_uid: Optional[int] = None,
    now: Optional[int] = None,
) -> SessionClaims:
    if not token:
        raise CapabilityError("session capability required")
    claims = verifier.verify(
        token, expected_folder=expected_folder, expected_uid=expected_uid, now=now)
    if claims.party != expected_party:
        raise CapabilityError("capability party mismatch")
    if claims.spec_fingerprint != runtime_spec_fingerprint():
        raise CapabilityError("capability runtime spec mismatch")
    return claims
