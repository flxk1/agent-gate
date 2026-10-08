from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from a2a_compliance.wire.signing import verify_signature
from a2a_compliance.wire.trust import TrustStore
from loomground_lane import GovernanceLane

_REQUIRED_FIELDS = ("pack_id", "lane_id", "agent", "version", "rules", "key_id", "signature")


class PolicyPackError(ValueError):
    pass


@dataclass(frozen=True)
class PolicyPack:
    pack_id: str
    lane_id: str
    agent: str
    version: int
    rules: dict[str, Any]
    key_id: str


def _malformations(raw: Any) -> list[str]:
    if not isinstance(raw, dict):
        return ["pack is not a JSON object"]
    errors = [f"missing field: {f}" for f in _REQUIRED_FIELDS if f not in raw]
    if "rules" in raw and not isinstance(raw["rules"], dict):
        errors.append("rules must be an object")
    if "version" in raw and not isinstance(raw["version"], int):
        errors.append("version must be an int")
    for f in ("pack_id", "lane_id", "agent", "key_id", "signature"):
        if f in raw and (not isinstance(raw[f], str) or not raw[f].strip()):
            errors.append(f"{f} must be a non-empty string")
    return errors


def published_policy_pack(
    raw: dict[str, Any],
    *,
    trust_store: TrustStore,
    lane: Optional[GovernanceLane],
) -> PolicyPack:
    errors = _malformations(raw)
    if errors:
        raise PolicyPackError("malformed policy pack: " + "; ".join(errors))

    key_id = raw["key_id"]
    binding = trust_store.resolve(key_id)
    if binding is None:
        raise PolicyPackError(f"unknown key_id: {key_id!r} is not resolvable by the trust store")
    if not binding.authorizes_type("PolicyPack"):
        raise PolicyPackError(f"key not bound to object type PolicyPack: {key_id!r}")

    sig_errors = verify_signature(raw, binding.public_key)
    if sig_errors:
        raise PolicyPackError("signature verification failed: " + "; ".join(sig_errors))

    if lane is None:
        raise PolicyPackError(
            "no governance lane bound -- a policy pack is never imported without one")
    if lane.lane_id != raw["lane_id"] or lane.agent != raw["agent"]:
        raise PolicyPackError(
            f"lane mismatch: pack declares lane {raw['lane_id']!r}/{raw['agent']!r}, "
            f"bound lane is {lane.lane_id!r}/{lane.agent!r}")

    return PolicyPack(
        pack_id=raw["pack_id"], lane_id=raw["lane_id"], agent=raw["agent"],
        version=raw["version"], rules=dict(raw["rules"]), key_id=key_id,
    )


__all__ = ["PolicyPack", "PolicyPackError", "published_policy_pack"]
