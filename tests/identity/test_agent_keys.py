import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from a2a_compliance.wire import canonical
from a2a_compliance.wire.signing import pae_bytes
from agent_gate.identity import agent_keys as ak


def _pem():
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return key, pub


def test_register_and_get_live_key(tmp_path):
    root = str(tmp_path)
    _, pem = _pem()
    rec = ak.register_agent_key("agent-a", pem, root=root)
    got = ak.get_agent_key(rec["keyid"], root=root)
    assert got is not None
    assert got["agent"] == "agent-a"


def test_expired_key_fails_verification(tmp_path):
    root = str(tmp_path)
    _, pem = _pem()
    now = time.time()
    rec = ak.register_agent_key("agent-a", pem, expires=now - 1, now=now - 10, root=root)
    assert ak.get_agent_key(rec["keyid"], now=now, root=root) is None


def test_revoked_key_fails_verification(tmp_path):
    root = str(tmp_path)
    _, pem = _pem()
    rec = ak.register_agent_key("agent-a", pem, root=root)
    assert ak.revoke_agent_key(rec["keyid"], root=root)
    assert ak.get_agent_key(rec["keyid"], root=root) is None


def test_bad_key_rejected(tmp_path):
    with pytest.raises(ValueError):
        ak.register_agent_key("agent-a", "not a pem", root=str(tmp_path))


def test_trust_store_resolves_live_key_with_declared_scope(tmp_path):
    root = str(tmp_path)
    _, pem = _pem()
    rec = ak.register_agent_key(
        "agent-a", pem, object_types=["ToolReceipt"], roles=["host"], root=root)
    store = ak.AgentKeyTrustStore(root=root)
    binding = store.resolve(rec["keyid"])
    assert binding is not None
    assert binding.authorizes_type("ToolReceipt")
    assert not binding.authorizes_type("StageReceipt")


def test_trust_store_resolves_nothing_for_revoked_key(tmp_path):
    root = str(tmp_path)
    _, pem = _pem()
    rec = ak.register_agent_key("agent-a", pem, object_types=["ToolReceipt"], root=root)
    ak.revoke_agent_key(rec["keyid"], root=root)
    store = ak.AgentKeyTrustStore(root=root)
    assert store.resolve(rec["keyid"]) is None


def test_trust_store_satisfies_a2a_verification_call(tmp_path):
    root = str(tmp_path)
    key, pem = _pem()
    rec = ak.register_agent_key(
        "agent-a", pem, object_types=["ToolReceipt"], roles=["host"], root=root)
    store = ak.AgentKeyTrustStore(root=root)

    from datetime import datetime, timedelta, timezone
    now = datetime.now(timezone.utc)
    obj = {
        "schema_version": "1.0.0", "type": "ToolReceipt", "issuer": "agent-a",
        "issued_at": now.isoformat(), "expires_at": (now + timedelta(days=1)).isoformat(),
        "run_id": "run-1", "nonce": "nonce-1", "key_id": rec["keyid"],
        "tool": "Bash", "arguments_digest": "0" * 64, "effect_digest": "0" * 64,
        "started_at": now.isoformat(), "ended_at": now.isoformat(),
        "executor": {"id": "x", "role": "host"}, "dispatch_id": "d1",
        "action_digest": "0" * 64,
    }
    obj["subject_digest"] = canonical.subject_digest(obj)
    sig = key.sign(pae_bytes(obj))
    import base64
    obj["signature"] = base64.b64encode(sig).decode("ascii")

    from a2a_compliance.wire.verification import verify
    result = verify(obj, "ToolReceipt", trust_store=store)
    assert result.ok, result.errors
