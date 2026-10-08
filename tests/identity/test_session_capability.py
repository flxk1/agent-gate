from datetime import datetime, timedelta, timezone

import pytest

from agent_gate.identity import session_capability as sc


def test_mint_then_verify(tmp_path):
    root = str(tmp_path)
    token, claims = sc.mint(
        party="agent-a", lane_id="lane-1", folder="/f", grade="auto",
        policy_fingerprint="pf1", spec_fingerprint="sf1", uid=0, root=root,
    )
    verifier = sc.CapabilityVerifier.from_key_dir(root=root)
    got = verifier.verify(token, expected_folder="/f", expected_uid=0)
    assert got.party == "agent-a"
    assert got.nonce == claims.nonce


def test_expired_token_rejected(tmp_path):
    root = str(tmp_path)
    token, claims = sc.mint(
        party="agent-a", lane_id="lane-1", folder="/f", grade="auto",
        policy_fingerprint="pf1", spec_fingerprint="sf1", uid=0,
        ttl_seconds=1, root=root,
    )
    verifier = sc.CapabilityVerifier.from_key_dir(root=root)
    with pytest.raises(sc.CapabilityError):
        verifier.verify(token, now=claims.exp + 100)


def test_revoked_token_rejected_via_file_revocation_store(tmp_path):
    root = str(tmp_path)
    token, claims = sc.mint(
        party="agent-a", lane_id="lane-1", folder="/f", grade="auto",
        policy_fingerprint="pf1", spec_fingerprint="sf1", uid=0, root=root,
    )
    store = sc.FileRevocationStore.default(root=root)
    verifier = sc.CapabilityVerifier.from_key_dir(root=root, revoked_nonces=store)
    verifier.verify(token)
    verifier.revoke(claims.nonce)

    fresh_store = sc.FileRevocationStore.default(root=root)
    fresh_verifier = sc.CapabilityVerifier.from_key_dir(root=root, revoked_nonces=fresh_store)
    with pytest.raises(sc.CapabilityError):
        fresh_verifier.verify(token)


def test_wrong_folder_rejected(tmp_path):
    root = str(tmp_path)
    token, _ = sc.mint(
        party="agent-a", lane_id="lane-1", folder="/f", grade="auto",
        policy_fingerprint="pf1", spec_fingerprint="sf1", uid=0, root=root,
    )
    verifier = sc.CapabilityVerifier.from_key_dir(root=root)
    with pytest.raises(sc.CapabilityError):
        verifier.verify(token, expected_folder="/other")


def test_file_revocation_store_satisfies_a2a_revocation_store_protocol(tmp_path):
    from a2a_compliance.wire import canonical
    from a2a_compliance.wire.verification import verify

    store = sc.FileRevocationStore(tmp_path / "revocations")
    now = datetime.now(timezone.utc)
    digest = "1" * 64
    assert not store.is_revoked("permit", digest, at=now)
    store.revoke("permit", digest, effective_at=now - timedelta(seconds=1))
    assert store.is_revoked("permit", digest, at=now)

    obj = {
        "schema_version": "1.0.0", "type": "ToolReceipt", "issuer": "x",
        "issued_at": now.isoformat(), "expires_at": (now + timedelta(days=1)).isoformat(),
        "run_id": "run-1", "nonce": "n1", "key_id": "k1",
        "tool": "Bash", "arguments_digest": "0" * 64, "effect_digest": "0" * 64,
        "started_at": now.isoformat(), "ended_at": now.isoformat(),
        "executor": {"id": "x", "role": "host"}, "dispatch_id": "d1",
        "action_digest": digest, "signature": "",
    }
    obj["subject_digest"] = canonical.subject_digest(obj)
    result = verify(obj, "ToolReceipt", revocation_store=store, now=now)
    assert not result.ok
    assert any("revoked" in e for e in result.errors)


def test_file_revocation_store_satisfies_a2a_nonce_store_protocol(tmp_path):
    store = sc.FileRevocationStore(tmp_path / "revocations")
    assert store.consume("run-1", "nonce-1")
    assert not store.consume("run-1", "nonce-1")
    store.record("run-2", "nonce-2")
    assert store.seen("run-2", "nonce-2")
