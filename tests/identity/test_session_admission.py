import pytest

from agent_gate.identity import session_admission as sa
from agent_gate.identity import session_capability as sc


def test_runtime_spec_fingerprint_stable():
    assert sa.runtime_spec_fingerprint() == sa.runtime_spec_fingerprint()
    assert sa.runtime_spec_fingerprint().startswith("sha256:")


def test_reverify_accepts_matching_token(tmp_path):
    root = str(tmp_path)
    token, claims = sc.mint(
        party="agent-a", lane_id="lane-1", folder="/f", grade="auto",
        policy_fingerprint="pf1", spec_fingerprint=sa.runtime_spec_fingerprint(),
        uid=0, root=root,
    )
    verifier = sc.CapabilityVerifier.from_key_dir(root=root)
    got = sa.reverify(token, verifier=verifier, expected_party="agent-a", expected_folder="/f")
    assert got.nonce == claims.nonce


def test_reverify_rejects_stale_runtime_spec(tmp_path):
    root = str(tmp_path)
    token, _ = sc.mint(
        party="agent-a", lane_id="lane-1", folder="/f", grade="auto",
        policy_fingerprint="pf1", spec_fingerprint="stale-spec",
        uid=0, root=root,
    )
    verifier = sc.CapabilityVerifier.from_key_dir(root=root)
    with pytest.raises(sc.CapabilityError):
        sa.reverify(token, verifier=verifier, expected_party="agent-a", expected_folder="/f")


def test_reverify_rejects_wrong_party(tmp_path):
    root = str(tmp_path)
    token, _ = sc.mint(
        party="agent-a", lane_id="lane-1", folder="/f", grade="auto",
        policy_fingerprint="pf1", spec_fingerprint=sa.runtime_spec_fingerprint(),
        uid=0, root=root,
    )
    verifier = sc.CapabilityVerifier.from_key_dir(root=root)
    with pytest.raises(sc.CapabilityError):
        sa.reverify(token, verifier=verifier, expected_party="agent-b", expected_folder="/f")


def test_reverify_rejects_revoked_token(tmp_path):
    root = str(tmp_path)
    token, claims = sc.mint(
        party="agent-a", lane_id="lane-1", folder="/f", grade="auto",
        policy_fingerprint="pf1", spec_fingerprint=sa.runtime_spec_fingerprint(),
        uid=0, root=root,
    )
    store = sc.FileRevocationStore.default(root=root)
    store.revoke("session_nonce", claims.nonce)
    verifier = sc.CapabilityVerifier.from_key_dir(root=root, revoked_nonces=store)
    with pytest.raises(sc.CapabilityError):
        sa.reverify(token, verifier=verifier, expected_party="agent-a", expected_folder="/f")


def test_reverify_rejects_empty_token():
    verifier = sc.CapabilityVerifier(b"\x00" * 32)
    with pytest.raises(sc.CapabilityError):
        sa.reverify("", verifier=verifier, expected_party="agent-a")
