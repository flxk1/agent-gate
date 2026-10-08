from __future__ import annotations

import pytest

from a2a_compliance.wire.signing import dev_sign_subject
from a2a_compliance.wire.trust import InMemoryTrustStore, ANY
from loomground_lane import GovernanceLane

from agent_gate.host.policy_pack import PolicyPackError, published_policy_pack


@pytest.fixture
def lane():
    return GovernanceLane(
        lane_id="lane-1", agent="agent-1", max_grade="L2",
        action_classes=("tool:Write",), approved_by="felix", rationale="pilot",
    )


@pytest.fixture
def pack_trust_store(dev_keypair):
    _private, public = dev_keypair
    store = InMemoryTrustStore()
    store.add("key-pack-1", public, frozenset({"PolicyPack"}), frozenset({ANY}))
    return store


def _signed_pack(private_key):
    pack = {
        "pack_id": "pack-1", "lane_id": "lane-1", "agent": "agent-1",
        "version": 1, "rules": {"deny": ["Bash"]}, "key_id": "key-pack-1",
    }
    pack["signature"] = dev_sign_subject(pack, private_key)
    return pack


def test_well_formed_signed_lane_bound_pack_is_accepted(dev_keypair, pack_trust_store, lane):
    private_key, _public = dev_keypair
    pack = _signed_pack(private_key)
    result = published_policy_pack(pack, trust_store=pack_trust_store, lane=lane)
    assert result.pack_id == "pack-1"
    assert result.rules == {"deny": ["Bash"]}


@pytest.mark.parametrize("missing", ["pack_id", "lane_id", "agent", "version", "rules", "key_id", "signature"])
def test_malformed_pack_missing_field_is_rejected(dev_keypair, pack_trust_store, lane, missing):
    private_key, _public = dev_keypair
    pack = _signed_pack(private_key)
    del pack[missing]
    with pytest.raises(PolicyPackError):
        published_policy_pack(pack, trust_store=pack_trust_store, lane=lane)


def test_pack_that_is_not_an_object_is_rejected(pack_trust_store, lane):
    with pytest.raises(PolicyPackError):
        published_policy_pack("not-a-dict", trust_store=pack_trust_store, lane=lane)  # type: ignore[arg-type]


def test_unsigned_pack_is_rejected(dev_keypair, pack_trust_store, lane):
    private_key, _public = dev_keypair
    pack = _signed_pack(private_key)
    pack["signature"] = ""
    with pytest.raises(PolicyPackError):
        published_policy_pack(pack, trust_store=pack_trust_store, lane=lane)


def test_tampered_pack_fails_signature_verification(dev_keypair, pack_trust_store, lane):
    private_key, _public = dev_keypair
    pack = _signed_pack(private_key)
    pack["rules"] = {"deny": ["Write"]}
    with pytest.raises(PolicyPackError):
        published_policy_pack(pack, trust_store=pack_trust_store, lane=lane)


def test_unknown_key_id_is_rejected(dev_keypair, pack_trust_store, lane):
    private_key, _public = dev_keypair
    pack = _signed_pack(private_key)
    pack["key_id"] = "key-unknown"
    with pytest.raises(PolicyPackError):
        published_policy_pack(pack, trust_store=pack_trust_store, lane=lane)


def test_key_not_bound_to_policy_pack_type_is_rejected(dev_keypair, lane):
    private_key, public = dev_keypair
    store = InMemoryTrustStore()
    store.add("key-pack-1", public, frozenset({"ToolReceipt"}), frozenset({ANY}))
    pack = _signed_pack(private_key)
    with pytest.raises(PolicyPackError):
        published_policy_pack(pack, trust_store=store, lane=lane)


def test_no_lane_is_rejected(dev_keypair, pack_trust_store):
    private_key, _public = dev_keypair
    pack = _signed_pack(private_key)
    with pytest.raises(PolicyPackError):
        published_policy_pack(pack, trust_store=pack_trust_store, lane=None)


def test_mismatched_lane_is_rejected(dev_keypair, pack_trust_store):
    private_key, _public = dev_keypair
    pack = _signed_pack(private_key)
    other_lane = GovernanceLane(
        lane_id="lane-2", agent="agent-1", max_grade="L2",
        action_classes=("tool:Write",), approved_by="felix", rationale="pilot",
    )
    with pytest.raises(PolicyPackError):
        published_policy_pack(pack, trust_store=pack_trust_store, lane=other_lane)
