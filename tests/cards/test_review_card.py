from __future__ import annotations

import pytest

from a2a_compliance.wire.chain import verify_chain

from agent_gate.cards import review_card as rc
from agent_gate.records import chain_receipt


def test_reserved_act_outranks_completeness():
    card = rc.review_card(node_id="n1", stage="lock", what="locked", why="policy",
                          signals={"completeness": "high"}, reserved_act={"kind": "export"})
    assert card["status"] == "reserved"
    assert card["override"]["human_required"] is True


def test_low_completeness_needs_review():
    card = rc.review_card(node_id="n2", stage="analysis", what="x", why="y",
                          signals={"completeness": "low"})
    assert card["status"] == "needs-review"


def test_high_completeness_auto():
    card = rc.review_card(node_id="n3", stage="routing", what="x", why="y",
                          signals={"completeness": "high"})
    assert card["status"] == "auto"
    assert card["override"]["human_required"] is False


def test_override_requires_actor_and_rationale(chain, issuer):
    card = rc.review_card(node_id="n4", stage="lock", what="x", why="y")
    with pytest.raises(ValueError):
        rc.record_override(chain=chain, signer=issuer, card=card, actor="", field="f",
                           new_value=1, rationale="because")
    with pytest.raises(ValueError):
        rc.record_override(chain=chain, signer=issuer, card=card, actor="felix", field="f",
                           new_value=1, rationale="")


def test_override_is_a_signed_chain_event(chain, issuer, trust_store):
    card = rc.review_card(node_id="n5", stage="lock", what="x", why="y")
    envelope = rc.record_override(
        chain=chain, signer=issuer, card=card, actor="felix", field="verdict",
        old_value="hold", new_value="permit", rationale="reviewed and cleared",
    )
    assert envelope["receipt"]["type"] == "ToolReceipt"
    result = verify_chain([e.get("receipt", e) for e in chain.all()],
                          "ToolReceipt", trust_store=trust_store)
    assert result.ok, result.errors

    overrides = rc.overrides_for(chain, trust_store=trust_store)
    assert len(overrides) == 1
    assert overrides[0]["node_id"] == "n5"
    assert overrides[0]["actor"] == "felix"
    assert overrides[0]["rationale"] == "reviewed and cleared"


def test_tampered_override_fails_verify_chain(chain, issuer, trust_store):
    card = rc.review_card(node_id="n6", stage="lock", what="x", why="y")
    rc.record_override(chain=chain, signer=issuer, card=card, actor="felix", field="verdict",
                       old_value="hold", new_value="permit", rationale="reviewed")
    tampered = dict(chain.all()[-1])
    tampered["receipt"] = dict(tampered["receipt"])
    tampered["receipt"]["effect_digest"] = "0" * 64

    result = verify_chain([tampered["receipt"]], "ToolReceipt", trust_store=trust_store)
    assert not result.ok


def test_forged_override_payload_fails_verify_and_is_never_surfaced(chain, issuer, trust_store):
    card = rc.review_card(node_id="n7", stage="lock", what="x", why="y")
    rc.record_override(chain=chain, signer=issuer, card=card, actor="felix", field="verdict",
                       old_value="hold", new_value="deny", rationale="keep blocked")

    chain.all()[-1]["payload"]["new_value"] = "permit"
    chain.all()[-1]["payload"]["rationale"] = "forged"

    assert chain_receipt.verify(chain, trust_store=trust_store).ok is False

    overrides = rc.overrides_for(chain, trust_store=trust_store)
    assert overrides == []
    assert not any(o.get("new_value") == "permit" for o in overrides)
    assert not any(o.get("rationale") == "forged" for o in overrides)

    flags = rc.recurrence_flags(chain, threshold=1, trust_store=trust_store)
    assert flags == []


def test_recurrence_flags_at_threshold(chain, issuer, trust_store):
    card = rc.review_card(node_id="shared", stage="lock", what="x", why="y")
    for i in range(3):
        rc.record_override(chain=chain, signer=issuer, card=card, actor=f"felix-{i}",
                           field="verdict", old_value="hold", new_value="permit",
                           rationale=f"reviewed #{i}")
    flags = rc.recurrence_flags(chain, threshold=3, trust_store=trust_store)
    assert flags == [{"kind": "propose-rule", "stage": "lock", "field": "verdict", "count": 3}]

    below = rc.recurrence_flags(chain, threshold=4, trust_store=trust_store)
    assert below == []
