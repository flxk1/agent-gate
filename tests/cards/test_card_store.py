from __future__ import annotations

import inspect

from loomground_vertical.subject_card import make_card

from agent_gate import subject as subj
from agent_gate.cards import card_store as cs


def test_store_functions_have_no_folder_parameter():
    for fn in (cs.save_card, cs.load_card, cs.list_cards, cs.scan, cs.redact):
        params = inspect.signature(fn).parameters
        assert "folder" not in params, f"{fn.__name__} still takes a folder"


def test_save_load_roundtrip_keyed_on_subject(chain, issuer):
    store = cs.InMemoryCardStore()
    card = make_card("neutral", description="a GDPR intake", role="controller")
    who = subj.agent("agent-1")
    result = cs.save_card(card, who, store=store, chain=chain, signer=issuer, actor="felix")
    assert result["subject"] == str(who)

    reloaded = cs.load_card(who, store=store)
    assert reloaded is not None
    assert reloaded.domain == "neutral"
    assert reloaded.facets.get("role") == ["controller"]

    other = subj.session("sess-9")
    assert cs.load_card(other, store=store) is None
    assert cs.list_cards(store=store) == [str(who)]


def test_save_writes_a_chain_record(chain, issuer, trust_store):
    from agent_gate.records import chain_receipt

    store = cs.InMemoryCardStore()
    card = make_card("neutral", description="x")
    cs.save_card(card, subj.agent("a1"), store=store, chain=chain, signer=issuer)
    result = chain_receipt.verify(chain, trust_store=trust_store)
    assert result.ok, result.errors
    assert chain_receipt.payloads(chain)[-1]["kind"] == "fact-intake"


def test_scan_finds_hits_and_identity_match():
    store = cs.InMemoryCardStore()
    store.put("agent:ada", {"domain": "neutral", "subject_id": "ada", "notes": "ada lovelace", "facets": {}})
    store.put("agent:other", {"domain": "neutral", "subject_id": "other", "notes": "met ada once", "facets": {}})
    store.put("agent:nevada-holdings", {"domain": "neutral", "subject_id": "nevada-holdings",
                                        "notes": "no match here", "facets": {}})

    report = cs.scan("ada", store=store)
    assert "agent:ada" in report["identity"]
    assert report["hits"].get("agent:other") == 1
    assert "agent:nevada-holdings" not in report["hits"]
    assert "agent:nevada-holdings" not in report["identity"]


def test_redact_deletes_identity_and_scrubs_others():
    store = cs.InMemoryCardStore()
    store.put("agent:ada", {"domain": "neutral", "subject_id": "ada", "notes": "ada lovelace", "facets": {}})
    store.put("agent:other", {"domain": "neutral", "subject_id": "other", "notes": "met ada once", "facets": {}})

    result = cs.redact("ada", store=store)
    assert result["ok"] is True
    assert "agent:ada" in result["deleted"]
    assert store.get("agent:ada") is None
    assert result["redacted"].get("agent:other") == 1
    assert "[REDACTED]" in store.get("agent:other")["notes"]
