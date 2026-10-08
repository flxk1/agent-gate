from __future__ import annotations

from agent_gate.gate.verdict import Verdict
from agent_gate.records import chain_receipt, oversight_log as ol


def test_record_admission_is_signed_and_chained(chain, issuer, trust_store):
    ol.record_admission(Verdict.HOLD, chain=chain, signer=issuer, content_hash="h1",
                        cls="precedent", reason="needs human review")
    result = chain_receipt.verify(chain, trust_store=trust_store)
    assert result.ok, result.errors
    payload = chain_receipt.payloads(chain)[-1]
    assert payload["admission"] == Verdict.HOLD.value
    assert payload["class"] == "precedent"


def test_taint_walk_surfaces_citing_records_and_flags_stake():
    entries = [
        {"receipt": {"dispatch_id": "learn:a", "issued_at": "t1", "executor": {"id": "agent:x"}},
         "payload": {"kind": "learning-admission", "grounds": ["norm:14"], "footprint": ["financial"]}},
        {"receipt": {"dispatch_id": "learn:b", "issued_at": "t2", "executor": {"id": "agent:y"}},
         "payload": {"kind": "learning-admission", "grounds": ["norm:99"], "footprint": []}},
        {"receipt": {"dispatch_id": "learn:c", "issued_at": "t3", "executor": {"id": "agent:z"}},
         "payload": {"kind": "learning-admission", "cited": "norm:14", "footprint": []}},
    ]
    findings = ol.taint_walk(entries, "norm:14")
    assert {f.dispatch_id for f in findings} == {"learn:a", "learn:c"}
    stake = [f for f in findings if f.stake_bearing]
    assert len(stake) == 1
    assert stake[0].dispatch_id == "learn:a"


def test_taint_walk_chain_ignores_tampered_citation(chain, issuer, trust_store):
    ol.record_admission(Verdict.HOLD, chain=chain, signer=issuer, content_hash="h-taint",
                        cls="precedent", reason="needs review", grounds=["norm:14"],
                        footprint=["financial"])
    chain.all()[-1]["payload"]["grounds"] = ["norm:99"]
    chain.all()[-1]["payload"]["footprint"] = []

    assert chain_receipt.verify(chain, trust_store=trust_store).ok is False
    findings = ol.taint_walk_chain(chain, "norm:14", trust_store=trust_store)
    assert findings == []


def test_mark_tainted_records_summary_and_incidents(chain, issuer, trust_store):
    findings = ol.taint_walk([
        {"receipt": {"dispatch_id": "learn:a", "issued_at": "t1", "executor": {"id": "agent:x"}},
         "payload": {"grounds": ["norm:14"], "footprint": ["financial"]}},
    ], "norm:14")
    envelope = ol.mark_tainted(findings, chain=chain, signer=issuer, failed_ground="norm:14",
                               reason="precedent revoked")
    assert envelope["payload"]["tainted_count"] == 1
    assert envelope["payload"]["stake_bearing_count"] == 1
    assert chain_receipt.verify(chain, trust_store=trust_store).ok
