from __future__ import annotations

from agent_gate.records import chain_receipt, oversight_dispatch as od


def test_dispatch_records_and_returns_dispatch_id(chain, issuer, trust_store):
    result = od.dispatch({"action": "approve-export", "agent": "agent-1", "render": "ratify"},
                         chain=chain, signer=issuer, channel="email", recipient="felix@example.org")
    assert result.ok
    assert result.dispatch_id
    assert chain_receipt.verify(chain, trust_store=trust_store).ok


def test_residual_with_fewer_than_two_options_is_refused(chain, issuer):
    result = od.dispatch(
        {"action": "approve-export", "render": "options", "options": [{"id": "a"}], "link": "https://x"},
        chain=chain, signer=issuer, channel="jira",
    )
    assert not result.ok
    assert "options" in result.error
    assert chain.all() == []


def test_residual_options_without_link_is_refused(chain, issuer):
    result = od.dispatch(
        {"action": "approve-export", "render": "options",
         "options": [{"id": "a"}, {"id": "b"}]},
        chain=chain, signer=issuer, channel="jira",
    )
    assert not result.ok
    assert "link" in result.error


def test_residual_with_two_options_and_link_dispatches(chain, issuer):
    result = od.dispatch(
        {"action": "approve-export", "render": "options",
         "options": [{"id": "a"}, {"id": "b"}], "link": "https://x/surface/1"},
        chain=chain, signer=issuer, channel="jira",
    )
    assert result.ok


def test_decision_return_requires_surface_reference(chain, issuer):
    r1 = od.record_decision_return(chain=chain, signer=issuer, dispatch_id="d1",
                                   surface_dispatch_id="", actor="felix")
    assert "error" in r1
    assert chain.all() == []

    r2 = od.record_decision_return(chain=chain, signer=issuer, dispatch_id="d1",
                                   surface_dispatch_id="surface:1", actor="")
    assert "error" in r2


def test_decision_return_with_surface_reference_records(chain, issuer, trust_store):
    result = od.record_decision_return(chain=chain, signer=issuer, dispatch_id="d1",
                                       surface_dispatch_id="surface:1",
                                       chosen_option_id="a", actor="felix")
    assert "error" not in result
    assert result["surface_dispatch_id"] == "surface:1"
    assert chain_receipt.verify(chain, trust_store=trust_store).ok
