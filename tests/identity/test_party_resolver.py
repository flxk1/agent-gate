from agent_gate.identity import parties as p
from agent_gate.identity import party_resolver as pr
from agent_gate.subject import agent


def test_default_resolver_is_local():
    assert isinstance(pr.get_resolver(), pr.LocalPartyResolver)


def test_set_resolver_roundtrip():
    custom = pr.LocalPartyResolver()
    pr.set_resolver(custom)
    try:
        assert pr.get_resolver() is custom
    finally:
        pr.set_resolver(None)
    assert isinstance(pr.get_resolver(), pr.LocalPartyResolver)


def test_resolver_list_parties_blinded_by_one_unsigned_entry(chain, issuer, trust_store):
    p.register_party(chain, agent("agent-a"), "agent", signer=issuer, competences=["ops"])
    chain.append({"event": "system", "actor": "attacker", "extra": {
        "kind": "PartyRegistered", "party_id": "agent:ghost", "party_kind": "agent",
    }})
    resolver = pr.get_resolver()
    assert resolver.list_parties(chain, trust_store=trust_store)["parties"] == []


def test_resolver_route_approvers_blinded_by_forged_kill_switch(chain, issuer, trust_store):
    human = agent("human-1")
    p.register_party(chain, human, "human", signer=issuer, role="approver", competences=["legal"])
    chain.append({"event": "system", "actor": "attacker", "extra": {
        "kind": "PartyStatus", "party_id": str(human), "status": "killed", "reason": "forged",
    }})
    resolver = pr.get_resolver()
    res = resolver.route_approvers(chain, "legal", trust_store=trust_store)
    assert res["count"] == 0


def test_resolver_resolve_competences_fails_closed_without_trust_store(chain, issuer):
    p.register_party(chain, agent("agent-a"), "agent", signer=issuer, competences=["ops"])
    resolver = pr.get_resolver()
    assert resolver.resolve_competences(chain, str(agent("agent-a"))) == []
