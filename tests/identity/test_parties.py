import pytest

from agent_gate.identity import parties as p
from agent_gate.identity import party_resolver as pr
from agent_gate.subject import agent, session


def test_register_and_list_party(chain, issuer, trust_store):
    subj = agent("agent-a")
    p.register_party(chain, subj, "agent", signer=issuer, name="Agent A", competences=["review"])
    rows = p.list_parties(chain, trust_store=trust_store)["parties"]
    assert len(rows) == 1
    assert rows[0]["party_id"] == str(subj)
    assert rows[0]["status"] == "active"


def test_re_register_preserves_agent_uid(chain, issuer, trust_store):
    subj = agent("agent-a")
    first = p.register_party(chain, subj, "agent", signer=issuer, trust_store=trust_store)
    second = p.register_party(chain, subj, "agent", signer=issuer, trust_store=trust_store)
    assert first["agent_uid"] == second["agent_uid"]


def test_set_party_status_killed(chain, issuer, trust_store):
    subj = session("sess-1")
    p.register_party(chain, subj, "agent", signer=issuer)
    p.set_party_status(chain, subj, "killed", signer=issuer, reason="revoked")
    rows = p.list_parties(chain, trust_store=trust_store)["parties"]
    assert rows[0]["status"] == "killed"


def test_route_approvers_filters_active_humans(chain, issuer, trust_store):
    human = agent("human-1")
    p.register_party(chain, human, "human", signer=issuer, role="approver", competences=["legal"])
    res = p.route_approvers(chain, "legal", trust_store=trust_store)
    assert res["count"] == 1


def test_resolver_resolve_competences(chain, issuer, trust_store):
    subj = agent("agent-a")
    p.register_party(chain, subj, "agent", signer=issuer, competences=["ops"])
    resolver = pr.get_resolver()
    assert resolver.resolve_competences(chain, str(subj), trust_store=trust_store) == ["ops"]


def test_no_folder_param_anywhere_in_parties_module():
    import inspect
    sig = inspect.signature(p.register_party)
    assert "folder_context" not in sig.parameters
    assert "log_root" not in sig.parameters


def test_register_party_without_signer_refuses():
    class _Log:
        def append(self, record):
            raise AssertionError("must not append without a signer")

        def tail(self):
            return None

        def all(self):
            return []

    with pytest.raises(ValueError):
        p.register_party(_Log(), agent("agent-a"), "agent")


def test_set_party_status_without_signer_refuses(chain, issuer):
    subj = session("sess-1")
    p.register_party(chain, subj, "agent", signer=issuer)
    with pytest.raises(ValueError):
        p.set_party_status(chain, subj, "killed")


def test_unsigned_party_registration_never_shows_in_roster(chain):
    chain.append({"event": "system", "actor": "user", "extra": {
        "kind": "PartyRegistered", "party_id": "agent:ghost", "party_kind": "agent",
    }})
    assert p.list_parties(chain)["parties"] == []


def test_unsigned_kill_switch_blinds_the_whole_roster(chain, issuer, trust_store):
    subj = session("sess-1")
    p.register_party(chain, subj, "agent", signer=issuer)
    chain.append({"event": "system", "actor": "attacker", "extra": {
        "kind": "PartyStatus", "party_id": str(subj), "status": "killed", "reason": "forged",
    }})
    assert p.list_parties(chain, trust_store=trust_store)["parties"] == []


def test_tampered_registration_never_shows_in_roster(chain, issuer, trust_store):
    subj = agent("agent-a")
    p.register_party(chain, subj, "agent", signer=issuer, competences=["ops"])
    chain.all()[-1]["payload"]["competences"] = ["root"]
    assert p.list_parties(chain, trust_store=trust_store)["parties"] == []


def test_list_parties_fails_closed_without_trust_store(chain, issuer):
    p.register_party(chain, agent("agent-a"), "agent", signer=issuer)
    assert p.list_parties(chain)["parties"] == []


def test_agent_registration_refuses_an_unverifiable_log(chain, issuer, trust_store):
    from agent_gate.subject import agent
    subj = agent("agent-a")
    p.register_party(chain, subj, "agent", signer=issuer, trust_store=trust_store)
    with pytest.raises(ValueError):
        p.register_party(chain, subj, "agent", signer=issuer)
    assert len(chain.all()) == 1
