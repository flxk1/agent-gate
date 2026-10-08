from __future__ import annotations

import pytest

from agent_gate.locks.credentials import SubjectCredentialSource, Track
from agent_gate.subject import agent as agent_subject
from agent_gate.subject import session as session_subject


def test_source_satisfies_credential_port():
    source = SubjectCredentialSource()
    assert hasattr(source, "get") and callable(source.get)
    assert source.get("missing|track") is None


def test_lookup_is_scoped_to_its_own_subject(monkeypatch):
    monkeypatch.setenv("CRED_TOK", "s3cr3t")
    source = SubjectCredentialSource()
    a = agent_subject("a")
    b = agent_subject("b")
    source.register(a, Track(connector_id="out", credential_ref="env:CRED_TOK"))

    assert source.lookup(a, "out") is not None
    assert source.lookup(b, "out") is None
    assert source.get(f"{a}|out") == "s3cr3t"
    assert source.get(f"{b}|out") is None


def test_session_and_agent_subjects_never_collide(monkeypatch):
    monkeypatch.setenv("AGENT_TOK", "agent-secret")
    monkeypatch.setenv("SESSION_TOK", "session-secret")
    source = SubjectCredentialSource()
    agent = agent_subject("x")
    session = session_subject("x")
    source.register(agent, Track(connector_id="out", credential_ref="env:AGENT_TOK"))
    source.register(session, Track(connector_id="out", credential_ref="env:SESSION_TOK"))

    assert source.get(f"{agent}|out") == "agent-secret"
    assert source.get(f"{session}|out") == "session-secret"


def test_get_malformed_name_returns_none():
    assert SubjectCredentialSource().get("no-delimiter") is None


def test_rejects_invalid_credential_ref():
    with pytest.raises(ValueError):
        Track(connector_id="out", credential_ref="plain-secret-not-a-ref")


def test_rejects_unknown_floor():
    with pytest.raises(ValueError):
        Track(connector_id="out", floor="sometimes")
