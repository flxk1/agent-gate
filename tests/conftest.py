from __future__ import annotations

import time
from typing import Optional

import pytest

from a2a_compliance.wire.admission import dev_issuer
from a2a_compliance.wire.signing import generate_dev_keypair
from a2a_compliance.wire.trust import ANY, InMemoryRevocationStore, InMemoryTrustStore
from a2a_compliance.wire.verification import InMemoryNonceStore

from loomground_drift.breaker import Breaker, BreakerState, Lease

from agent_gate.ports import IdentityPort, RecordSink


@pytest.fixture
def tmp_key_root(tmp_path):
    root = tmp_path / "keys"
    root.mkdir()
    return root


@pytest.fixture
def tmp_log_root(tmp_path):
    root = tmp_path / "log"
    root.mkdir()
    return root


@pytest.fixture
def dev_keypair():
    return generate_dev_keypair()


@pytest.fixture
def trust_store(dev_keypair):
    private_key, public_key = dev_keypair
    store = InMemoryTrustStore()
    store.add("key-test-1", public_key, frozenset({"ExecutionPermit", "ToolReceipt"}), frozenset({ANY}))
    return store


@pytest.fixture
def revocation_store():
    return InMemoryRevocationStore()


@pytest.fixture
def nonce_store():
    return InMemoryNonceStore()


@pytest.fixture
def issuer(dev_keypair):
    private_key, _public_key = dev_keypair
    return dev_issuer("key-test-1", "agent-gate:test-issuer", private_key)


@pytest.fixture
def running_breaker():
    return Breaker(Lease(agent="actor-1", granted_grade="L2", expires_at=time.time() + 10_000))


@pytest.fixture
def quarantined_breaker():
    breaker = Breaker(Lease(agent="actor-1", granted_grade="L2", expires_at=time.time() + 10_000))
    breaker._quarantined_reason = "test quarantine"
    assert breaker.status().state is BreakerState.QUARANTINED
    return breaker


class FakeIdentity(IdentityPort):
    def __init__(self, *, bound: Optional[dict[str, str]] = None) -> None:
        self._bound = dict(bound or {})

    def bind(self, session_id: str) -> str:
        return self._bound.setdefault(session_id, session_id)

    def resolve(self, session_id: str) -> Optional[str]:
        return self._bound.get(session_id)


@pytest.fixture
def identity():
    return FakeIdentity()


class ListChain(RecordSink):
    def __init__(self) -> None:
        self._records: list[dict] = []

    def append(self, record: dict) -> None:
        self._records.append(record)

    def tail(self) -> Optional[dict]:
        return self._records[-1] if self._records else None

    def all(self) -> list[dict]:
        return list(self._records)


@pytest.fixture
def chain():
    return ListChain()
