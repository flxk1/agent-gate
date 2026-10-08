from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Optional

from a2a_compliance.wire.admission import Issuer
from a2a_compliance.wire.trust import RevocationStore, TrustStore
from a2a_compliance.wire.verification import NonceStore

from loomground_drift.breaker import Breaker, Lease

from ..host import home as host_home
from ..host import stores as host_stores
from ..host.policy_load import load_policy
from ..identity import SessionIdentity
from ..identity.agent_keys import AgentKeyTrustStore
from ..ops.backup import JsonlChain
from ..ports import IdentityPort, RecordSink
from .executor import HostMediatedExecutor


@dataclass
class Wiring:
    identity: IdentityPort
    trust_store: TrustStore
    nonce_store: NonceStore
    revocation_store: RevocationStore
    issuer: Issuer
    breaker: Breaker
    policy: Any
    chain: RecordSink
    policy_loaded: bool
    policy_error: Optional[str]
    executor: HostMediatedExecutor = field(default_factory=HostMediatedExecutor)


_SINGLETON: Optional[Wiring] = None


def _build() -> Wiring:
    info = host_home.init_home()
    root, keys_root, chain_path = info["root"], info["keys_root"], info["chain_path"]

    identity = SessionIdentity(root=root)
    trust_store = AgentKeyTrustStore(root=keys_root)
    nonce_store = host_stores.FileNonceStore(root)
    revocation_store = host_stores.FileRevocationStore(root)
    issuer = host_home.host_issuer()
    chain = JsonlChain(chain_path)
    breaker = Breaker(Lease(agent="agent-gate", granted_grade="L2", expires_at=time.time() + 10_000))

    policy_result = load_policy()
    return Wiring(
        identity=identity,
        trust_store=trust_store,
        nonce_store=nonce_store,
        revocation_store=revocation_store,
        issuer=issuer,
        breaker=breaker,
        policy=policy_result.policy,
        chain=chain,
        policy_loaded=policy_result.loaded,
        policy_error=policy_result.error,
    )


def default_wiring() -> Wiring:
    global _SINGLETON
    if _SINGLETON is None:
        _SINGLETON = _build()
    return _SINGLETON


def reset_default_wiring() -> None:
    global _SINGLETON
    _SINGLETON = None
