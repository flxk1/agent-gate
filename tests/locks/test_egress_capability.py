import json
import socket
import urllib.error
import urllib.request

import pytest

from agent_gate.identity.session_capability import CapabilityError, CapabilityVerifier, mint
from agent_gate.locks.egress_proxy import EgressProxy, autonomous_callback
from agent_gate.locks.egress_proxy import OversightLevel
from loomground_audit_chain.mutation_log import read_chain

pytestmark = pytest.mark.live_egress_capability


def _port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _post(port: int, token: str = ""):
    headers = {"X-Lock-Upstream": "not-allowed.invalid"}
    if token:
        headers["X-Agent-Gate-Capability"] = token
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}/v1/messages",
        data=json.dumps({"messages": [{"content": "clean"}]}).encode(),
        headers=headers, method="POST")
    with pytest.raises(urllib.error.HTTPError) as error:
        urllib.request.urlopen(request, timeout=2)
    return error.value


def test_proxy_refuses_missing_invalid_and_revoked_before_routing(tmp_path):
    verifier = CapabilityVerifier.from_key_dir()
    token, claims = mint(
        party="bot", lane_id="lane", folder=str(tmp_path / "scope"), grade="L2",
        policy_fingerprint="sha256:policy", spec_fingerprint="sha256:spec", uid=123)
    port = _port()
    proxy = EgressProxy(port=port, oversight=OversightLevel.AUTONOMOUS,
                        approval_callback=autonomous_callback, capability_verifier=verifier)
    proxy.start()
    try:
        missing = _post(port)
        invalid = _post(port, "not-a-capability")
        valid = _post(port, token)
        verifier.revoke(claims.nonce)
        revoked = _post(port, token)
        assert b"session capability refused" in missing.read()
        assert b"session capability refused" in invalid.read()
        assert b"not allowed by lock" in valid.read()
        assert b"session capability refused" in revoked.read()
        assert proxy.stats["blocked"] == 4
        with pytest.raises(CapabilityError, match="revoked"):
            CapabilityVerifier.from_key_dir().verify(token)
    finally:
        proxy.stop()


def test_capability_refusal_is_recorded_via_audit_chain(tmp_path, monkeypatch):
    from loomground_audit_chain.mutation_log import LOG_ROOT_ENV

    log_root = tmp_path / "audit-chain"
    monkeypatch.setenv(LOG_ROOT_ENV, str(log_root))
    port = _port()
    proxy = EgressProxy(port=port, oversight=OversightLevel.AUTONOMOUS,
                        approval_callback=autonomous_callback,
                        capability_verifier=CapabilityVerifier.from_key_dir())
    proxy.start()
    try:
        _post(port)
    finally:
        proxy.stop()
    log_dir = log_root / "agent-gate-locks"
    events = list(read_chain(log_dir))
    incidents = [e for e in events if e.get("incident_type") == "oversight-bypassed"]
    assert len(incidents) == 1
    assert incidents[0]["actor"] == "egress-proxy"
    assert incidents[0]["signature"]
