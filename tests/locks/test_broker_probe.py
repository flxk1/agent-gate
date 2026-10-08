from __future__ import annotations

import socket

from agent_gate.locks.broker_probe import probe_broker
from agent_gate.locks.egress_proxy import EgressProxy, OversightLevel, autonomous_callback
from agent_gate.subject import agent as agent_subject


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _proxy(**kw) -> EgressProxy:
    p = EgressProxy(port=_free_port(), oversight=OversightLevel.AUTONOMOUS,
                    approval_callback=autonomous_callback, **kw)
    p.start()
    return p


def test_probe_unreachable_is_not_bound():
    out = probe_broker(str(agent_subject("x")), proxy_url=f"http://127.0.0.1:{_free_port()}", timeout=0.3)
    assert out == {"reachable": False, "bound_here": False}


def test_probe_unbound_proxy_is_reachable_not_bound():
    p = _proxy()
    try:
        out = probe_broker(str(agent_subject("x")), proxy_url=f"http://127.0.0.1:{p.port}")
        assert out == {"reachable": True, "bound_here": False}
    finally:
        p.stop()


def test_probe_bound_to_this_subject():
    subject = agent_subject("bot-1")
    p = _proxy(track_subject=subject)
    try:
        out = probe_broker(str(subject), proxy_url=f"http://127.0.0.1:{p.port}")
        assert out == {"reachable": True, "bound_here": True}
    finally:
        p.stop()


def test_probe_bound_elsewhere_is_not_bound_here():
    p = _proxy(track_subject=agent_subject("bot-a"))
    try:
        out = probe_broker(str(agent_subject("bot-b")), proxy_url=f"http://127.0.0.1:{p.port}")
        assert out == {"reachable": True, "bound_here": False}
    finally:
        p.stop()
