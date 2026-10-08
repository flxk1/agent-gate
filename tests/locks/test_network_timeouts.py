from __future__ import annotations

import http.client
import json
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
import urllib.error
import urllib.request

from agent_gate.locks.egress_proxy import (
    EgressProxy,
    OversightLevel,
    _egress_max_concurrency,
    _egress_timeout_secs,
    autonomous_callback,
)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _make_upstream(mode: str, *, hang_s: float = 30.0):
    port = _free_port()

    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, *a, **k):
            return

        def _drain(self):
            length = int(self.headers.get("Content-Length", "0"))
            if length:
                self.rfile.read(length)

        def do_POST(self):
            self._drain()
            if mode == "hang_before_headers":
                time.sleep(hang_s)
                return
            if mode == "truncated_body":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", "1000")
                self.end_headers()
                self.wfile.write(b'{"partial":')

        do_GET = do_POST

    server = ThreadingHTTPServer(("127.0.0.1", port), _Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, port


def _start_proxy(upstream_port: int):
    proxy_port = _free_port()
    proxy = EgressProxy(port=proxy_port, oversight=OversightLevel.AUTONOMOUS,
                        approval_callback=autonomous_callback,
                        upstream_overrides={"stub.test": f"http://127.0.0.1:{upstream_port}"})
    proxy.start()
    return proxy, proxy_port


def _post_through_proxy(proxy_port: int, *, client_timeout: float):
    req = urllib.request.Request(
        f"http://127.0.0.1:{proxy_port}/v1/messages",
        data=json.dumps({"messages": [{"role": "user", "content": "hi"}]}).encode(),
        headers={"X-Lock-Upstream": "stub.test", "Content-Type": "application/json"}, method="POST")
    return urllib.request.urlopen(req, timeout=client_timeout)


def test_egress_hung_upstream_is_bounded_and_fails_closed(monkeypatch):
    monkeypatch.setenv("AGENT_GATE_EGRESS_TIMEOUT_SECS", "2")
    upstream, up_port = _make_upstream("hang_before_headers", hang_s=30.0)
    proxy, proxy_port = _start_proxy(up_port)
    try:
        started = time.time()
        with pytest.raises(urllib.error.HTTPError) as ei:
            _post_through_proxy(proxy_port, client_timeout=20)
        elapsed = time.time() - started
        assert ei.value.code == 502, f"expected fail-closed 502, got {ei.value.code}"
        assert elapsed < 10, f"proxy took {elapsed:.1f}s to bound a hung upstream"
        assert proxy.stats["errors"] >= 1
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()


def test_egress_truncated_body_is_caught_not_uncaught(monkeypatch):
    monkeypatch.setenv("AGENT_GATE_EGRESS_TIMEOUT_SECS", "5")
    upstream, up_port = _make_upstream("truncated_body")
    proxy, proxy_port = _start_proxy(up_port)
    try:
        try:
            resp = _post_through_proxy(proxy_port, client_timeout=10)
            resp.read()
        except (urllib.error.URLError, http.client.IncompleteRead, ConnectionError):
            pass

        assert proxy.stats["errors"] >= 1, (
            "IncompleteRead from a truncated upstream body was not counted as an "
            "upstream error -- it escaped the fail-closed handler uncaught")

        health = urllib.request.urlopen(f"http://127.0.0.1:{proxy_port}/__lock_health__", timeout=3)
        assert json.loads(health.read())["status"] == "ok"
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()


def test_egress_concurrency_is_bounded_sheds_load(monkeypatch):
    cap = 3
    extra = 5
    monkeypatch.setenv("AGENT_GATE_EGRESS_TIMEOUT_SECS", "8")
    monkeypatch.setenv("AGENT_GATE_EGRESS_MAX_CONCURRENCY", str(cap))

    upstream, up_port = _make_upstream("hang_before_headers", hang_s=30.0)
    proxy, proxy_port = _start_proxy(up_port)
    assert proxy.max_concurrency == cap

    saturators: list[threading.Thread] = []

    def _hold_open():
        try:
            _post_through_proxy(proxy_port, client_timeout=25).read()
        except Exception:
            pass

    try:
        for _ in range(cap):
            t = threading.Thread(target=_hold_open, daemon=True)
            t.start()
            saturators.append(t)

        deadline = time.time() + 5
        while proxy.stats["received"] < cap and time.time() < deadline:
            time.sleep(0.02)
        assert proxy.stats["received"] >= cap

        for i in range(extra):
            started = time.time()
            with pytest.raises(urllib.error.HTTPError) as ei:
                _post_through_proxy(proxy_port, client_timeout=10).read()
            elapsed = time.time() - started
            assert ei.value.code == 503, f"over-cap request {i} got {ei.value.code}"
            assert elapsed < 3, f"over-cap request {i} took {elapsed:.1f}s -- not shed"

        assert proxy.stats["shed"] >= extra
        assert proxy.stats["received"] == cap

        health = urllib.request.urlopen(f"http://127.0.0.1:{proxy_port}/__lock_health__", timeout=3)
        payload = json.loads(health.read())
        assert payload["status"] == "ok"
        assert payload["max_concurrency"] == cap
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()
        for t in saturators:
            t.join(timeout=10)


def test_egress_max_concurrency_is_configurable(monkeypatch):
    monkeypatch.delenv("AGENT_GATE_EGRESS_MAX_CONCURRENCY", raising=False)
    assert _egress_max_concurrency() == 64
    monkeypatch.setenv("AGENT_GATE_EGRESS_MAX_CONCURRENCY", "8")
    assert _egress_max_concurrency() == 8
    monkeypatch.setenv("AGENT_GATE_EGRESS_MAX_CONCURRENCY", "0")
    assert _egress_max_concurrency() == 64
    monkeypatch.setenv("AGENT_GATE_EGRESS_MAX_CONCURRENCY", "1.5")
    assert _egress_max_concurrency() == 64


def test_egress_timeout_is_configurable(monkeypatch):
    monkeypatch.delenv("AGENT_GATE_EGRESS_TIMEOUT_SECS", raising=False)
    assert _egress_timeout_secs() == 60.0
    monkeypatch.setenv("AGENT_GATE_EGRESS_TIMEOUT_SECS", "3.5")
    assert _egress_timeout_secs() == 3.5
    monkeypatch.setenv("AGENT_GATE_EGRESS_TIMEOUT_SECS", "0")
    assert _egress_timeout_secs() == 60.0
    monkeypatch.setenv("AGENT_GATE_EGRESS_TIMEOUT_SECS", "not-a-number")
    assert _egress_timeout_secs() == 60.0
