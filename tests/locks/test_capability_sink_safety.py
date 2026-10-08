from __future__ import annotations

import http.client
import json
import socket
import urllib.request

import pytest

from agent_gate.locks import egress_proxy
from agent_gate.locks.egress_proxy import (
    EgressProxy,
    OversightLevel,
    _capability_sink_is_safe,
    autonomous_callback,
)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.mark.parametrize("url,safe", [
    ("http://remote.example.com", False),
    ("https://remote.example.com", True),
    ("http://127.0.0.1:9", True),
    ("http://[::1]:9", True),
    ("https://127.0.0.1:9", True),
    ("http://localhost:9", True),
])
def test_capability_sink_is_safe_unit(url, safe):
    assert _capability_sink_is_safe(url) is safe


class _FakeResp:
    status = 200

    def __init__(self):
        from email.message import Message
        self.headers = Message()

    def read(self):
        return b'{"ok": true}'

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


@pytest.mark.parametrize("upstream_url,blocked", [
    ("http://93.184.216.34", True),
    ("https://93.184.216.34", False),
    ("http://127.0.0.1:1", False),
    ("http://[::1]:1", False),
])
def test_proxy_refuses_token_to_unsafe_sink_before_sending(monkeypatch, upstream_url, blocked):
    calls = []

    def fake_urlopen(req, timeout=None):
        calls.append(req.full_url)
        return _FakeResp()

    monkeypatch.setattr(egress_proxy, "_open", fake_urlopen)

    port = _free_port()
    proxy = EgressProxy(port=port, oversight=OversightLevel.AUTONOMOUS,
                        approval_callback=autonomous_callback,
                        upstream_overrides={"sink.test": upstream_url})
    proxy.start()
    try:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
        body = json.dumps({"messages": [{"role": "user", "content": "hi"}]}).encode()
        conn.request("POST", "/v1/messages", body=body,
                     headers={"X-Lock-Upstream": "sink.test",
                              "X-Agent-Gate-Capability": "whatever-token",
                              "Content-Type": "application/json"})
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        if blocked:
            assert resp.status == 403
            assert b"neither https nor loopback" in data
            assert calls == []
        else:
            assert resp.status == 200
            assert len(calls) == 1
            assert calls[0].startswith(upstream_url)
    finally:
        proxy.stop()


class _Recorder:
    def __init__(self, status=200, location=None):
        import http.server
        import threading
        self.hits = []
        rec = self

        class H(http.server.BaseHTTPRequestHandler):
            def _any(self):
                n = int(self.headers.get("Content-Length") or 0)
                self.rfile.read(n)
                rec.hits.append({k.lower(): v for k, v in self.headers.items()})
                self.send_response(status)
                if location:
                    self.send_header("Location", location)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"{}")

            do_GET = do_POST = _any

            def log_message(self, *a):
                pass

        self.server = http.server.HTTPServer(("127.0.0.1", 0), H)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def _post_through_proxy(upstream_url):
    port = _free_port()
    proxy = EgressProxy(port=port, oversight=OversightLevel.AUTONOMOUS,
                        approval_callback=autonomous_callback,
                        upstream_overrides={"sink.test": upstream_url})
    proxy.start()
    try:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        body = json.dumps({"messages": [{"role": "user", "content": "hi"}]}).encode()
        conn.request("POST", "/v1/messages", body=body,
                     headers={"X-Lock-Upstream": "sink.test",
                              "X-Agent-Gate-Capability": "SECRET-TOKEN",
                              "Content-Type": "application/json"})
        resp = conn.getresponse()
        resp.read()
        conn.close()
        return resp.status
    finally:
        proxy.stop()


def test_capability_token_is_never_forwarded_upstream():
    up = _Recorder()
    try:
        assert _post_through_proxy(f"http://127.0.0.1:{up.port}") == 200
        assert len(up.hits) == 1
        assert "x-agent-gate-capability" not in up.hits[0]
    finally:
        up.close()


@pytest.mark.parametrize("code", [301, 302, 303, 307, 308])
def test_upstream_redirect_is_not_followed(code):
    sink = _Recorder()
    up = _Recorder(status=code, location=f"http://127.0.0.1:{sink.port}/stolen")
    try:
        assert _post_through_proxy(f"http://127.0.0.1:{up.port}") == code
        assert len(up.hits) == 1
        assert sink.hits == []
    finally:
        up.close()
        sink.close()
