from __future__ import annotations

import json
import socket
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from agent_gate.locks.credentials import SubjectCredentialSource, Track
from agent_gate.locks.egress_proxy import ApprovalDecision, EgressProxy, OversightLevel, autonomous_callback
from agent_gate.locks.track_broker import TRACK_HEADER, bind_track
from agent_gate.subject import agent as agent_subject


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def subject():
    return agent_subject("bot-1")


@pytest.fixture
def source(subject, monkeypatch):
    monkeypatch.setenv("BROKER_TOK", "s3cr3t-tok")
    monkeypatch.delenv("NOT_SET_ANYWHERE", raising=False)
    src = SubjectCredentialSource()
    src.register(subject, Track(connector_id="out-llm", credential_ref="env:BROKER_TOK"))
    src.register(subject, Track(connector_id="out-bare"))
    src.register(subject, Track(connector_id="out-dead", credential_ref="env:BROKER_TOK", floor="deny"))
    src.register(subject, Track(connector_id="out-hold", credential_ref="env:BROKER_TOK", floor="hold"))
    src.register(subject, Track(connector_id="out-cold", credential_ref="env:NOT_SET_ANYWHERE"))
    return src


def test_bind_track_armed(source, subject):
    b = bind_track(source, subject, "out-llm")
    assert b.ok and b.secret == "s3cr3t-tok"
    assert b.credential_ref == "env:BROKER_TOK" and not b.hold
    assert "s3cr3t-tok" not in repr(b)


@pytest.mark.parametrize("cid,fragment", [
    (None, "no track declared"),
    ("", "no track declared"),
    ("ghost", "unknown track"),
    ("out-dead", "floor is deny"),
    ("out-bare", "no cable"),
    ("out-cold", "unplugged"),
])
def test_bind_track_refuses_each_rung(source, subject, cid, fragment):
    b = bind_track(source, subject, cid)
    assert not b.ok and b.secret is None
    assert fragment in b.reason
    assert "s3cr3t-tok" not in b.reason


def test_bind_track_refuses_for_a_different_subject(source):
    other = agent_subject("bot-2")
    b = bind_track(source, other, "out-llm")
    assert not b.ok and "unknown track" in b.reason


def test_bind_track_sanitizes_echoed_id(source, subject):
    b = bind_track(source, subject, "gh—ost\r\n" + "x" * 100)
    assert not b.ok
    assert "\r" not in b.reason and "\n" not in b.reason
    assert b.reason.isascii()
    assert len(b.reason) < 120


def test_bind_track_hold_floor_binds_with_flag(source, subject):
    b = bind_track(source, subject, "out-hold")
    assert b.ok and b.hold and b.floor == "hold"


def test_track_rejects_invalid_credential_ref():
    with pytest.raises(ValueError):
        Track(connector_id="x", credential_ref="not-a-known-scheme")


def test_track_rejects_unknown_floor():
    with pytest.raises(ValueError):
        Track(connector_id="x", floor="bogus")


class _Stub:
    def __init__(self):
        self.received: list[dict] = []
        port = _free_port()
        stub = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a, **k):
                return

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                stub.received.append({
                    "path": self.path,
                    "headers": {k.lower(): v for k, v in self.headers.items()},
                    "body": self.rfile.read(length).decode(),
                })
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"ok": true}')

        self.url = f"http://127.0.0.1:{port}"
        self.server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def stop(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def broker(source, subject, tmp_path):
    stub = _Stub()
    audit = tmp_path / "audit.jsonl"
    proxy = EgressProxy(
        port=_free_port(), oversight=OversightLevel.AUTONOMOUS, approval_callback=autonomous_callback,
        upstream_overrides={"api.anthropic.com": stub.url}, audit_log_path=str(audit),
        track_subject=subject, credentials=source)
    proxy.start()
    yield proxy, stub, audit
    proxy.stop()
    stub.stop()


def _post(proxy, *, track=None, extra_headers=None, content="hello") -> tuple[int, bytes]:
    body = json.dumps({"messages": [{"role": "user", "content": content}]}).encode()
    headers = {"X-Lock-Upstream": "api.anthropic.com", "Content-Type": "application/json"}
    if track is not None:
        headers[TRACK_HEADER] = track
    headers.update(extra_headers or {})
    req = urllib.request.Request(f"http://127.0.0.1:{proxy.port}/v1/messages", data=body,
                                 headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def test_broker_injects_track_credential_and_strips_client_key(broker):
    proxy, stub, _ = broker
    status, _ = _post(proxy, track="out-llm", extra_headers={"x-api-key": "agent-held-dummy"})
    assert status == 200
    fwd = stub.received[0]["headers"]
    assert fwd["x-api-key"] == "s3cr3t-tok"
    assert "x-lock-track" not in fwd
    assert "agent-held-dummy" not in json.dumps(stub.received)


@pytest.mark.parametrize("track,fragment", [
    (None, "no track declared"),
    ("ghost", "unknown track"),
    ("out-dead", "floor is deny"),
    ("out-bare", "no cable"),
    ("out-cold", "unplugged"),
])
def test_broker_refuses_before_forwarding(broker, track, fragment):
    proxy, stub, _ = broker
    status, body = _post(proxy, track=track)
    assert status == 403
    assert fragment in body.decode()
    assert stub.received == []
    assert proxy.stats["blocked"] == 1


def test_broker_refuses_uninjectable_upstream(source, subject):
    proxy = EgressProxy(port=_free_port(), oversight=OversightLevel.AUTONOMOUS,
                        approval_callback=autonomous_callback,
                        upstream_overrides={"stub.test": "http://127.0.0.1:9"},
                        track_subject=subject, credentials=source)
    proxy.start()
    try:
        body = json.dumps({"messages": [{"role": "user", "content": "hi"}]}).encode()
        req = urllib.request.Request(
            f"http://127.0.0.1:{proxy.port}/v1/messages", data=body,
            headers={"X-Lock-Upstream": "stub.test", TRACK_HEADER: "out-llm"}, method="POST")
        with pytest.raises(urllib.error.HTTPError) as e:
            urllib.request.urlopen(req, timeout=5)
        assert e.value.code == 403
        assert "no credential injection binding" in e.value.read().decode()
    finally:
        proxy.stop()


def test_hold_floor_consults_a_person_on_clean_content(source, subject):
    stub = _Stub()
    asked: list = []

    def person(pending):
        asked.append(pending)
        return ApprovalDecision(action="allow", reason="operator approved the hold")

    proxy = EgressProxy(port=_free_port(), oversight=OversightLevel.AUTONOMOUS, approval_callback=person,
                        upstream_overrides={"api.anthropic.com": stub.url},
                        track_subject=subject, credentials=source)
    proxy.start()
    try:
        status, _ = _post(proxy, track="out-hold")
        assert status == 200
        assert len(asked) == 1
        assert proxy.stats["user_approved"] == 1

        asked.clear()
        status, _ = _post(proxy, track="out-llm")
        assert status == 200 and asked == []
    finally:
        proxy.stop()
        stub.stop()


def test_hold_floor_block_refuses(source, subject):
    stub = _Stub()
    proxy = EgressProxy(port=_free_port(), oversight=OversightLevel.AUTONOMOUS,
                        approval_callback=lambda p: ApprovalDecision(action="block", reason="operator said no"),
                        upstream_overrides={"api.anthropic.com": stub.url},
                        track_subject=subject, credentials=source)
    proxy.start()
    try:
        status, body = _post(proxy, track="out-hold")
        assert status == 403
        assert "operator said no" in body.decode()
        assert stub.received == []
    finally:
        proxy.stop()
        stub.stop()


def test_broker_audit_carries_track_never_secret(broker):
    proxy, _, audit = broker
    _post(proxy, track="out-llm")
    _post(proxy, track="out-bare")
    raw = audit.read_text()
    entries = [json.loads(l) for l in raw.strip().splitlines()]
    decision = next(e for e in entries if e.get("kind") == "proxy_decision")
    assert decision["track"] == "out-llm"
    assert decision["credential_ref"] == "env:BROKER_TOK"
    assert decision["mode"] == "brokered"
    block = next(e for e in entries if e.get("kind") == "proxy_block")
    assert block["track"] == "out-bare"
    assert "s3cr3t-tok" not in raw


def test_health_reports_broker_bound_to_subject(broker, subject):
    proxy, _, _ = broker
    with urllib.request.urlopen(f"http://127.0.0.1:{proxy.port}/__lock_health__", timeout=5) as resp:
        health = json.loads(resp.read())
    assert health["broker_bound"] is True
    assert health["broker_subject"] == str(subject)


def test_unbound_proxy_ignores_track_header():
    stub = _Stub()
    proxy = EgressProxy(port=_free_port(), oversight=OversightLevel.AUTONOMOUS,
                        approval_callback=autonomous_callback,
                        upstream_overrides={"api.anthropic.com": stub.url})
    proxy.start()
    try:
        status, _ = _post(proxy, track="ghost", extra_headers={"x-api-key": "client-key"})
        assert status == 200
        assert stub.received[0]["headers"]["x-api-key"] == "client-key"
    finally:
        proxy.stop()
        stub.stop()
