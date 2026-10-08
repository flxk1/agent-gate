from __future__ import annotations

import json
import socket
import threading
import time
import urllib.error
import urllib.request
from email.message import Message
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from agent_gate.locks.egress_proxy import (
    AgentIdentity,
    ApprovalDecision,
    EgressProxy,
    GateDecision,
    OversightLevel,
    PendingRequest,
    _credential_binding_violation,
    _block_all_callback,
    _sanitise_agent_id,
    _upstream_request_url,
    autonomous_callback,
    block_on_findings_callback,
    extract_prompt_text,
    gate_prompt,
    make_default_callback,
    notify_callback,
    redact_body_in_place,
    request_agent_identity,
    resolve_agent_identity,
)
from loomground_lock.core import Finding


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_extract_anthropic_messages():
    body = json.dumps({"messages": [{"role": "user", "content": "What's Maria Schmidt's salary?"}]}).encode()
    assert "Maria Schmidt" in extract_prompt_text("api.anthropic.com", body)


def test_extract_legacy_completions_prompt():
    body = json.dumps({"prompt": "Maria Schmidt called yesterday."}).encode()
    assert "Maria Schmidt" in extract_prompt_text("api.openai.com", body)


def test_extract_malformed_body_returns_empty():
    assert extract_prompt_text("api.anthropic.com", b"not-json") == ""


def test_extract_non_utf8_body_returns_empty():
    assert extract_prompt_text("api.anthropic.com", b"\xff\xfe\xfd") == ""


def test_extract_pulls_tool_result_and_tool_use():
    body = json.dumps({"messages": [{"role": "user", "content": [
        {"type": "tool_result", "content": "patient alice@example.com"},
        {"type": "tool_use", "input": {"q": "ssn 123-45-6789"}},
    ]}]}).encode()
    text = extract_prompt_text("api.anthropic.com", body)
    assert "alice@example.com" in text and "123-45-6789" in text


def test_extract_image_only_yields_no_text():
    body = json.dumps({"messages": [{"role": "user", "content": [
        {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "iVBORw0KGgo"}}
    ]}]}).encode()
    assert extract_prompt_text("api.anthropic.com", body).strip() == ""


def test_numeric_tool_args_are_not_scannable_text():
    body = json.dumps({"messages": [{"role": "user", "content": [
        {"type": "tool_use", "input": {"id": 123456789, "ratio": 3.14}}
    ]}]}).encode()
    assert extract_prompt_text("api.anthropic.com", body).strip() == ""


def test_gate_prompt_allows_clean_text():
    d = gate_prompt("aggregate metrics for the team this quarter", oversight=OversightLevel.AUTONOMOUS)
    assert d.action == "allow"


def test_gate_prompt_flags_email_via_core_lock_text():
    d = gate_prompt("please email alice@example.com about it", oversight=OversightLevel.NOTIFY)
    assert d.action in ("refuse", "minimise")
    assert any(f.tier in ("B", "B+", "C") for f in d.findings)


def test_gate_prompt_refuse_escalates_to_ask_user_at_approve():
    d = gate_prompt("contact alice@example.com", oversight=OversightLevel.APPROVE)
    assert d.action == "ask_user"


def test_gate_prompt_refuse_stays_refuse_below_approve():
    d = gate_prompt("contact alice@example.com", oversight=OversightLevel.NOTIFY)
    assert d.action == "refuse"


def test_gate_prompt_never_raises_on_internal_error(monkeypatch):
    import agent_gate.locks.egress_proxy as ep

    def _boom(*a, **k):
        raise RuntimeError("boom")

    monkeypatch.setattr(ep, "lock_text", _boom)
    d = gate_prompt("hello", oversight=OversightLevel.AUTONOMOUS)
    assert d.action == "refuse"
    assert "lock_text raised unexpectedly" in d.reason


def _pending_with_high_finding() -> PendingRequest:
    return PendingRequest(
        request_id="req-test-1", upstream_host="api.anthropic.com", method="POST",
        path="/v1/messages", body=b"{}", extracted_text="some text",
        findings=[Finding(tier="B", type="pii_in_argument", severity="high", field=None,
                          detail="email pattern")],
        oversight=OversightLevel.APPROVE)


def _pending_clean() -> PendingRequest:
    return PendingRequest(
        request_id="req-test-2", upstream_host="api.anthropic.com", method="POST",
        path="/v1/messages", body=b"{}", extracted_text="benign text", findings=[],
        oversight=OversightLevel.APPROVE)


def test_autonomous_callback_always_allows():
    assert autonomous_callback(_pending_with_high_finding()).action == "allow"


def test_notify_callback_always_allows():
    assert notify_callback(_pending_with_high_finding()).action == "allow"


def test_block_on_findings_allows_clean():
    assert block_on_findings_callback(_pending_clean()).action == "allow"


def test_block_on_findings_blocks_high():
    assert block_on_findings_callback(_pending_with_high_finding()).action == "block"


def test_manual_callback_always_blocks():
    assert _block_all_callback(_pending_clean()).action == "block"
    assert _block_all_callback(_pending_with_high_finding()).action == "block"


def test_make_default_callback_per_level():
    for lvl in OversightLevel:
        assert callable(make_default_callback(lvl))


def test_proxy_starts_and_stops():
    port = _free_port()
    proxy = EgressProxy(port=port, oversight=OversightLevel.AUTONOMOUS, approval_callback=autonomous_callback)
    proxy.start()
    try:
        resp = urllib.request.urlopen(f"http://127.0.0.1:{port}/__lock_health__", timeout=2)
        data = json.loads(resp.read().decode())
        assert data["status"] == "ok"
        assert data["oversight"] == "autonomous"
        assert data["broker_bound"] is False
    finally:
        proxy.stop()


def test_proxy_blocks_disallowed_upstream():
    port = _free_port()
    proxy = EgressProxy(port=port, oversight=OversightLevel.AUTONOMOUS, approval_callback=autonomous_callback)
    proxy.start()
    try:
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/v1/messages", data=b"{}",
            headers={"X-Lock-Upstream": "evil.example.com"}, method="POST")
        with pytest.raises(urllib.error.HTTPError) as ei:
            urllib.request.urlopen(req, timeout=2)
        assert ei.value.code == 403
    finally:
        proxy.stop()


def test_upstream_url_preserves_origin_form_path_and_query():
    assert (_upstream_request_url("https://api.anthropic.com", "/v1/messages?beta=1")
           == "https://api.anthropic.com/v1/messages?beta=1")


@pytest.mark.parametrize("target", [
    "@127.0.0.1:9000/v1/messages", "//127.0.0.1:9000/v1/messages",
    "https://127.0.0.1:9000/v1/messages", "/v1/messages#fragment",
])
def test_upstream_url_rejects_targets_that_can_select_an_authority(target):
    with pytest.raises(ValueError):
        _upstream_request_url("https://api.anthropic.com", target)


def test_proxy_blocks_when_callback_says_block():
    port = _free_port()

    def reject_all(pending):
        return ApprovalDecision(action="block", reason="test reject")

    proxy = EgressProxy(port=port, oversight=OversightLevel.SUPERVISED, approval_callback=reject_all)
    proxy.start()
    try:
        body = json.dumps({"messages": [{"role": "user", "content": "Maria Schmidt's salary?"}]}).encode()
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/v1/messages", data=body,
            headers={"X-Lock-Upstream": "api.anthropic.com", "Content-Type": "application/json"},
            method="POST")
        with pytest.raises(urllib.error.HTTPError) as ei:
            urllib.request.urlopen(req, timeout=2)
        assert ei.value.code == 403
        resp_body = json.loads(ei.value.read().decode())
        assert "blocked by agent-gate" in resp_body["error"]
        assert resp_body["reason"] == "test reject"
        assert proxy.stats["blocked"] == 1
        assert proxy.stats["allowed"] == 0
    finally:
        proxy.stop()


def test_proxy_writes_audit_log_on_decision(tmp_path):
    port = _free_port()
    audit = tmp_path / "audit.jsonl"

    def reject_all(pending):
        return ApprovalDecision(action="block", reason="test")

    proxy = EgressProxy(port=port, oversight=OversightLevel.SUPERVISED,
                        approval_callback=reject_all, audit_log_path=str(audit))
    proxy.start()
    try:
        body = json.dumps({"messages": [{"role": "user", "content": "contact alice@example.com"}]}).encode()
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/v1/messages", data=body,
            headers={"X-Lock-Upstream": "api.anthropic.com"}, method="POST")
        try:
            urllib.request.urlopen(req, timeout=2)
        except urllib.error.HTTPError:
            pass
    finally:
        proxy.stop()

    entries = [json.loads(l) for l in audit.read_text().strip().splitlines()]
    decisions = [e for e in entries if e.get("kind") == "proxy_decision"]
    assert len(decisions) >= 1
    entry = decisions[0]
    assert entry["upstream"] == "api.anthropic.com"
    assert entry["action"] == "block"
    assert "alice@example.com" not in audit.read_text()


def test_proxy_forwards_to_stub_upstream():
    upstream_port = _free_port()
    proxy_port = _free_port()
    upstream_received = []

    class StubHandler(BaseHTTPRequestHandler):
        def log_message(self, *a, **k):
            return

        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            upstream_received.append({"path": self.path, "body": self.rfile.read(length).decode()})
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"ok": true, "from": "stub-upstream"}')

    upstream_server = ThreadingHTTPServer(("127.0.0.1", upstream_port), StubHandler)
    threading.Thread(target=upstream_server.serve_forever, daemon=True).start()

    proxy = EgressProxy(port=proxy_port, oversight=OversightLevel.AUTONOMOUS,
                        approval_callback=autonomous_callback,
                        upstream_overrides={"stub.test": f"http://127.0.0.1:{upstream_port}"})
    proxy.start()
    try:
        body = json.dumps({"messages": [{"role": "user", "content": "hi"}]}).encode()
        req = urllib.request.Request(
            f"http://127.0.0.1:{proxy_port}/v1/messages", data=body,
            headers={"X-Lock-Upstream": "stub.test", "Content-Type": "application/json"}, method="POST")
        resp = urllib.request.urlopen(req, timeout=2)
        out = json.loads(resp.read().decode())
        assert out == {"ok": True, "from": "stub-upstream"}
        assert proxy.stats["allowed"] == 1
        assert len(upstream_received) == 1
    finally:
        proxy.stop()
        upstream_server.shutdown()
        upstream_server.server_close()


def test_proxy_minimise_redacts_request_body_before_forward():
    body = json.dumps({"messages": [{"role": "user", "content": "write to alice@example.com please"}]}).encode()
    redacted = redact_body_in_place(body, "api.anthropic.com")
    payload = json.loads(redacted)
    new_text = payload["messages"][0]["content"]
    assert "alice@example.com" not in new_text
    assert "[REDACTED-EMAIL]" in new_text


def test_proxy_fails_closed_on_unverifiable_body():
    port = _free_port()
    proxy = EgressProxy(port=port, oversight=OversightLevel.AUTONOMOUS, approval_callback=autonomous_callback)
    proxy.start()
    try:
        body = json.dumps({"messages": [{"role": "user", "content": [
            {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "iVBORw0KGgo"}}
        ]}]}).encode()
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/v1/messages", data=body,
            headers={"X-Lock-Upstream": "api.anthropic.com", "Content-Type": "application/json"}, method="POST")
        with pytest.raises(urllib.error.HTTPError) as ei:
            urllib.request.urlopen(req, timeout=2)
        assert ei.value.code == 403
    finally:
        proxy.stop()


def test_credential_binding_matched_is_ok():
    assert _credential_binding_violation({"x-api-key": "sk-ant"}, "api.anthropic.com") is None


def test_credential_binding_crossprovider_is_violation():
    assert _credential_binding_violation({"x-api-key": "sk-ant"}, "api.openai.com") == "x-api-key"


def test_credential_binding_unknown_upstream_fails_closed():
    assert _credential_binding_violation({"x-api-key": "k"}, "evil.example.com") == "x-api-key"


def _hdrs(**pairs) -> Message:
    m = Message()
    for k, v in pairs.items():
        m[k.replace("_", "-")] = v
    return m


def test_agent_identity_prefers_signature_agent_header(monkeypatch):
    monkeypatch.setenv("AGENT_GATE_AGENT", "env-agent")
    assert request_agent_identity(_hdrs(Signature_Agent="agent-alpha", X_Lock_Agent="beta")) == "agent-alpha"


def test_agent_identity_alias_then_env_then_default(monkeypatch):
    monkeypatch.delenv("AGENT_GATE_AGENT", raising=False)
    assert request_agent_identity(_hdrs(X_Lock_Agent="beta")) == "beta"
    monkeypatch.setenv("AGENT_GATE_AGENT", "env-agent")
    assert request_agent_identity(_hdrs()) == "env-agent"
    monkeypatch.delenv("AGENT_GATE_AGENT", raising=False)
    assert request_agent_identity(_hdrs()) == "agent"


def test_agent_identity_sanitises_quotes_control_chars_and_length():
    assert _sanitise_agent_id('"https://bot.example"') == "https://bot.example"
    assert _sanitise_agent_id("a\x00b\x07") == "ab"
    assert len(_sanitise_agent_id("x" * 400)) == 128


def test_agent_identity_never_raises(monkeypatch):
    monkeypatch.setenv("AGENT_GATE_AGENT", "fallback")

    class Boom:
        def get(self, _name):
            raise RuntimeError("header store broke")

    assert request_agent_identity(Boom()) == "fallback"
    assert request_agent_identity(None) == "fallback"


def test_resolve_identity_declared_when_unsigned():
    msg = Message()
    msg["Signature-Agent"] = '"solo-agent"'
    ident = resolve_agent_identity(msg)
    assert ident.verified is False and ident.actor == "solo-agent"
    assert "no signature" in ident.reason


def test_proxy_attributes_agent_identity_per_request(monkeypatch):
    seen_actors: list = []

    def spy_gate(text, **kw):
        seen_actors.append(kw.get("actor"))
        return GateDecision(action="allow", reason="test", source="cloud_llm_request")

    monkeypatch.setattr("agent_gate.locks.egress_proxy.gate_prompt", spy_gate)

    upstream_port = _free_port()
    proxy_port = _free_port()
    upstream_header_sets: list = []

    class StubHandler(BaseHTTPRequestHandler):
        def log_message(self, *a, **k):
            return

        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            self.rfile.read(length)
            upstream_header_sets.append({k.lower() for k in self.headers.keys()})
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"ok": true}')

    upstream = ThreadingHTTPServer(("127.0.0.1", upstream_port), StubHandler)
    threading.Thread(target=upstream.serve_forever, daemon=True).start()
    proxy = EgressProxy(port=proxy_port, oversight=OversightLevel.AUTONOMOUS,
                        approval_callback=autonomous_callback,
                        upstream_overrides={"stub.test": f"http://127.0.0.1:{upstream_port}"})
    proxy.start()
    try:
        for who, header in (("agent-alpha", "Signature-Agent"), ("agent-beta", "X-Lock-Agent")):
            body = json.dumps({"messages": [{"role": "user", "content": "hi"}]}).encode()
            req = urllib.request.Request(
                f"http://127.0.0.1:{proxy_port}/v1/messages", data=body,
                headers={"X-Lock-Upstream": "stub.test", "Content-Type": "application/json", header: who},
                method="POST")
            urllib.request.urlopen(req, timeout=3).read()
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()

    assert seen_actors == ["agent-alpha", "agent-beta"], seen_actors
    for received in upstream_header_sets:
        assert "signature-agent" not in received
        assert "x-lock-agent" not in received


def test_require_verified_env_parsing(monkeypatch):
    from agent_gate.locks.egress_proxy import _require_verified_egress

    monkeypatch.delenv("AGENT_GATE_REQUIRE_VERIFIED_EGRESS", raising=False)
    assert _require_verified_egress() is False
    for on in ("1", "on", "true", "YES"):
        monkeypatch.setenv("AGENT_GATE_REQUIRE_VERIFIED_EGRESS", on)
        assert _require_verified_egress() is True
    monkeypatch.setenv("AGENT_GATE_REQUIRE_VERIFIED_EGRESS", "0")
    assert _require_verified_egress() is False


def test_require_verified_refuses_unsigned(monkeypatch):
    monkeypatch.setenv("AGENT_GATE_REQUIRE_VERIFIED_EGRESS", "1")
    port = _free_port()
    proxy = EgressProxy(port=port, oversight=OversightLevel.AUTONOMOUS, approval_callback=autonomous_callback)
    proxy.start()
    try:
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/v1/messages",
            data=json.dumps({"messages": [{"role": "user", "content": "hi"}]}).encode(),
            headers={"X-Lock-Upstream": "api.anthropic.com", "Content-Type": "application/json",
                     "Signature-Agent": '"unsigned-agent"'},
            method="POST")
        with pytest.raises(urllib.error.HTTPError) as ei:
            urllib.request.urlopen(req, timeout=2)
        assert ei.value.code == 403
    finally:
        proxy.stop()


def test_require_verified_off_allows_unsigned():
    upstream_port = _free_port()
    proxy_port = _free_port()

    class Stub(BaseHTTPRequestHandler):
        def log_message(self, *a, **k):
            return

        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"ok": true}')

    upstream = ThreadingHTTPServer(("127.0.0.1", upstream_port), Stub)
    threading.Thread(target=upstream.serve_forever, daemon=True).start()
    proxy = EgressProxy(port=proxy_port, oversight=OversightLevel.AUTONOMOUS,
                        approval_callback=autonomous_callback,
                        upstream_overrides={"stub.test": f"http://127.0.0.1:{upstream_port}"})
    proxy.start()
    try:
        req = urllib.request.Request(
            f"http://127.0.0.1:{proxy_port}/v1/messages",
            data=json.dumps({"messages": [{"role": "user", "content": "hi"}]}).encode(),
            headers={"X-Lock-Upstream": "stub.test", "Content-Type": "application/json",
                     "Signature-Agent": '"whoever"'},
            method="POST")
        urllib.request.urlopen(req, timeout=3).read()
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()


def test_policy_composition_off_by_default(monkeypatch):
    from agent_gate.locks import host_deps

    monkeypatch.delenv("AGENT_GATE_EGRESS_POLICY", raising=False)
    calls = []
    host_deps.ensure_wired()
    monkeypatch.setattr(host_deps, "policy_admit",
                        lambda **kw: calls.append(kw) or {"light": "block", "reason": "x"})
    d = gate_prompt("hello", oversight=OversightLevel.AUTONOMOUS, actor="agent:a")
    assert d.action == "allow"
    assert calls == []


def test_policy_composition_can_only_tighten_never_loosen(monkeypatch):
    from agent_gate.locks import host_deps

    monkeypatch.setenv("AGENT_GATE_EGRESS_POLICY", "1")
    host_deps.ensure_wired()
    monkeypatch.setattr(host_deps, "policy_admit", lambda **kw: {"light": "go", "reason": ""})
    d = gate_prompt("contact alice@example.com", oversight=OversightLevel.NOTIFY, actor="agent:a")
    assert d.action == "refuse"


def test_policy_composition_escalates_allow_to_ask_user(monkeypatch):
    from agent_gate.locks import host_deps

    monkeypatch.setenv("AGENT_GATE_EGRESS_POLICY", "1")
    host_deps.ensure_wired()
    monkeypatch.setattr(host_deps, "policy_admit", lambda **kw: {"light": "ask", "reason": "reserved"})
    d = gate_prompt("clean benign text", oversight=OversightLevel.AUTONOMOUS, actor="agent:a")
    assert d.action == "ask_user"
    assert "reserved" in d.reason


def test_policy_composition_refuses_when_policy_is_unavailable(monkeypatch):
    from agent_gate.host.home import HostKeyRevoked
    from agent_gate.locks import host_deps

    def _raise(**kw):
        raise HostKeyRevoked("host key revoked")

    monkeypatch.setenv("AGENT_GATE_EGRESS_POLICY", "1")
    host_deps.ensure_wired()
    monkeypatch.setattr(host_deps, "policy_admit", _raise)
    d = gate_prompt("clean benign text", oversight=OversightLevel.AUTONOMOUS, actor="agent:a")
    assert d.action == "refuse"
    assert "policy unavailable" in d.reason
