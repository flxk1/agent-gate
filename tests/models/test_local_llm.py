from __future__ import annotations

import urllib.error

import pytest

from agent_gate.models import local_llm


@pytest.mark.parametrize("url,ok", [
    ("https://api.anthropic.com", True),
    ("http://api.example.com", False),
    ("http://evil.example.com:8080", False),
    ("http://127.0.0.1:8080", True),
    ("http://localhost:1234", True),
    ("http://[::1]:1234", True),
    ("ftp://x", False),
])
def test_is_secure_or_loopback(url, ok):
    assert local_llm._is_secure_or_loopback(url) is ok


def test_refuses_key_over_plain_http_before_any_call(monkeypatch):
    monkeypatch.setattr(local_llm, "_post_json", lambda *a, **k: pytest.fail("sent"))
    r = local_llm.complete_via("http://api.example.com", "m", "hi", api_key="sk-secret-123")
    assert r["ok"] is False and "https" in r["error"].lower()
    assert "sk-secret-123" not in str(r)


def test_transport_speaks_openai_shape(monkeypatch):
    sent = {}

    def fake_post(url, body, headers, timeout):
        sent.update(url=url, body=body, headers=headers, timeout=timeout)
        return {"model": "phi", "choices": [{"message": {"content": "LOCAL ANSWER"}}],
                "usage": {"total_tokens": 40}}

    monkeypatch.setattr(local_llm, "_post_json", fake_post)
    out = local_llm.complete_via("http://127.0.0.1:1/v1/", "phi", "ping", api_key="k",
                                 max_tokens=32, extra_headers={"X-Lock-Track": "t"})
    assert out["ok"] and out["response"] == "LOCAL ANSWER" and out["usage"]["total_tokens"] == 40
    assert sent["url"] == "http://127.0.0.1:1/v1/chat/completions"
    assert sent["body"]["messages"][-1]["content"] == "ping" and sent["body"]["max_tokens"] == 32
    assert sent["headers"] == {"X-Lock-Track": "t", "Authorization": "Bearer k"}


@pytest.mark.parametrize("exc,needle", [
    (urllib.error.HTTPError("u", 500, "boom", None, None), "HTTP 500"),
    (urllib.error.URLError("refused"), "unreachable"),
    (ValueError("bad json"), "call failed"),
])
def test_transport_errors_are_structured(monkeypatch, exc, needle):
    def raise_(*a, **k):
        raise exc

    monkeypatch.setattr(local_llm, "_post_json", raise_)
    r = local_llm.complete_via("http://127.0.0.1:1/v1", "m", "p")
    assert r["ok"] is False and needle in r["error"]


def test_malformed_response_shape(monkeypatch):
    monkeypatch.setattr(local_llm, "_post_json", lambda *a, **k: {"not": "openai"})
    r = local_llm.complete_via("http://127.0.0.1:1/v1", "m", "p")
    assert r["ok"] is False and "unexpected response shape" in r["error"]


def test_complete_requires_endpoint_and_model(monkeypatch):
    assert "no local-LLM endpoint" in local_llm.complete("p")["error"]
    monkeypatch.setenv(local_llm.URL_ENV, "http://127.0.0.1:1/v1")
    assert "no model configured" in local_llm.complete("p")["error"]


def test_classify_matches_category(monkeypatch):
    monkeypatch.setattr(local_llm, "complete",
                        lambda *a, **k: {"ok": True, "response": ' "Personal data." '})
    r = local_llm.classify("x", ["benign", "personal data"])
    assert r["ok"] and r["category"] == "personal data"


def test_list_available(monkeypatch):
    monkeypatch.setenv(local_llm.URL_ENV, "http://127.0.0.1:1/v1")
    monkeypatch.setattr(local_llm, "_get_json",
                        lambda url, h, t: {"data": [{"id": "a"}, {"id": "b"}, {}]})
    r = local_llm.list_available()
    assert r["ok"] and r["models"] == ["a", "b"]


def test_list_available_refuses_key_over_plain_http(monkeypatch):
    monkeypatch.setenv(local_llm.URL_ENV, "http://lan.example:1/v1")
    monkeypatch.setenv(local_llm.API_KEY_ENV, "sk-x")
    monkeypatch.setattr(local_llm, "_get_json", lambda *a, **k: pytest.fail("sent"))
    assert local_llm.list_available()["reachable"] is False
