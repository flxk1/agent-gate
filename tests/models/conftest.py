from __future__ import annotations

import pytest

from agent_gate.models import cascade_binding as cb
from agent_gate.models import local_llm, models_registry

_ENV = (
    local_llm.URL_ENV, local_llm.MODEL_ENV, local_llm.API_KEY_ENV, local_llm.TIMEOUT_ENV,
    cb.CLOUD_URL_ENV, cb.CLOUD_MODEL_ENV, cb.CLOUD_PRICE_ENV, cb.EGRESS_PROXY_ENV,
)


@pytest.fixture(autouse=True)
def isolated_models_env(tmp_path, monkeypatch):
    for k in _ENV:
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv(models_registry.MODELS_DIR_ENV, str(tmp_path / "models"))
    monkeypatch.setenv(cb.CONFIG_PATH_ENV, str(tmp_path / "models.json"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    import socket
    import urllib.request

    def refuse(*a, **k):
        raise AssertionError("network access attempted in a models test")

    monkeypatch.setattr(urllib.request, "urlopen", refuse)
    monkeypatch.setattr(socket.socket, "connect", refuse)


class ScriptedCompleter:

    def __init__(self, replies: dict[str, list[str]], *, tokens: int = 40):
        self.replies = {u: list(r) for u, r in replies.items()}
        self.tokens = tokens
        self.calls: list[dict] = []

    def __call__(self, url, model, prompt, *, api_key="", temperature=0.0, max_tokens=512,
                 timeout=None, extra_headers=None):
        self.calls.append({"url": url, "model": model, "prompt": prompt, "api_key": api_key,
                           "headers": dict(extra_headers or {})})
        queue = self.replies.get(url, [])
        reply = queue.pop(0) if queue else ""
        if reply == "__error__":
            return {"ok": False, "error": "LLM HTTP 500: boom", "latency_ms": 3}
        return {"ok": True, "response": reply, "latency_ms": 2,
                "usage": {"total_tokens": self.tokens}}

    def urls(self) -> list[str]:
        return [c["url"] for c in self.calls]


@pytest.fixture
def scripted():
    return ScriptedCompleter
