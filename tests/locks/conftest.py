from __future__ import annotations

from types import SimpleNamespace

import pytest


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "live_egress_capability: exercises the real wired capability verifier")


@pytest.fixture(autouse=True)
def _identity_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_GATE_IDENTITY_DIR", str(tmp_path / "identity"))
    yield


@pytest.fixture(autouse=True)
def _isolate_egress_capability(request, monkeypatch):
    if request.node.get_closest_marker("live_egress_capability") is None:
        from agent_gate.locks import host_deps
        host_deps.ensure_wired()

        class _UnitVerifier:
            def verify(self, token, **kwargs):
                return SimpleNamespace()

        monkeypatch.setattr(host_deps, "capability_verifier_factory", lambda: _UnitVerifier())
    yield
