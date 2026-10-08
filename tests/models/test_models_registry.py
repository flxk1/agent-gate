from __future__ import annotations

import json

import pytest

from agent_gate.models import local_llm
from agent_gate.models import models_registry as mr
from agent_gate.models.models_registry import ModelEntry, health_check


def test_empty_registry():
    assert mr.list_models() == [] and mr.models_for_role("validator") == []


def test_register_fills_positional_slots(tmp_path):
    mr.register_model("a", "validator", artifact_path="/x/a.gguf")
    mr.register_model("b", "validator")
    mr.register_model("c", "validator")
    data = mr.load_registry()
    assert data["role_map"]["validator"] == {"order_n1": "a", "order_n2": "b"}
    assert mr.models_for_role("validator") == ["a", "b", "c"]
    assert mr.registry_path() == tmp_path / "models" / "registry.json"
    assert mr.get_model("a").artifact_path == "/x/a.gguf"
    with pytest.raises(mr.ModelNotFoundError):
        mr.get_model("zzz")


def test_role_canonicalisation_and_rejection():
    assert mr.register_model("m", "LOCK-TIER-c").roles == ["lock-tier-C"]
    with pytest.raises(mr.InvalidRoleError):
        mr.register_model("m", "workspace")


def test_legacy_slot_keys_read_as_positional():
    mr.registry_path().parent.mkdir(parents=True)
    mr.registry_path().write_text(json.dumps({"models": {}, "role_map": {
        "validator": {"primary": "p", "backup": "b"},
        "drafter": {"primary": "old", "order_n1": "new"}}}))
    assert mr.models_for_role("validator") == ["p", "b"]
    assert mr.models_for_role("drafter") == ["new"]


def test_corrupt_registry():
    mr.registry_path().parent.mkdir(parents=True)
    mr.registry_path().write_text("{not json")
    assert mr.models_for_role("validator") == []
    with pytest.raises(mr.ModelRegistryError):
        mr.list_models()


def _entry(tmp_path, mid="phi-3.5-mini-q4", content=b"GGUF" * 4):
    p = tmp_path / f"{mid}.gguf"
    if content is not None:
        p.write_bytes(content)
    return ModelEntry(id=mid, artifact_path=str(p), roles=["validator"])


def test_health_no_endpoint(tmp_path):
    r = health_check(_entry(tmp_path))
    assert r["status"] == "ok" and r["artifact_exists"] is True
    assert r["endpoint_reachable"] is None and "no endpoint configured" in r["endpoint_error"]


def test_health_missing_and_empty_artifact(tmp_path):
    assert health_check(_entry(tmp_path, "gone", None))["status"] == "missing"
    assert health_check(_entry(tmp_path, "zero", b""))["status"] == "empty"
    assert health_check(ModelEntry(id="x"))["detail"] == "no artifact_path recorded"


def test_health_unreachable(tmp_path, monkeypatch):
    import urllib.error
    monkeypatch.setenv(local_llm.URL_ENV, "http://127.0.0.1:1/v1")

    def refuse(*a, **k):
        raise urllib.error.URLError("Connection refused")

    monkeypatch.setattr(local_llm, "_get_json", refuse)
    r = health_check(_entry(tmp_path))
    assert r["endpoint_reachable"] is False and "refused" in r["endpoint_error"]


@pytest.mark.parametrize("listed,reachable", [(["phi-3.5-mini-q4", "q"], True), (["q"], False)])
def test_health_listed_or_not(tmp_path, monkeypatch, listed, reachable):
    monkeypatch.setenv(local_llm.URL_ENV, "http://localhost:1234/v1")
    monkeypatch.setattr(local_llm, "_get_json",
                        lambda *a, **k: {"data": [{"id": i} for i in listed]})
    r = health_check(_entry(tmp_path))
    assert r["endpoint_reachable"] is reachable
    assert r["endpoint_url"] == "http://localhost:1234/v1"
    assert (r["endpoint_error"] == "") is reachable


def test_pull_requires_a_package_script(tmp_path):
    r = mr.pull_model("m", package_root=tmp_path)
    assert r["ok"] is False and "pull script not found" in r["stderr"]


def test_pull_runs_the_package_script_offline(tmp_path):
    scripts = tmp_path / "pkg" / "scripts"
    scripts.mkdir(parents=True)
    (scripts / "pull_models.sh").write_text('echo "pulled $2"\n')
    r = mr.pull_model("tiny", package_root=tmp_path / "pkg")
    assert r["ok"] and r["stdout"].strip() == "pulled tiny"
