from __future__ import annotations

import inspect
import json
import re
from pathlib import Path

import pytest

from agent_gate.models import cascade_binding as cb
from agent_gate.models import models_registry
from agent_gate.subject import agent, global_subject, session

LOCAL = "http://127.0.0.1:1111/v1"
PROXY = "http://127.0.0.1:8443/v1"


def allow(prompt):
    return "allow", prompt


def _cloud_cfg():
    cb.write_config(local_url=LOCAL, local_model="phi-3.5-mini",
                    cloud_url="https://cloud.example/v1", cloud_model="big")


def test_no_tier_is_loud():
    r = cb.cascade_for(global_subject(), "hi")
    assert r["ok"] is False and "no model tier" in r["error"] and r["advice"]
    assert r["subject"] == "global"


def test_config_file_supplies_a_local_tier(tmp_path, scripted, chain):
    written = cb.write_config(local_url=LOCAL, local_model="qwen2.5-coder")
    assert written == cb.config_path() == tmp_path / "models.json"
    ts = cb.tiers()
    assert [(t.name, t.model) for t in ts] == [("local", "qwen2.5-coder")]
    c = scripted({LOCAL: ["def f(): return 1"]})
    r = cb.cascade_for(agent("a1"), "x", sink=chain, completer=c)
    assert r["ok"] and r["served_by"] == "local"


def test_default_config_path_is_per_user_not_per_folder(tmp_path, monkeypatch):
    monkeypatch.delenv(cb.CONFIG_PATH_ENV)
    assert cb.config_path() == tmp_path / "xdg" / "agent-gate" / "models.json"


def test_env_wins_over_config(monkeypatch):
    cb.write_config(local_url="http://config:1/v1", local_model="from-config")
    monkeypatch.setenv(cb.LOCAL_URL_ENV, "http://env:2/v1")
    monkeypatch.setenv(cb.LOCAL_MODEL_ENV, "from-env")
    t = cb.tiers()[0]
    assert (t.url, t.model) == ("http://env:2/v1", "from-env")


def test_env_url_without_model_uses_default_role_model(monkeypatch):
    models_registry.register_model("qwen-3b", models_registry.DEFAULT_ROLE)
    models_registry.register_model("coder-7b", "code-fix")
    monkeypatch.setenv(cb.LOCAL_URL_ENV, LOCAL)
    assert [(t.url, t.model) for t in cb.tiers()] == [(LOCAL, "qwen-3b")]


def test_ordered_local_list_and_non_http_entries_skipped():
    cb.write_config(local_models=[{"model": "tiny", "url": LOCAL},
                                  {"model": "/m/qwen-7b.gguf"},
                                  {"model": "mid", "url": "https://m.example/v1"}])
    assert [(t.name, t.model) for t in cb.tiers()] == [("local-tiny", "tiny"), ("local-mid", "mid")]


def test_write_merges_without_clobbering_and_strips_raw_key():
    cb.config_path().write_text(json.dumps({"cloud": {
        "url": "https://c/v1", "model": "big", "price_per_1k": 0.4,
        "api_key": "legacy-credential-value"}}))
    assert "api_key" not in cb.load_config()["cloud"]
    cb.write_config(local_url=LOCAL, local_model="small")
    stored = json.loads(cb.config_path().read_text())
    assert "api_key" not in stored["cloud"] and stored["cloud"]["price_per_1k"] == 0.4
    ts = cb.tiers(capability_token="cap", track_id="cloud-primary")
    assert {t.name for t in ts} == {"local", "cloud"}
    c = next(t for t in ts if t.is_cloud)
    assert c.api_key == "" and c.proxy_url == cb.DEFAULT_EGRESS_PROXY and c.configured


def test_direct_raw_cloud_key_is_ignored():
    with pytest.warns(DeprecationWarning, match="deprecated and ignored"):
        cb.write_config(cloud_url="https://cloud.example/v1", cloud_model="m",
                        cloud_api_key="test-credential-value")
    assert "api_key" not in json.loads(cb.config_path().read_text())["cloud"]


@pytest.mark.parametrize("url", [
    "https://user:pass" + "\x40" + "cloud.example/v1",
    "https://cloud.example/v1?token=test-value",
    "https://cloud.example/v1?API_KEY=test-value",
])
def test_endpoint_url_rejects_embedded_credentials(url):
    with pytest.raises(ValueError, match="credential") as exc:
        cb.write_config(cloud_url=url, cloud_model="m")
    assert "test-value" not in str(exc.value)


def test_served_locally_records_hash_not_prompt(scripted, chain):
    _cloud_cfg()
    c = scripted({LOCAL: ["answer"]})
    r = cb.cascade_for(session("s-1"), "secret prompt text", sink=chain, completer=c,
                       shield=allow, capability_token="cap", track_id="t")
    assert r["ok"] and r["served_by"] == "local" and r["served_is_cloud"] is False
    assert PROXY not in c.urls()
    (rec,) = chain.all()
    assert rec["kind"] == cb.RECORD_KIND and rec["subject"] == "session:s-1"
    assert "secret prompt text" not in json.dumps(rec)
    assert r["audit_id"] and len(r["audit_id"]) == 64 and "ledger" in r


def test_verifier_gated_local_first_then_cloud_fallback(scripted, chain):
    _cloud_cfg()
    c = scripted({LOCAL: ["I cannot do that"], PROXY: ["CLOUD ANSWER"]})
    r = cb.cascade_for(agent("a1"), "hard", sink=chain, completer=c, shield=allow,
                       capability_token="cap", track_id="cloud-primary")
    assert c.urls() == [LOCAL, PROXY]
    assert r["ok"] and r["served_by"] == "cloud" and r["served_is_cloud"]
    assert r["ledger"]["local_deferrals"] == 1 and r["ledger"]["escalated_to_cloud"]
    assert chain.all()[0]["served_is_cloud"] is True


def test_cloud_without_capability_is_not_reached(scripted, chain):
    _cloud_cfg()
    c = scripted({LOCAL: [""], PROXY: ["CLOUD"]})
    r = cb.cascade_for(agent("a1"), "hard", sink=chain, completer=c, shield=allow)
    assert c.urls() == [LOCAL] and r["escalation_withheld"]


def test_air_gap_is_a_subject_question(scripted, chain):
    _cloud_cfg()
    seen = []

    def gap(subject):
        seen.append(subject)
        return str(subject) == "agent:locked"

    c = scripted({LOCAL: ["", ""], PROXY: ["CLOUD"]})
    r = cb.cascade_for(agent("locked"), "t", sink=chain, completer=c, shield=allow,
                       air_gapped=gap, capability_token="cap", track_id="t")
    assert PROXY not in c.urls() and r["air_gapped"] and r["cloud_tiers_withheld"] == 1
    assert r["escalation_withheld"]
    r2 = cb.cascade_for(agent("free"), "t", sink=chain, completer=c, shield=allow,
                        air_gapped=gap, capability_token="cap", track_id="t")
    assert r2["served_is_cloud"] and not r2["air_gapped"]
    assert [str(s) for s in seen] == ["agent:locked", "agent:free"]


def test_air_gap_check_that_raises_fails_closed(scripted, chain):
    _cloud_cfg()

    def broken(subject):
        raise RuntimeError("policy unreadable")

    c = scripted({LOCAL: [""], PROXY: ["CLOUD"]})
    r = cb.cascade_for(agent("a"), "t", sink=chain, completer=c, shield=allow,
                       air_gapped=broken, capability_token="cap", track_id="t")
    assert r["air_gapped"] and PROXY not in c.urls()


def test_air_gapped_with_only_cloud_is_loud():
    cb.write_config(cloud_url="https://cloud.example/v1", cloud_model="big")
    r = cb.cascade_for(agent("a"), "t", air_gapped=lambda s: True)
    assert r["ok"] is False and r["air_gapped"] and r["cloud_tiers_withheld"] == 1
    assert "air-gapped" in r["error"] and "LOCAL model" in r["advice"]


def test_missing_or_failing_sink_is_reported(scripted):
    cb.write_config(local_url=LOCAL, local_model="m")
    r = cb.cascade_for(agent("a"), "t", completer=scripted({LOCAL: ["x"]}))
    assert r["audit_id"] is None and r["audit_dropped"] == "no record sink configured"

    class Broken:
        def append(self, record):
            raise OSError("disk full")

    r = cb.cascade_for(agent("a"), "t", sink=Broken(), completer=scripted({LOCAL: ["x"]}))
    assert r["audit_id"] is None and "disk full" in r["audit_dropped"]


def test_requires_a_subject_not_a_path(tmp_path):
    with pytest.raises(TypeError):
        cb.cascade_for(str(tmp_path), "t")
    with pytest.raises(TypeError):
        cb.cascade_for(Path(tmp_path), "t")


def test_no_workspace_or_folder_key():
    for fn in (cb.cascade_for, cb.tiers, cb.write_config, cb.local_tiers):
        assert not {p for p in inspect.signature(fn).parameters
                    if re.search(r"folder|workspace|path|dir", p)}
    src = Path(cb.__file__).read_text()
    assert not re.search(r"folder|workspace", src, re.IGNORECASE)
    assert "subject" in inspect.signature(cb.cascade_for).parameters
