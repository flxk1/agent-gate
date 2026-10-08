from __future__ import annotations

import pytest

from agent_gate.models import model_capability as mc
from agent_gate.models import models_registry as mr
from agent_gate.models.models_registry import ModelEntry


def test_capable_model_runs_local():
    big = mc.infer_profile("qwen-32b", params_billions=32)
    m = mc.match("extraction", big)
    assert big.tier == "large" and m.capable and m.action == "run_local" and not m.missing


def test_too_small_model_degrades_not_hallucinates():
    m = mc.match("extraction", mc.infer_profile("phi-mini", params_billions=1.5))
    assert not m.capable and m.action == "deterministic" and "json" in m.missing


def test_interpretation_escalates_to_human_on_medium():
    m = mc.match("interpretation", mc.infer_profile("mistral-7b", params_billions=7))
    assert not m.capable and m.action == "escalate_human"


def test_no_model_degrades():
    m = mc.match("privacy_semantic", None)
    assert not m.capable and m.action == "deterministic" and m.model_id is None


def test_every_task_has_a_named_degrade():
    for req in mc.TASKS.values():
        assert req.on_miss in mc.DEGRADES and req.requires <= set(mc.CAPS)


def test_unknown_task_is_a_value_error():
    with pytest.raises(ValueError):
        mc.match("nope", None)
    with pytest.raises(ValueError):
        mc.select("nope", [])


def test_select_picks_best_capable_else_degrades():
    small = mc.infer_profile("phi-mini", params_billions=1.5)
    big = mc.infer_profile("qwen-32b", params_billions=32)
    assert mc.select("extraction", [small, big]).model_id == "qwen-32b"
    assert mc.select("ask_routing", [small]).action == "run_local"
    assert mc.select("interpretation", [small]).action == "escalate_human"
    assert mc.select("interpretation", iter([small])).action == "escalate_human"
    assert mc.select("interpretation", []).model_id is None


def test_probed_profile_preferred():
    inferred = mc.infer_profile("big-70b", params_billions=70)
    probed = mc.ModelProfile("probed-small", frozenset({"classification"}), "small", probed=True)
    assert mc.select("intake", [inferred, probed]).model_id == "probed-small"


def test_profile_from_registry_id_parses_size():
    assert mc.profile_from_registry_id("llama-3-8b-instruct").tier == "medium"
    assert mc.profile_from_registry_id("qwen2.5-32b").tier == "large"
    assert mc.profile_from_registry_id("phi-mini").tier == "small"


def test_for_task_reads_the_registry(monkeypatch):
    monkeypatch.setattr(mr, "list_models", lambda: [ModelEntry(id="qwen-32b")])
    assert mc.for_task("extraction").action == "run_local"
    monkeypatch.setattr(mr, "list_models", lambda: [ModelEntry(id="phi-2b")])
    assert mc.for_task("extraction").action == "deterministic"
    monkeypatch.setattr(mr, "list_models", lambda: [])
    assert mc.for_task("interpretation").action == "escalate_human"


def test_for_task_degrades_on_unreadable_registry():
    mr.registry_path().parent.mkdir(parents=True)
    mr.registry_path().write_text("{broken")
    m = mc.for_task("completion")
    assert not m.capable and m.action == "escalate_cloud"


def test_readiness_projection():
    mr.register_model("mistral-7b", "drafter")
    r = mc.readiness()
    assert r["version"] == "model_capability/v1"
    assert "extraction" in r["ready"] and "interpretation" in r["degraded"]
    assert set(r["tasks"]) == set(mc.TASKS)
