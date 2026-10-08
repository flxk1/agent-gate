from __future__ import annotations

import pytest

from agent_gate.models import cascade
from agent_gate.models.cascade import Tier, nonempty_verifier, run_cascade

LOCAL = "http://127.0.0.1:1111/v1"
LOCAL2 = "http://127.0.0.1:2222/v1"
PROXY = "http://127.0.0.1:8443/v1"


def allow(prompt):
    return "allow", prompt


def local(url=LOCAL, name="local"):
    return Tier(name, url, "phi-3.5-mini", price_per_1k=0.0)


def cloud(price=3.0):
    return Tier("cloud", "https://cloud.example/v1", "big-cloud", is_cloud=True,
                price_per_1k=price, proxy_url=PROXY, capability_token="cap-token",
                track_id="cloud-primary")


def test_local_accept_never_calls_cloud(scripted):
    c = scripted({LOCAL: ["LOCAL ANSWER"], PROXY: ["CLOUD"]})
    r = run_cascade("classify this", [local(), cloud()], shield=allow, completer=c)
    assert r.ok and r.served_by == "local" and not r.served_is_cloud
    assert c.urls() == [LOCAL]
    led = r.ledger()
    assert led["accepted_locally"] is True
    assert led["escalated_to_cloud"] is False
    assert led["agent_tokens_offloaded_to_local"] == 40
    assert [a.note for a in r.attempts] == ["", "unreached"]


def test_local_defer_escalates_through_egress_proxy(scripted):
    c = scripted({LOCAL: [""], PROXY: ["CLOUD ANSWER"]})
    r = run_cascade("hard task", [local(), cloud()], shield=allow, completer=c)
    assert r.ok and r.served_by == "cloud" and r.served_is_cloud
    hop = c.calls[-1]
    assert hop["url"] == PROXY and hop["api_key"] == "" and hop["prompt"] == "hard task"
    assert hop["headers"] == {cascade.UPSTREAM_HEADER: "cloud.example",
                              cascade.TRACK_HEADER: "cloud-primary",
                              cascade.CAPABILITY_HEADER: "cap-token"}
    led = r.ledger()
    assert led["local_deferrals"] == 1 and led["escalated_to_cloud"] and not led["accepted_locally"]


def test_ordered_local_fallback_before_cloud(scripted):
    c = scripted({LOCAL: [""], LOCAL2: ["N2 ANSWER"]})
    r = run_cascade("task", [local(LOCAL, "local-n1"), local(LOCAL2, "local-n2"), cloud()],
                    shield=allow, completer=c)
    assert r.served_by == "local-n2" and not r.served_is_cloud
    assert PROXY not in c.urls()
    assert [a.tier for a in r.attempts if a.ran] == ["local-n1", "local-n2"]


def test_shield_refusal_blocks_cloud(scripted):
    c = scripted({LOCAL: [""]})
    r = run_cascade("contains a secret", [local(), cloud()],
                    shield=lambda p: ("refuse", ""), completer=c)
    assert PROXY not in c.urls()
    assert r.escalation_withheld is True and r.served_by == "local"
    blocked = [a for a in r.attempts if a.tier == "cloud"][0]
    assert not blocked.ran and "shield refused" in blocked.reason


def test_shield_minimise_sends_redacted_text(scripted):
    c = scripted({LOCAL: [""], PROXY: ["ok"]})
    r = run_cascade("my IBAN is DE.. and name is X", [local(), cloud()],
                    shield=lambda p: ("minimise", "REDACTED prompt"), completer=c)
    assert r.served_is_cloud
    assert c.calls[-1]["prompt"] == "REDACTED prompt"


def test_shield_unavailable_fails_closed_unless_overridden(scripted):
    broken = lambda p: ("unavailable", "")  # noqa: E731
    c = scripted({LOCAL: ["", ""], PROXY: ["ok"]})
    r = run_cascade("task", [local(), cloud(0.0)], shield=broken, completer=c)
    assert PROXY not in c.urls() and r.escalation_withheld is True
    r2 = run_cascade("task", [local(), cloud(0.0)], shield=broken,
                     allow_unscreened_cloud=True, completer=c)
    assert r2.served_is_cloud and PROXY in c.urls()


def test_unknown_shield_action_refuses_cloud(scripted):
    c = scripted({LOCAL: [""], PROXY: ["ok"]})
    r = run_cascade("task", [local(), cloud()], shield=lambda p: ("maybe", p), completer=c)
    assert PROXY not in c.urls() and r.escalation_withheld


def test_default_shield_fails_closed_when_lock_errors(monkeypatch):
    import loomground_lock.lock_classify as lc

    def boom(*a, **k):
        raise RuntimeError("lock down")

    monkeypatch.setattr(lc, "_lock_string", boom)
    assert cascade.default_shield("anything") == ("unavailable", "")


@pytest.mark.parametrize("decision,expected", [
    ({"action": "allow"}, ("allow", "p")),
    ({"action": "minimise", "text": "m"}, ("minimise", "m")),
    ({"action": "refuse"}, ("refuse", "")),
    ({}, ("refuse", "")),
])
def test_default_shield_maps_lock_decisions(monkeypatch, decision, expected):
    import loomground_lock.lock_classify as lc
    monkeypatch.setattr(lc, "_lock_string", lambda text, context="": decision)
    assert cascade.default_shield("p") == expected


def test_unconfigured_cloud_withholds_escalation(scripted):
    c = scripted({LOCAL: [""]})
    bare = Tier("cloud", "https://cloud.example/v1", "big", is_cloud=True, price_per_1k=3.0)
    r = run_cascade("task", [local(), bare], shield=allow, completer=c)
    assert r.escalation_withheld and r.served_by == "local" and "escalate manually" in r.error
    att = [a for a in r.attempts if a.tier == "cloud"][0]
    assert not att.ran and att.reason == "not configured"


def test_tier_error_is_recorded_and_skipped(scripted):
    c = scripted({LOCAL: ["__error__"], PROXY: ["ok"]})
    r = run_cascade("task", [local(), cloud()], shield=allow, completer=c)
    assert r.served_by == "cloud"
    loc = [a for a in r.attempts if a.tier == "local"][0]
    assert loc.ran and not loc.accepted and "HTTP 500" in loc.reason


def test_all_tiers_reject(scripted):
    c = scripted({LOCAL: ["I cannot help"], PROXY: [""]})
    r = run_cascade("task", [local(), cloud()], shield=allow, completer=c)
    assert not r.ok and not r.escalation_withheld
    assert r.error == "all tiers ran and none passed the verifier"


def test_ledger_reports_saving_with_quality_signal(scripted):
    c = scripted({LOCAL: ["answer"]})
    led = run_cascade("t", [local(), cloud()], shield=allow, completer=c).ledger()
    assert led["actual_cost"] == 0.0 and led["cloud_only_cost_estimate"] > 0.0
    assert led["estimated_saving"] == led["cloud_only_cost_estimate"]
    for k in ("tiers_run", "local_deferrals", "escalated_to_cloud", "accepted_locally"):
        assert k in led


def test_deferral_frontier_over_a_labelled_set(scripted):
    gold = [f"ANS{i}" for i in range(10)]
    local_replies = [f"ANS{i}" for i in range(7)] + ["WRONG", "", ""]
    served_local = served_cloud = false_accept = 0
    for i in range(10):
        c = scripted({LOCAL: [local_replies[i]], PROXY: [gold[i]]})

        def gold_verifier(prompt, response, _g=gold[i]):
            ok = response.strip() == _g
            return ok, "matches gold" if ok else "differs from gold", 1.0 if ok else 0.0

        r = run_cascade(f"task {i}", [local(), cloud()], verifier=gold_verifier,
                        shield=allow, completer=c)
        if r.served_is_cloud:
            served_cloud += 1
        else:
            served_local += 1
            false_accept += r.response.strip() != gold[i]
    assert (served_local, served_cloud, false_accept) == (7, 3, 0)


def test_nonempty_verifier():
    assert nonempty_verifier("p", "  ")[0] is False
    assert nonempty_verifier("p", "As an AI I won't")[0] is False
    assert nonempty_verifier("p", "42")[0] is True


def test_cascade_sends_the_header_the_proxy_reads():
    assert cascade.CAPABILITY_HEADER == "X-Agent-Gate-Capability"
