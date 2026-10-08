from __future__ import annotations

import time
from datetime import datetime, timezone

from loomground_drift.breaker import BreakerState

from agent_gate.ops import guardian_watch
from agent_gate.records import chain_receipt


def _append(chain, signer, *, actor="actor-1", action_digest=None, cost_usd=0.0, now=None):
    dt = datetime.fromtimestamp(now, tz=timezone.utc) if now is not None else None
    return chain_receipt.build_record(
        signer=signer, chain=chain, tool="Bash", payload={"cost_usd": cost_usd},
        executor_id=actor, executor_role="agent", action_digest=action_digest, now=dt,
    )


def test_loop_rule_trips_the_breaker(chain, issuer, running_breaker, trust_store):
    for _ in range(4):
        _append(chain, issuer, action_digest="f" * 64)
    rule = guardian_watch.WatchRule("loop_guard", "loop", 2)
    status = guardian_watch.watch(chain, "actor-1", running_breaker, [rule], trust_store=trust_store)
    assert status.state is BreakerState.QUARANTINED
    assert any("loop_guard" in t for t in status.tripped)


def test_loop_rule_does_not_trip_on_distinct_calls(chain, issuer, running_breaker, trust_store):
    for i in range(4):
        _append(chain, issuer, action_digest=f"{i:064x}")
    rule = guardian_watch.WatchRule("loop_guard", "loop", 2)
    status = guardian_watch.watch(chain, "actor-1", running_breaker, [rule], trust_store=trust_store)
    assert status.state is BreakerState.RUNNING


def test_rate_rule_trips_the_breaker(chain, issuer, running_breaker, trust_store):
    now = time.time()
    for _ in range(5):
        _append(chain, issuer, now=now)
    rule = guardian_watch.WatchRule("rate_guard", "rate", 3, window_seconds=3600)
    status = guardian_watch.watch(chain, "actor-1", running_breaker, [rule], now=now, trust_store=trust_store)
    assert status.state is BreakerState.QUARANTINED
    assert any("rate_guard" in t for t in status.tripped)


def test_rate_rule_ignores_calls_outside_the_window(chain, issuer, running_breaker, trust_store):
    old = time.time() - 10_000
    for _ in range(5):
        _append(chain, issuer, now=old)
    rule = guardian_watch.WatchRule("rate_guard", "rate", 3, window_seconds=60)
    status = guardian_watch.watch(chain, "actor-1", running_breaker, [rule], now=time.time(), trust_store=trust_store)
    assert status.state is BreakerState.RUNNING


def test_budget_rule_trips_the_breaker(chain, issuer, running_breaker, trust_store):
    for _ in range(3):
        _append(chain, issuer, cost_usd=5.0)
    rule = guardian_watch.WatchRule("budget_guard", "budget", 10.0)
    status = guardian_watch.watch(chain, "actor-1", running_breaker, [rule], trust_store=trust_store)
    assert status.state is BreakerState.QUARANTINED


def test_metrics_are_keyed_per_actor(chain, issuer, running_breaker, trust_store):
    _append(chain, issuer, actor="actor-1", cost_usd=100.0)
    _append(chain, issuer, actor="actor-2", cost_usd=0.0)
    rule = guardian_watch.WatchRule("budget_guard", "budget", 10.0)
    status = guardian_watch.watch(chain, "actor-2", running_breaker, [rule], trust_store=trust_store)
    assert status.state is BreakerState.RUNNING


def test_unknown_watch_rule_kind_rejected():
    import pytest
    with pytest.raises(ValueError):
        guardian_watch.WatchRule("bad", "not-a-kind", 1)


def test_per_metric_functions_are_not_exported():
    assert not hasattr(guardian_watch, "rate_metric")
    assert not hasattr(guardian_watch, "loop_metric")
    assert not hasattr(guardian_watch, "budget_metric")
    assert "rate_metric" not in guardian_watch.__all__
    assert "loop_metric" not in guardian_watch.__all__
    assert "budget_metric" not in guardian_watch.__all__


def test_budget_rule_trips_on_an_appended_unsigned_entry(chain, issuer, running_breaker, trust_store):
    _append(chain, issuer, cost_usd=5.0)
    chain.append({"unsigned": True, "payload": {"cost_usd": 0.0}})
    rule = guardian_watch.WatchRule("budget_guard", "budget", 1000.0)
    status = guardian_watch.watch(chain, "actor-1", running_breaker, [rule], trust_store=trust_store)
    assert status.state is BreakerState.QUARANTINED
