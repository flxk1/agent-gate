from __future__ import annotations

import pytest

from agent_gate.gate import verdict as v
from agent_gate.gate.verdict import Verdict


def test_three_vocabularies_collapse_to_one_tristate():
    assert v.from_gate("GO") is v.from_light("go") is v.from_admission("admit") is Verdict.PERMIT
    assert v.from_gate("CONDITIONAL") is v.from_light("ask") is v.from_admission("hold") is Verdict.HOLD
    assert v.from_gate("NO-GO") is v.from_light("block") is v.from_admission("reject") is Verdict.DENY


def test_strictest_wins():
    assert v.strictest(Verdict.PERMIT, Verdict.HOLD) is Verdict.HOLD
    assert v.strictest(Verdict.HOLD, Verdict.DENY) is Verdict.DENY
    assert v.strictest(Verdict.PERMIT, Verdict.PERMIT) is Verdict.PERMIT
    assert v.strictest(Verdict.DENY, Verdict.PERMIT, Verdict.HOLD) is Verdict.DENY


def test_strictest_empty_is_permit():
    assert v.strictest() is Verdict.PERMIT
    assert v.strictest_of([]) is Verdict.PERMIT


@pytest.mark.parametrize("word", ["go", "ask", "block"])
def test_light_roundtrip(word):
    assert v.to_light(v.from_light(word)) == word


@pytest.mark.parametrize("word", ["GO", "CONDITIONAL", "NO-GO"])
def test_gate_roundtrip(word):
    assert v.to_gate(v.from_gate(word)) == word


@pytest.mark.parametrize("word", ["admit", "hold", "reject"])
def test_admission_roundtrip(word):
    assert v.to_admission(v.from_admission(word)) == word


def test_admission_unknown_defaults_to_hold():
    assert v.from_admission("mystery") is Verdict.HOLD


@pytest.mark.parametrize("s,expect", [
    (None, Verdict.PERMIT), ("", Verdict.PERMIT),
    ("GO", Verdict.PERMIT), ("NO-GO", Verdict.DENY),
    ("CONDITIONAL", Verdict.HOLD),
    ("garbage", Verdict.DENY), ("permitt", Verdict.DENY),
])
def test_from_gate_failsafe(s, expect):
    assert v.from_gate(s) is expect


@pytest.mark.parametrize("s,expect", [
    (None, Verdict.PERMIT), ("go", Verdict.PERMIT), ("block", Verdict.DENY),
    ("ask", Verdict.HOLD), ("nonsense", Verdict.DENY),
])
def test_from_light_failsafe(s, expect):
    assert v.from_light(s) is expect


def test_coerce_unknown_defaults_to_deny():
    assert v.coerce("garbage") is Verdict.DENY
    assert v.coerce(None) is Verdict.DENY
    assert v.coerce("permit") is Verdict.PERMIT
