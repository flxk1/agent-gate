from __future__ import annotations

import pytest

from agent_gate.locks import disclosure as dz


def test_make_envelope_requires_a_party():
    with pytest.raises(ValueError):
        dz.make_envelope("hello", affected_parties=[])
    with pytest.raises(ValueError):
        dz.make_envelope("hello", affected_parties=["  "])


def test_envelope_marks_ai_origin_and_does_not_store_content():
    env = dz.make_envelope("the secret body", affected_parties=["bob"])
    d = env.to_dict()
    assert d["marking"]["ai_generated"] is True
    assert d["marking"]["profile"] == dz.MARKING_PROFILE
    assert "the secret body" not in repr(d)
    assert d["content_hash"].startswith("sha256:")


def test_envelope_verifies_and_detects_content_tamper():
    env = dz.make_envelope("approved text", affected_parties=["bob", "carol"])
    ok = dz.verify_envelope(env, content="approved text")
    assert ok["signature_ok"] and ok["content_ok"] and not ok["reasons"]
    bad = dz.verify_envelope(env, content="swapped text")
    assert bad["signature_ok"] and bad["content_ok"] is False


def test_signature_tamper_is_caught():
    env = dz.make_envelope("x", affected_parties=["bob"]).to_dict()
    env["affected_parties"] = ["mallory"]
    v = dz.verify_envelope(env, content="x")
    assert v["signature_ok"] is False


def test_verify_never_raises_on_garbage():
    assert dz.verify_envelope({}, content="x")["signature_ok"] is False
    assert dz.verify_envelope({"signature": "zz", "public_key_b64": "not-base64!!"})[
        "signature_ok"] is False


def test_stale_marking_profile_is_flagged():
    env = dz.make_envelope("x", affected_parties=["bob"]).to_dict()
    env["marking"]["profile"] = "some-old-profile"
    v = dz.verify_envelope(env, content="x")
    assert v["stale_profile"] is True
    assert any("not the current" in r for r in v["reasons"])


def test_current_profile_is_the_provisional_until_code_lands():
    assert dz.MARKING_PROFILE == dz.MARKING_PROFILE_PROVISIONAL


def test_two_envelopes_use_the_same_identity_key(tmp_path):
    root = str(tmp_path / "identity")
    a = dz.make_envelope("x", affected_parties=["bob"], root=root)
    b = dz.make_envelope("y", affected_parties=["carol"], root=root)
    assert a.originating_system == b.originating_system
