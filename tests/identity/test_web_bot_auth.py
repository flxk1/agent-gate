import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_gate.identity import agent_keys as ak
from agent_gate.identity import web_bot_auth as wba


def _register(root):
    key = Ed25519PrivateKey.generate()
    pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    rec = ak.register_agent_key("agent-a", pem, root=root)
    return key, rec["keyid"]


def test_sign_then_verify_roundtrip(tmp_path):
    root = str(tmp_path)
    key, keyid = _register(root)
    ctx = wba.RequestContext(authority="example.com", method="GET", path="/x")
    now = int(time.time())
    headers = wba.sign(key, agent="agent-a", keyid=keyid, covered=("@authority", "@method", "@path"),
                       ctx=ctx, created=now, expires=now + 60)
    v = wba.verify(headers, ctx=ctx, key_lookup=lambda kid: ak.get_agent_key(kid, root=root))
    assert v.verified
    assert v.agent == "agent-a"


def test_tampered_signature_fails(tmp_path):
    root = str(tmp_path)
    key, keyid = _register(root)
    ctx = wba.RequestContext(authority="example.com", method="GET", path="/x")
    now = int(time.time())
    headers = wba.sign(key, agent="agent-a", keyid=keyid, covered=("@authority",),
                       ctx=ctx, created=now)
    other_ctx = wba.RequestContext(authority="evil.com", method="GET", path="/x")
    v = wba.verify(headers, ctx=other_ctx, key_lookup=lambda kid: ak.get_agent_key(kid, root=root))
    assert not v.verified


def test_expired_signature_fails(tmp_path):
    root = str(tmp_path)
    key, keyid = _register(root)
    ctx = wba.RequestContext(authority="example.com", method="GET", path="/x")
    now = int(time.time()) - 10_000
    headers = wba.sign(key, agent="agent-a", keyid=keyid, covered=("@authority",),
                       ctx=ctx, created=now)
    v = wba.verify(headers, ctx=ctx, key_lookup=lambda kid: ak.get_agent_key(kid, root=root))
    assert not v.verified
    assert "old" in v.reason or "expired" in v.reason


def test_revoked_key_fails_verify(tmp_path):
    root = str(tmp_path)
    key, keyid = _register(root)
    ak.revoke_agent_key(keyid, root=root)
    ctx = wba.RequestContext(authority="example.com", method="GET", path="/x")
    now = int(time.time())
    headers = wba.sign(key, agent="agent-a", keyid=keyid, covered=("@authority",),
                       ctx=ctx, created=now)
    v = wba.verify(headers, ctx=ctx, key_lookup=lambda kid: ak.get_agent_key(kid, root=root))
    assert not v.verified


def test_missing_headers_fail_closed():
    v = wba.verify({}, ctx=wba.RequestContext())
    assert not v.verified
