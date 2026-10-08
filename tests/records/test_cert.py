from __future__ import annotations

import pytest

from agent_gate.records import cert, chain_receipt


def _ed25519_sign(private_key_bytes: bytes):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    return lambda data: key.sign(data)


MARKER = {
    "verdict": "hold-approved",
    "action_class": "export-personal-data",
    "action_digest": "a" * 64,
    "dispatch_id": "d-1",
    "at": "2026-10-07T00:00:00Z",
    "grounded": True,
    "obligation_pairs": ["gdpr:art-17"],
}


def test_mint_is_enforcement_bound_and_verifies(dev_keypair):
    private_key_bytes, public_key_bytes = dev_keypair
    sign = _ed25519_sign(private_key_bytes)
    envelope = cert.mint_governance_certification(MARKER, sign=sign, keyid="key-1")

    assert envelope["payloadType"] == "application/vnd.in-toto+json"
    verify_sig = cert.verify_sig_from_public_bytes(public_key_bytes)
    report = cert.verify_governance_certification(envelope, verify_sig=verify_sig)
    assert report["ok"], report["findings"]


def test_permit_verdict_requires_no_human_step(dev_keypair):
    private_key_bytes, _ = dev_keypair
    sign = _ed25519_sign(private_key_bytes)
    marker = {**MARKER, "verdict": "permit"}
    cert.mint_governance_certification(marker, sign=sign, keyid="key-1")
    predicate = cert.build_predicate(marker)
    assert predicate["overseen"]["required"] is False
    assert "disposition" not in predicate["overseen"]


def test_tampered_predicate_fails_verify(dev_keypair):
    import base64
    import json

    private_key_bytes, public_key_bytes = dev_keypair
    sign = _ed25519_sign(private_key_bytes)
    envelope = cert.mint_governance_certification(MARKER, sign=sign, keyid="key-1")

    payload = json.loads(base64.b64decode(envelope["payload"]))
    payload["predicate"]["enforced"]["blocked_unless_permitted"] = False
    tampered = dict(envelope)
    tampered["payload"] = base64.b64encode(
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).decode("ascii")
    verify_sig = cert.verify_sig_from_public_bytes(public_key_bytes)
    report = cert.verify_governance_certification(tampered, verify_sig=verify_sig)
    assert not report["ok"]
    codes = {f["code"] for f in report["findings"]}
    assert "not-enforcement-bound" in codes or "bad-signature" in codes


def test_wrong_key_fails_signature(dev_keypair):
    from a2a_compliance.wire.signing import generate_dev_keypair

    private_key_bytes, _ = dev_keypair
    _, other_public = generate_dev_keypair()
    sign = _ed25519_sign(private_key_bytes)
    envelope = cert.mint_governance_certification(MARKER, sign=sign, keyid="key-1")
    verify_sig = cert.verify_sig_from_public_bytes(other_public)
    report = cert.verify_governance_certification(envelope, verify_sig=verify_sig)
    assert not report["ok"]


def test_mint_and_record_appends_a_verifiable_chain_entry(chain, issuer, trust_store, dev_keypair):
    private_key_bytes, public_key_bytes = dev_keypair
    sign = _ed25519_sign(private_key_bytes)
    envelope = cert.mint_and_record(MARKER, sign=sign, keyid="key-1", chain=chain, signer=issuer)
    assert envelope["payloadType"] == "application/vnd.in-toto+json"
    result = chain_receipt.verify(chain, trust_store=trust_store)
    assert result.ok, result.errors
    assert chain_receipt.payloads(chain)[-1]["kind"] == "governance-certification"
