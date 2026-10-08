from __future__ import annotations

import base64
import hashlib
import json
from typing import Any, Callable, Optional

from ..ports import RecordSink

PREDICATE_TYPE = "https://loomground.org/attestations/GovernanceCertification/v1"
_INTOTO_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
_DSSE_PAYLOAD_TYPE = "application/vnd.in-toto+json"
ACTION_EVIDENCE_SCHEME = "https://loomground.org/grounding/action-evidence/v1"
DEFAULT_BASIS = "eu-ai-act-2024-1689-art-14"


def _sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _pae(payload_type: str, body: bytes) -> bytes:
    t = payload_type.encode("utf-8")
    return (b"DSSEv1 " + str(len(t)).encode() + b" " + t + b" "
            + str(len(body)).encode() + b" " + body)


def dsse_wrap(statement: dict, sign: Callable[[bytes], bytes], keyid: str) -> dict:
    body = json.dumps(statement, separators=(",", ":"), sort_keys=True).encode("utf-8")
    sig = sign(_pae(_DSSE_PAYLOAD_TYPE, body))
    return {
        "payloadType": _DSSE_PAYLOAD_TYPE,
        "payload": base64.b64encode(body).decode("ascii"),
        "signatures": [{"keyid": keyid, "sig": base64.b64encode(sig).decode("ascii")}],
    }


def _legitimate_anchors(marker: dict) -> list[dict]:
    anchors: list[dict] = [
        {"role": "oversight-obligation", "basis": marker.get("basis") or DEFAULT_BASIS},
        {"role": "effective-policy",
         "oversight_level": marker.get("oversight_level", ""),
         "grade": marker.get("grade", ""),
         "gate_verdict": marker.get("gate_verdict", "")},
    ]
    for op in marker.get("obligation_pairs") or []:
        anchors.append({"role": "policy-rule", "obligation_pair": str(op)})
    return anchors


def build_predicate(marker: dict) -> dict:
    evidence = marker.get("evidence") or []
    verdict = marker.get("verdict") or "hold-approved"
    overseen: dict[str, Any] = {
        "required": verdict != "permit",
        "qualifier": marker.get("qualification", "unspecified"),
    }
    if verdict != "permit":
        overseen["disposition"] = "DECIDED"
        overseen["oversight_certificate"] = {
            "embedded": False,
            "reason": "oversight-certificate sub-attestation not ported in this slice",
            "decision_ref": marker.get("dispatch_id", ""),
        }
    return {
        "verdict": verdict,
        "action_class": marker.get("action_class", ""),
        "issued_at": marker.get("at", ""),
        "enforced": {
            "mechanism": marker.get("mechanism", "claude-code:PreToolUse"),
            "blocked_unless_permitted": True,
            "decision_ref": marker.get("dispatch_id", ""),
        },
        "overseen": overseen,
        "grounded": {
            "scheme": ACTION_EVIDENCE_SCHEME,
            "ref": evidence,
            "digest": {"sha256": _sha256_hex(
                json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode("utf-8"))},
        },
        "intact": {
            "type": "native-chain",
            "log_id": marker.get("log_id", ""),
            "entry_ref": marker.get("dispatch_id", ""),
            "algorithm": "ed25519+sha256",
        },
        "legitimate": {
            "policy_fingerprint": marker.get("policy_digest", ""),
            "anchors": _legitimate_anchors(marker),
        },
    }


def mint_governance_certification(
    marker: dict, *, sign: Callable[[bytes], bytes], keyid: str,
) -> dict:
    predicate = build_predicate(marker)
    statement = {
        "_type": _INTOTO_STATEMENT_TYPE,
        "subject": [{"name": marker.get("action_class", "action"),
                     "digest": {"sha256": marker.get("action_digest", "")}}],
        "predicateType": PREDICATE_TYPE,
        "predicate": predicate,
    }
    return dsse_wrap(statement, sign, keyid)


def mint_and_record(
    marker: dict, *, sign: Callable[[bytes], bytes], keyid: str,
    chain: RecordSink, signer, actor: str = "system",
) -> dict:
    from . import chain_receipt

    envelope = mint_governance_certification(marker, sign=sign, keyid=keyid)
    chain_receipt.build_record(
        signer=signer, chain=chain, tool="agent_gate.records.governance_cert",
        payload={"kind": "governance-certification", "envelope": envelope,
                 "action_class": marker.get("action_class", "")},
        executor_id=actor, executor_role="system",
        dispatch_id=f"cert:{marker.get('dispatch_id', '')}" or None,
    )
    return envelope


def verify_sig_from_public_bytes(public_key_bytes: bytes) -> Callable[[bytes, bytes], bool]:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)

    def verify_sig(message: bytes, sig: bytes) -> bool:
        try:
            public_key.verify(sig, message)
            return True
        except InvalidSignature:
            return False

    return verify_sig


def verify_governance_certification(envelope: dict, *, verify_sig: Callable[[bytes, bytes], bool]) -> dict:
    try:
        from governance_certification import verify as _gcv
        return _gcv.verify(envelope, verify_sig=verify_sig)
    except ImportError:
        pass
    try:
        payload = base64.b64decode(envelope["payload"])
        pae = _pae(str(envelope.get("payloadType", _DSSE_PAYLOAD_TYPE)), payload)
        sig_ok = any(verify_sig(pae, base64.b64decode(s["sig"]))
                     for s in (envelope.get("signatures") or []))
        statement = json.loads(payload)
        predicate = statement.get("predicate") or {}
        findings: list[dict[str, str]] = []
        if statement.get("predicateType") != PREDICATE_TYPE:
            findings.append({"code": "wrong-predicate-type",
                             "detail": str(statement.get("predicateType"))})
        if (predicate.get("enforced") or {}).get("blocked_unless_permitted") is not True:
            findings.append({"code": "not-enforcement-bound",
                             "detail": "enforced.blocked_unless_permitted is not true"})
        if not sig_ok:
            findings.append({"code": "bad-signature", "detail": "DSSE signature did not verify"})
        return {"ok": sig_ok and not findings, "findings": findings, "statement": statement}
    except Exception as exc:
        return {"ok": False, "statement": None,
                "findings": [{"code": "verify-error", "detail": f"{type(exc).__name__}: {exc}"}]}
