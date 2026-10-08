from __future__ import annotations

import contextlib
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from a2a_compliance.wire import canonical
from a2a_compliance.wire.admission import Issuer
from a2a_compliance.wire.chain import ChainVerificationResult, verify_chain
from a2a_compliance.wire.trust import RevocationStore, TrustStore
from a2a_compliance.wire.verification import NonceStore

from ..ports import RecordSink

RECEIPT_TTL = timedelta(days=365)
GATE_EXECUTOR_PREFIX = "agent-gate:"


def build_record(
    *,
    signer: Issuer,
    chain: RecordSink,
    tool: str,
    payload: dict[str, Any],
    executor_id: str,
    executor_role: str,
    dispatch_id: Optional[str] = None,
    action_digest: Optional[str] = None,
    now: Optional[datetime] = None,
) -> dict[str, Any]:
    if str(executor_id).startswith(GATE_EXECUTOR_PREFIX):
        raise ValueError(f"executor id prefix {GATE_EXECUTOR_PREFIX!r} is reserved for gate receipts")
    now = now or datetime.now(timezone.utc)
    dispatch_id = dispatch_id or f"{tool}:{uuid.uuid4().hex}"
    payload_digest = canonical.digest_hex(payload)
    receipt: dict[str, Any] = {
        "schema_version": "1.0.0",
        "type": "ToolReceipt",
        "issuer": signer.identity,
        "issued_at": now.isoformat(),
        "expires_at": (now + RECEIPT_TTL).isoformat(),
        "run_id": dispatch_id,
        "nonce": f"{dispatch_id}:{uuid.uuid4().hex}",
        "key_id": signer.key_id,
        "tool": tool,
        "arguments_digest": payload_digest,
        "effect_digest": payload_digest,
        "started_at": now.isoformat(),
        "ended_at": now.isoformat(),
        "executor": {"id": executor_id, "role": executor_role},
        "dispatch_id": dispatch_id,
        "action_digest": action_digest or payload_digest,
    }

    def _finalize(last: Optional[dict]) -> dict:
        prev_receipt = last.get("receipt", last) if isinstance(last, dict) else None
        prev = canonical.subject_digest(prev_receipt) if prev_receipt else None
        rec = dict(receipt)
        if prev:
            rec["prev_digest"] = prev
        rec["subject_digest"] = canonical.subject_digest(rec)
        rec["signature"] = signer.sign(rec)
        return rec

    get_lock = getattr(chain, "lock_for_append", None)
    with (get_lock() if get_lock is not None else contextlib.nullcontext()):
        final = _finalize(chain.tail())
        envelope = {"receipt": final, "payload": dict(payload)}
        chain.append(envelope)
    return envelope


def receipts(chain: RecordSink) -> list[dict[str, Any]]:
    out = []
    for e in chain.all():
        out.append(e.get("receipt", e) if isinstance(e, dict) else e)
    return out


def payloads(chain: RecordSink) -> list[dict[str, Any]]:
    out = []
    for e in chain.all():
        out.append(e.get("payload", {}) if isinstance(e, dict) else {})
    return out


def entries(chain: RecordSink) -> list[dict[str, Any]]:
    out = []
    for e in chain.all():
        if isinstance(e, dict) and "receipt" in e:
            out.append(e)
        else:
            out.append({"receipt": e, "payload": {}})
    return out


def _is_gate_receipt(receipt: Any) -> bool:
    executor = receipt.get("executor") if isinstance(receipt, dict) else None
    return isinstance(executor, dict) and str(executor.get("id", "")).startswith(GATE_EXECUTOR_PREFIX)


def _payload_digest_ok(entry: Any) -> bool:
    if not isinstance(entry, dict):
        return False
    if "receipt" not in entry:
        return _is_gate_receipt(entry)
    receipt = entry.get("receipt")
    payload = entry.get("payload")
    if not isinstance(receipt, dict) or not isinstance(payload, dict):
        return False
    digest = canonical.digest_hex(payload)
    return receipt.get("arguments_digest") == digest


def verify(
    chain: RecordSink,
    *,
    nonce_store: Optional[NonceStore] = None,
    trust_store: Optional[TrustStore] = None,
    revocation_store: Optional[RevocationStore] = None,
    now: Optional[datetime] = None,
    genesis_prev_digest: Optional[str] = None,
) -> ChainVerificationResult:
    result = verify_chain(
        receipts(chain), "ToolReceipt",
        nonce_store=nonce_store, trust_store=trust_store,
        revocation_store=revocation_store, now=now,
        genesis_prev_digest=genesis_prev_digest,
    )
    errors = list(result.errors)
    ok = result.ok
    if trust_store is None:
        errors.append("no trust store: receipt signatures unchecked")
        ok = False
    for i, entry in enumerate(chain.all()):
        if not _payload_digest_ok(entry):
            errors.append(f"chain[{i}]: payload digest does not match the signed receipt")
            ok = False
    return ChainVerificationResult(ok, tuple(errors))


def verified_entries(
    chain: RecordSink,
    *,
    nonce_store: Optional[NonceStore] = None,
    trust_store: Optional[TrustStore] = None,
    revocation_store: Optional[RevocationStore] = None,
    now: Optional[datetime] = None,
    genesis_prev_digest: Optional[str] = None,
) -> list[dict[str, Any]]:
    result = verify(
        chain, nonce_store=nonce_store, trust_store=trust_store,
        revocation_store=revocation_store, now=now,
        genesis_prev_digest=genesis_prev_digest,
    )
    if not result.ok:
        return []
    return entries(chain)


def verified_payloads(chain: RecordSink, **kwargs: Any) -> list[dict[str, Any]]:
    return [e.get("payload", {}) for e in verified_entries(chain, **kwargs)]


def verified_receipts(chain: RecordSink, **kwargs: Any) -> list[dict[str, Any]]:
    return [e.get("receipt", {}) for e in verified_entries(chain, **kwargs)]
