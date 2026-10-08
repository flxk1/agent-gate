from __future__ import annotations

import contextlib
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

from a2a_compliance.wire import canonical
from a2a_compliance.wire.admission import Issuer
from a2a_compliance.wire.executor import ExecutionOutcome, ExecutorPort, consume_and_execute
from a2a_compliance.wire.trust import RevocationStore, TrustStore
from a2a_compliance.wire.verification import NonceStore

from ..ports import IdentityPort, RecordSink
from .verdict import Verdict

RECEIPT_TTL = timedelta(days=365)


class HostMediatedExecutor:

    def __init__(self, *, executor_id: str = "agent-gate:host", executor_role: str = "host") -> None:
        self.executor_id = executor_id
        self.executor_role = executor_role

    def execute(self, tool: str, arguments: dict) -> ExecutionOutcome:
        return ExecutionOutcome(
            effect={"mediated": True, "tool": tool},
            executor_id=self.executor_id, executor_role=self.executor_role,
        )


class _SessionTagged:
    def __init__(self, inner: ExecutorPort, session_id: str) -> None:
        self._inner, self._session_id = inner, session_id

    def execute(self, tool: str, arguments: dict) -> ExecutionOutcome:
        out = self._inner.execute(tool, arguments)
        return ExecutionOutcome(effect=out.effect, executor_id=f"{out.executor_id}:{self._session_id}",
                                executor_role=out.executor_role)


@dataclass(frozen=True)
class GateResult:
    verdict: Verdict
    receipt: dict
    reasons: tuple[str, ...] = ()


class Gate:

    def __init__(
        self,
        *,
        identity: IdentityPort,
        trust_store: TrustStore,
        nonce_store: NonceStore,
        executor: ExecutorPort,
        signer: Issuer,
        chain: RecordSink,
        revocation_store: Optional[RevocationStore] = None,
    ) -> None:
        self.identity = identity
        self.trust_store = trust_store
        self.nonce_store = nonce_store
        self.executor = executor
        self.signer = signer
        self.chain = chain
        self.revocation_store = revocation_store

    def _append_lock(self) -> contextlib.AbstractContextManager:
        get_lock = getattr(self.chain, "lock_for_append", None)
        return get_lock() if get_lock is not None else contextlib.nullcontext()

    def _prev_digest(self) -> Optional[str]:
        last = self.chain.tail()
        if isinstance(last, dict) and "receipt" in last:
            last = last["receipt"]
        return canonical.subject_digest(last) if last else None

    def _finalize(self, receipt: dict) -> dict:
        receipt = dict(receipt)
        prev = self._prev_digest()
        receipt.pop("prev_digest", None)
        if prev:
            receipt["prev_digest"] = prev
        receipt.pop("subject_digest", None)
        receipt.pop("signature", None)
        receipt["subject_digest"] = canonical.subject_digest(receipt)
        receipt["signature"] = self.signer.sign(receipt)
        return receipt

    def _refusal_skeleton(
        self, *, tool: str, arguments: dict, dispatch_id: str, run_id: str,
        action_digest: str, reasons: tuple[str, ...], now: datetime, session_id: str,
        kind: str = "gate",
    ) -> dict:
        return {
            "schema_version": "1.0.0",
            "type": "ToolReceipt",
            "issuer": self.signer.identity,
            "issued_at": now.isoformat(),
            "expires_at": (now + RECEIPT_TTL).isoformat(),
            "run_id": run_id,
            "nonce": f"{run_id}:refused:{uuid.uuid4().hex}",
            "key_id": self.signer.key_id,
            "tool": tool,
            "arguments_digest": canonical.digest_hex(arguments),
            "effect_digest": canonical.digest_hex({"refused": True, "reasons": list(reasons)}),
            "started_at": now.isoformat(),
            "ended_at": now.isoformat(),
            "executor": {"id": f"agent-gate:{kind}:{session_id}", "role": "gate"},
            "dispatch_id": dispatch_id,
            "action_digest": action_digest or canonical.digest_hex({"tool": tool, "arguments": arguments}),
        }

    def _append_refusal(
        self, *, tool: str, arguments: dict, dispatch_id: str, run_id: str,
        action_digest: str, reasons: tuple[str, ...], now: datetime, session_id: str,
        kind: str = "gate",
    ) -> dict:
        skeleton = self._refusal_skeleton(
            tool=tool, arguments=arguments, dispatch_id=dispatch_id, run_id=run_id,
            action_digest=action_digest, reasons=reasons, now=now, session_id=session_id, kind=kind,
        )
        with self._append_lock():
            receipt = self._finalize(skeleton)
            self.chain.append(receipt)
        return receipt

    def refuse(self, *, session_id: str, tool: str, arguments: dict, dispatch_id: str,
               reasons: tuple[str, ...], now: Optional[datetime] = None) -> GateResult:
        receipt = self._append_refusal(
            tool=tool, arguments=arguments, dispatch_id=dispatch_id, run_id=dispatch_id,
            action_digest="", reasons=reasons, now=now or datetime.now(timezone.utc),
            session_id=session_id, kind="refused",
        )
        return GateResult(Verdict.DENY, receipt, reasons)

    def call(
        self,
        *,
        session_id: str,
        tool: str,
        arguments: dict,
        permit: Optional[dict],
        dispatch_id: str,
        run_id: Optional[str] = None,
        now: Optional[datetime] = None,
    ) -> GateResult:
        now = now or datetime.now(timezone.utc)
        run_id = run_id or dispatch_id
        actor = self.identity.resolve(session_id)
        kind = "gate" if actor else "refused"

        if permit is None:
            reasons = ("no permit: holding, never allowing",)
            receipt = self._append_refusal(
                tool=tool, arguments=arguments, dispatch_id=dispatch_id,
                run_id=run_id, action_digest="", reasons=reasons, now=now, session_id=session_id, kind=kind,
            )
            return GateResult(Verdict.HOLD, receipt, reasons)

        permit_actor = (permit.get("constraints") or {}).get("actor")
        if not actor or not permit_actor or permit_actor != actor:
            if not actor:
                reasons = (f"session {session_id!r} is not bound to any identity",)
            elif not permit_actor:
                reasons = ("permit carries no constraints.actor",)
            else:
                reasons = (f"permit actor {permit_actor!r} does not match bound session actor {actor!r}",)
            receipt = self._append_refusal(
                tool=tool, arguments=arguments, dispatch_id=dispatch_id,
                run_id=permit.get("run_id") or run_id,
                action_digest=permit.get("action_digest", ""), reasons=reasons, now=now,
                session_id=session_id, kind=kind,
            )
            return GateResult(Verdict.DENY, receipt, reasons)

        result = consume_and_execute(
            permit, tool=tool, arguments=arguments,
            trust_store=self.trust_store, nonce_store=self.nonce_store,
            executor=_SessionTagged(self.executor, session_id), signer=self.signer, dispatch_id=dispatch_id,
            revocation_store=self.revocation_store, now=now,
        )
        if not result.ok:
            receipt = self._append_refusal(
                tool=tool, arguments=arguments, dispatch_id=dispatch_id,
                run_id=permit.get("run_id") or run_id,
                action_digest=permit.get("action_digest", ""), reasons=result.reasons, now=now,
                session_id=session_id, kind=kind,
            )
            return GateResult(Verdict.DENY, receipt, result.reasons)

        with self._append_lock():
            receipt = self._finalize(result.receipt)
            self.chain.append(receipt)
        return GateResult(Verdict.PERMIT, receipt, ())
