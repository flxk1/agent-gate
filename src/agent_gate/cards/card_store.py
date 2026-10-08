from __future__ import annotations

import re
from dataclasses import asdict
from typing import Any, Optional, Protocol

from a2a_compliance.wire.admission import Issuer
from loomground_vertical.subject_card import SubjectCard

from ..ports import RecordSink
from ..records import chain_receipt
from ..subject import Subject


class CardStore(Protocol):

    def get(self, key: str) -> Optional[dict[str, Any]]: ...

    def put(self, key: str, data: dict[str, Any]) -> None: ...

    def delete(self, key: str) -> None: ...

    def keys(self) -> list[str]: ...


class InMemoryCardStore:

    def __init__(self) -> None:
        self._data: dict[str, dict[str, Any]] = {}

    def get(self, key: str) -> Optional[dict[str, Any]]:
        v = self._data.get(key)
        return dict(v) if v is not None else None

    def put(self, key: str, data: dict[str, Any]) -> None:
        self._data[key] = dict(data)

    def delete(self, key: str) -> None:
        self._data.pop(key, None)

    def keys(self) -> list[str]:
        return sorted(self._data.keys())


def save_card(
    card: SubjectCard, subject: Subject, *, store: CardStore,
    chain: RecordSink, signer: Issuer, actor: str = "user",
    facets_written: Optional[list[str]] = None,
) -> dict[str, Any]:
    key = str(subject)
    store.put(key, asdict(card))
    envelope = chain_receipt.build_record(
        signer=signer, chain=chain, tool="agent_gate.card.save",
        payload={"kind": "fact-intake", "subject": key, "domain": card.domain,
                 "facets_written": facets_written or sorted(card.facets)},
        executor_id=actor, executor_role="user",
        dispatch_id=f"card:{key}",
    )
    return {"subject": key, "dispatch_id": envelope["receipt"]["dispatch_id"]}


def load_card(subject: Subject, *, store: CardStore) -> Optional[SubjectCard]:
    key = str(subject)
    data = store.get(key)
    if data is None:
        return None
    return SubjectCard(
        domain=data.get("domain", ""), facets=dict(data.get("facets") or {}),
        description=data.get("description", ""), notes=data.get("notes", ""),
        contact=data.get("contact", ""), attachments=list(data.get("attachments") or []),
        subject_id=data.get("subject_id", key),
    )


def list_cards(*, store: CardStore) -> list[str]:
    return store.keys()


_WORD_BOUNDARY = r"(?<![A-Za-z0-9]){}(?![A-Za-z0-9])"


def _contains_word_ci(haystack: str, needle: str) -> bool:
    if not needle:
        return False
    return re.search(_WORD_BOUNDARY.format(re.escape(needle)), haystack, re.I) is not None


def _count_ci(haystack: str, needle: str) -> int:
    if not needle:
        return 0
    return len(re.findall(re.escape(needle), haystack, re.I))


def _walk_strings(obj: Any) -> list[str]:
    if isinstance(obj, str):
        return [obj]
    if isinstance(obj, dict):
        out: list[str] = []
        for v in obj.values():
            out.extend(_walk_strings(v))
        return out
    if isinstance(obj, (list, tuple)):
        out = []
        for v in obj:
            out.extend(_walk_strings(v))
        return out
    return []


def _fields_to_scan(data: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in data.items() if k != "subject_id"}


def scan(subject_needle: str, *, store: CardStore) -> dict[str, Any]:
    needle = (subject_needle or "").strip()
    hits: dict[str, int] = {}
    identity: list[str] = []
    if not needle:
        return {"hits": hits, "identity": identity}
    for key in store.keys():
        data = store.get(key) or {}
        if _contains_word_ci(key, needle) or _contains_word_ci(str(data.get("subject_id", "")), needle):
            identity.append(key)
            continue
        n = sum(_count_ci(t, needle) for t in _walk_strings(_fields_to_scan(data)))
        if n:
            hits[key] = n
    return {"hits": hits, "identity": identity}


def redact(subject_needle: str, *, store: CardStore) -> dict[str, Any]:
    needle = (subject_needle or "").strip()
    if not needle:
        return {"ok": False, "error": "erasure subject must be non-empty"}
    redacted: dict[str, int] = {}
    deleted: list[str] = []
    for key in store.keys():
        data = store.get(key) or {}
        if _contains_word_ci(key, needle) or _contains_word_ci(str(data.get("subject_id", "")), needle):
            store.delete(key)
            deleted.append(key)
            continue
        body, n = _redact_value(_fields_to_scan(data), needle)
        if not n:
            continue
        if "subject_id" in data:
            body["subject_id"] = data["subject_id"]
        store.put(key, body)
        redacted[key] = n
    return {"ok": True, "redacted": redacted, "deleted": deleted}


def _redact_value(obj: Any, needle: str) -> tuple[Any, int]:
    if isinstance(obj, str):
        rx = re.compile(re.escape(needle), re.I)
        n = len(rx.findall(obj))
        return (rx.sub("[REDACTED]", obj) if n else obj), n
    if isinstance(obj, dict):
        total = 0
        out = {}
        for k, v in obj.items():
            rv, n = _redact_value(v, needle)
            out[k] = rv
            total += n
        return out, total
    if isinstance(obj, list):
        total = 0
        out = []
        for v in obj:
            rv, n = _redact_value(v, needle)
            out.append(rv)
            total += n
        return out, total
    return obj, 0
