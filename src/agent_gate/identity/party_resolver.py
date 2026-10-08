from __future__ import annotations

from typing import Any, Optional, Protocol, runtime_checkable

from ..ports import RecordSink
from . import parties as _local


@runtime_checkable
class PartyResolver(Protocol):

    def list_parties(self, log: RecordSink, kind: str = "",
                     competence: str = "", **verify_kwargs: Any) -> dict[str, Any]: ...

    def route_approvers(self, log: RecordSink, competence: str, **verify_kwargs: Any) -> dict[str, Any]: ...

    def resolve_competences(self, log: RecordSink, principal: str, **verify_kwargs: Any) -> list[str]: ...


class LocalPartyResolver:

    def list_parties(self, log, kind="", competence="", **verify_kwargs):
        return _local._list_parties_local(log, kind, competence, **verify_kwargs)

    def route_approvers(self, log, competence, **verify_kwargs):
        return _local._route_approvers_local(log, competence, **verify_kwargs)

    def resolve_competences(self, log, principal, **verify_kwargs):
        for r in self.list_parties(log, **verify_kwargs)["parties"]:
            if r.get("party_id") == principal and r.get("status") == "active":
                return list(r.get("competences") or [])
        return []


_ACTIVE: PartyResolver = LocalPartyResolver()


def get_resolver() -> PartyResolver:
    return _ACTIVE


def set_resolver(resolver: Optional[PartyResolver]) -> None:
    global _ACTIVE
    _ACTIVE = resolver if resolver is not None else LocalPartyResolver()
