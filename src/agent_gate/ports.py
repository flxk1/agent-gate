from __future__ import annotations

from typing import Optional, Protocol


class IdentityPort(Protocol):

    def bind(self, session_id: str) -> str:
        ...

    def resolve(self, session_id: str) -> Optional[str]:
        ...


class CredentialPort(Protocol):

    def get(self, name: str) -> Optional[str]:
        ...


class RecordSink(Protocol):

    def append(self, record: dict) -> None:
        ...

    def tail(self) -> Optional[dict]:
        ...

    def all(self) -> list[dict]:
        ...


CAPABILITY_HEADER = "X-Agent-Gate-Capability"
