from __future__ import annotations

from dataclasses import dataclass
from typing import Final

GLOBAL: Final = "global"
AGENT: Final = "agent"
SESSION: Final = "session"

KINDS: Final[frozenset[str]] = frozenset({GLOBAL, AGENT, SESSION})


@dataclass(frozen=True)
class Subject:

    kind: str
    id: str = ""

    def __post_init__(self) -> None:
        if self.kind not in KINDS:
            raise ValueError(f"unknown subject kind {self.kind!r}; expected one of {sorted(KINDS)}")
        if self.kind == GLOBAL and self.id:
            raise ValueError("the global subject carries no id")
        if self.kind != GLOBAL and not self.id:
            raise ValueError(f"a {self.kind} subject requires an id")

    def __str__(self) -> str:
        return self.kind if self.kind == GLOBAL else f"{self.kind}:{self.id}"


def global_subject() -> Subject:
    return Subject(GLOBAL)


def agent(uid: str) -> Subject:
    return Subject(AGENT, str(uid))


def session(sid: str) -> Subject:
    return Subject(SESSION, str(sid))
