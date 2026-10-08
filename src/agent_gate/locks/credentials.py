from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from loomground_lock.credential_resolver import is_valid_ref, resolve_secret

from ..subject import Subject

FLOORS = ("permit", "hold", "deny")


@dataclass(frozen=True)
class Track:

    connector_id: str
    credential_ref: Optional[str] = None
    floor: str = "permit"

    def __post_init__(self) -> None:
        if self.floor not in FLOORS:
            raise ValueError(f"floor must be one of {FLOORS}, got {self.floor!r}")
        if self.credential_ref and not is_valid_ref(self.credential_ref):
            raise ValueError(
                "credential_ref must be a known-scheme reference "
                "(env:/keydir:/oidc:/spiffe:), never a raw secret")


class SubjectCredentialSource:

    def __init__(self) -> None:
        self._tracks: dict[tuple[str, str], Track] = {}

    def register(self, subject: Subject, track: Track) -> None:
        self._tracks[(str(subject), track.connector_id)] = track

    def lookup(self, subject: Subject, connector_id: str) -> Optional[Track]:
        return self._tracks.get((str(subject), connector_id))

    def get(self, name: str) -> Optional[str]:
        try:
            subject_key, connector_id = name.rsplit("|", 1)
        except ValueError:
            return None
        for (sk, cid), track in self._tracks.items():
            if sk == subject_key and cid == connector_id:
                return resolve_secret(track.credential_ref)
        return None
