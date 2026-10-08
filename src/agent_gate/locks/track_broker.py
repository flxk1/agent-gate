from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from ..subject import Subject
from .credentials import SubjectCredentialSource

TRACK_HEADER = "X-Lock-Track"


@dataclass
class TrackBinding:

    ok: bool
    reason: str
    connector_id: Optional[str] = None
    credential_ref: Optional[str] = None
    floor: str = "permit"
    hold: bool = False
    secret: Optional[str] = field(default=None, repr=False)


def _refuse(reason: str, **kw) -> TrackBinding:
    return TrackBinding(ok=False, reason=reason, **kw)


def _display(cid: str) -> str:
    safe = "".join(ch if " " <= ch <= "~" else "?" for ch in cid)
    return safe[:64] + ("..." if len(safe) > 64 else "")


def bind_track(source: SubjectCredentialSource, subject: Subject,
               connector_id: Optional[str]) -> TrackBinding:
    cid = (connector_id or "").strip()
    if not cid:
        return _refuse(f"no track declared ({TRACK_HEADER} header required in broker mode)")

    disp = _display(cid)
    track = source.lookup(subject, cid)
    if track is None:
        return _refuse(f"unknown track '{disp}'", connector_id=cid)

    if track.floor == "deny":
        return _refuse(f"track '{disp}' floor is deny; egress barred",
                       connector_id=cid, floor=track.floor)

    if not (track.credential_ref or "").strip():
        return _refuse(f"track '{disp}' has no cable; cannot reach outside",
                       connector_id=cid, floor=track.floor)

    secret = source.get(f"{subject}|{cid}")
    if secret is None:
        return _refuse(f"track '{disp}' is unplugged; credential does not resolve",
                       connector_id=cid, credential_ref=track.credential_ref,
                       floor=track.floor)

    return TrackBinding(ok=True, reason="", connector_id=cid,
                        credential_ref=track.credential_ref, floor=track.floor,
                        hold=(track.floor == "hold"), secret=secret)
