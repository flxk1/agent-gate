from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import Any, Optional

from a2a_compliance.wire.admission import Issuer
from loomground_lock import injection_scan as _lis

from ..gate.verdict import Verdict
from ..ports import RecordSink
from . import chain_receipt

TIER = "ingest-cyber"

_ACTIVE_TEXT: tuple[tuple[re.Pattern, str], ...] = (
    (re.compile(r"<script\b|javascript:|vbscript:", re.I), "embedded_script"),
    (re.compile(r"\b(?:Auto_?Open|Workbook_Open|Document_Open|AutoExec)\b"), "office_macro_autoexec"),
    (re.compile(r"powershell\s+-enc|cmd\.exe\s*/c|/bin/sh\s+-c|base64\s+-d", re.I), "shell_payload"),
)

_EXEC_MAGIC: tuple[tuple[bytes, str], ...] = (
    (b"MZ", "pe-executable"), (b"\x7fELF", "elf-executable"),
    (b"\xca\xfe\xba\xbe", "macho"), (b"\xcf\xfa\xed\xfe", "macho"),
    (b"#!", "script-shebang"),
)
_DOC_EXT = {".pdf", ".txt", ".md", ".csv", ".docx", ".xlsx", ".pptx", ".rtf", ".html", ".xml"}
_PDF_ACTIVE = (b"/JavaScript", b"/JS", b"/OpenAction", b"/Launch", b"/AA", b"/EmbeddedFile")
_OLE_MACRO = (b"vbaProject.bin", b"_VBA_PROJECT", b"Macros", b"AutoOpen")


@dataclass
class Threat:
    kind: str
    label: str
    severity: str
    detail: str
    confidence: float
    standard: str

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def scan_text(text: str) -> list[Threat]:
    if not text:
        return []
    out: list[Threat] = []
    for f in _lis.scan_text(text):
        detail = getattr(f, "detail", "") or ""
        m = re.search(r"'([^']+)'", detail)
        out.append(Threat("prompt_injection", m.group(1) if m else "prompt_injection",
                          getattr(f, "severity", "high") or "high", detail,
                          float(getattr(f, "confidence", 0.8) or 0.8), "OWASP-LLM01"))
    for rx, label in _ACTIVE_TEXT:
        if rx.search(text):
            out.append(Threat("active_content", label, "high",
                              f"active-content marker {label!r}", 0.85, "file-shape"))
    return out


def scan_bytes(data: bytes, filename: Optional[str] = None) -> list[Threat]:
    if not data:
        return []
    out: list[Threat] = []
    ext = ("." + filename.rsplit(".", 1)[-1].lower()) if filename and "." in filename else ""
    for magic, kind in _EXEC_MAGIC:
        if data.startswith(magic):
            masq = ext in _DOC_EXT
            out.append(Threat("malware", f"{kind}{'_masquerade' if masq else ''}", "high",
                              f"magic {magic!r} = {kind}" + (f" but extension {ext}" if masq else ""),
                              0.95, "file-shape"))
            return out
    if data[:5] == b"%PDF-" or ext == ".pdf":
        for marker in _PDF_ACTIVE:
            if marker in data:
                out.append(Threat("active_content", "pdf_active_content", "high",
                                  f"PDF active-content marker {marker.decode(errors='replace')!r}",
                                  0.8, "file-shape"))
                break
    if data[:4] == b"\xd0\xcf\x11\xe0" or (data[:2] == b"PK" and b"vbaProject.bin" in data):
        for marker in _OLE_MACRO:
            if marker in data:
                out.append(Threat("active_content", "office_macro", "high",
                                  f"Office macro marker {marker.decode(errors='replace')!r}",
                                  0.8, "file-shape"))
                break
    return out


@dataclass
class QuarantineVerdict:
    admission: str
    threats: list[dict[str, Any]]
    reason: str

    @property
    def quarantined(self) -> bool:
        return self.admission != Verdict.PERMIT.value

    def as_dict(self) -> dict[str, Any]:
        return {"admission": self.admission, "quarantined": self.quarantined,
                "threats": self.threats, "reason": self.reason}


def scan(*, text: Optional[str] = None, data: Optional[bytes] = None,
         filename: Optional[str] = None) -> QuarantineVerdict:
    threats: list[Threat] = []
    if text:
        threats += scan_text(text)
    if data:
        threats += scan_bytes(data, filename)
    if any(t.kind == "malware" for t in threats):
        adm, reason = Verdict.DENY.value, "executable/malware in an auto-input folder"
    elif any(t.severity == "high" for t in threats):
        adm, reason = Verdict.HOLD.value, "high-confidence injection/active-content -- quarantined for review"
    else:
        adm, reason = Verdict.PERMIT.value, ("advisory signals only" if threats else "no threat pattern matched")
    return QuarantineVerdict(adm, [t.as_dict() for t in threats], reason)


def record_hold(
    verdict: QuarantineVerdict, *, chain: RecordSink, signer: Issuer,
    candidate_ref: str, actor: str = "system",
) -> dict[str, Any]:
    payload = {"kind": "ingest-quarantine", "candidate_ref": candidate_ref, **verdict.as_dict()}
    return chain_receipt.build_record(
        signer=signer, chain=chain, tool="agent_gate.ingest.hold",
        payload=payload, executor_id=actor, executor_role="system",
        dispatch_id=f"quarantine:{candidate_ref}",
    )


def release(
    *, chain: RecordSink, signer: Issuer, held_dispatch_id: str,
    actor: str = "user", rationale: str = "",
) -> dict[str, Any]:
    if not rationale.strip():
        raise ValueError("releasing a quarantine hold requires a rationale")
    payload = {
        "kind": "QuarantineReleased",
        "released_dispatch_id": held_dispatch_id,
        "rationale": rationale,
    }
    return chain_receipt.build_record(
        signer=signer, chain=chain, tool="agent_gate.ingest.release",
        payload=payload, executor_id=actor, executor_role="human",
        dispatch_id=f"quarantine:released:{held_dispatch_id[:40]}",
    )


def release_status(chain: RecordSink, held_dispatch_id: str, **verify_kwargs: Any) -> bool:
    for entry in chain_receipt.verified_entries(chain, **verify_kwargs):
        payload = entry.get("payload", {}) or {}
        if payload.get("kind") == "QuarantineReleased" and payload.get("released_dispatch_id") == held_dispatch_id:
            return True
    return False
