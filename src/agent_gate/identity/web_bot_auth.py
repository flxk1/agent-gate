from __future__ import annotations

import base64
import re
import time
from dataclasses import dataclass, field
from typing import Callable, Mapping, Optional, Sequence

ALG = "ed25519"
DEFAULT_TAG = "web-bot-auth"
DEFAULT_MAX_AGE = 300.0
DEFAULT_MAX_SKEW = 60.0


@dataclass
class RequestContext:
    authority: str = ""
    method: str = ""
    path: str = ""
    target_uri: str = ""
    headers: Mapping[str, str] = field(default_factory=dict)


@dataclass
class Verdict:
    verified: bool
    agent: Optional[str] = None
    keyid: Optional[str] = None
    reason: str = ""


def _component_value(name: str, ctx: RequestContext) -> Optional[str]:
    n = name.lower()
    if n == "@authority":
        return (ctx.authority or "").lower() or None
    if n == "@method":
        return (ctx.method or "").upper() or None
    if n == "@path":
        return ctx.path or None
    if n == "@target-uri":
        return ctx.target_uri or None
    if n.startswith("@"):
        return None
    value = ctx.headers.get(n)
    return value.strip() if isinstance(value, str) else None


def build_signature_base(covered: Sequence[str], sig_params: str,
                         ctx: RequestContext) -> bytes:
    lines = []
    for comp in covered:
        val = _component_value(comp, ctx)
        if val is None:
            raise ValueError(f"cannot resolve covered component {comp!r}")
        lines.append(f'"{comp}": {val}')
    lines.append(f'"@signature-params": {sig_params}')
    return "\n".join(lines).encode("utf-8")


_LABEL_RE = re.compile(r"^\s*([A-Za-z0-9_-]+)\s*=\s*(.*)$", re.DOTALL)
_LIST_RE = re.compile(r"^\s*\(([^)]*)\)(.*)$", re.DOTALL)
_QUOTED_RE = re.compile(r'"([^"]*)"')


def _parse_params(s: str) -> dict:
    out: dict = {}
    for part in s.split(";"):
        part = part.strip()
        if not part:
            continue
        if "=" not in part:
            out[part] = True
            continue
        k, v = part.split("=", 1)
        k, v = k.strip(), v.strip()
        if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
            out[k] = v[1:-1]
        else:
            try:
                out[k] = int(v)
            except ValueError:
                out[k] = v
    return out


def parse_signature_input(value: str):
    m = _LABEL_RE.match(value.strip())
    if not m:
        raise ValueError("malformed Signature-Input")
    label, params_str = m.group(1), m.group(2).strip()
    lm = _LIST_RE.match(params_str)
    if not lm:
        raise ValueError("Signature-Input missing covered-component list")
    covered = _QUOTED_RE.findall(lm.group(1))
    params = _parse_params(lm.group(2))
    return label, covered, params, params_str


def parse_signature(value: str, label: str) -> Optional[bytes]:
    for item in value.split(","):
        m = re.match(r"^\s*([A-Za-z0-9_-]+)\s*=\s*:([^:]*):\s*$", item)
        if m and m.group(1) == label:
            try:
                return base64.b64decode(m.group(2))
            except Exception:
                return None
    return None


def _normalise_agent(value) -> Optional[str]:
    if not isinstance(value, str):
        return None
    return value.strip().strip('"').strip() or None


def _ed25519_verify(pem, data: bytes, sig: bytes) -> bool:
    try:
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        key = load_pem_public_key(pem.encode("utf-8") if isinstance(pem, str) else pem)
        key.verify(sig, data)
        return True
    except Exception:
        return False


def _default_key_lookup(keyid: str) -> Optional[dict]:
    from .agent_keys import get_agent_key
    return get_agent_key(keyid)


def sign(private_key, *, agent: str, keyid: str, covered: Sequence[str],
         ctx: RequestContext, created: int, expires: Optional[int] = None,
         tag: str = DEFAULT_TAG, label: str = "sig1") -> dict:
    covered_list = "(" + " ".join(f'"{c}"' for c in covered) + ")"
    params = [f"created={int(created)}"]
    if expires is not None:
        params.append(f"expires={int(expires)}")
    params += [f'keyid="{keyid}"', f'alg="{ALG}"', f'tag="{tag}"']
    params_str = covered_list + ";" + ";".join(params)
    base = build_signature_base(covered, params_str, ctx)
    signature = private_key.sign(base)
    sig_b64 = base64.b64encode(signature).decode("ascii")
    return {
        "Signature-Input": f"{label}={params_str}",
        "Signature": f"{label}=:{sig_b64}:",
        "Signature-Agent": f'"{agent}"',
    }


def verify(headers: Mapping[str, str], *, ctx: RequestContext,
           key_lookup: Optional[Callable[[str], Optional[dict]]] = None,
           now: Optional[float] = None,
           max_age: float = DEFAULT_MAX_AGE,
           max_skew: float = DEFAULT_MAX_SKEW,
           expected_agent: Optional[str] = None) -> Verdict:
    now = float(now if now is not None else time.time())
    h = {str(k).lower(): v for k, v in dict(headers).items()}
    try:
        si = h.get("signature-input")
        sig_field = h.get("signature")
        if not si or not sig_field:
            return Verdict(False, reason="missing Signature-Input or Signature")
        label, covered, params, params_str = parse_signature_input(si)

        if str(params.get("alg", ALG)).lower() != ALG:
            return Verdict(False, reason=f"unsupported alg {params.get('alg')!r}")
        keyid = params.get("keyid")
        if not keyid:
            return Verdict(False, reason="missing keyid")

        created, expires = params.get("created"), params.get("expires")
        if isinstance(created, int) and created - now > max_skew:
            return Verdict(False, reason="created is in the future")
        if isinstance(expires, int):
            if now > expires:
                return Verdict(False, reason="signature expired")
        elif isinstance(created, int):
            if now - created > max_age:
                return Verdict(False, reason="signature too old")

        rec = (key_lookup or _default_key_lookup)(str(keyid))
        if not rec:
            return Verdict(False, keyid=str(keyid),
                           reason="unknown, revoked, or expired keyid")
        agent = rec.get("agent")

        declared = (expected_agent if expected_agent is not None
                    else _normalise_agent(h.get("signature-agent")))
        if declared is not None and agent is not None and declared != agent:
            return Verdict(False, agent=agent, keyid=str(keyid),
                           reason="Signature-Agent does not match the key's agent")

        signature = parse_signature(sig_field, label)
        if signature is None:
            return Verdict(False, keyid=str(keyid), reason="malformed Signature")
        base = build_signature_base(covered, params_str, ctx)
        if not _ed25519_verify(rec.get("public_key_pem", ""), base, signature):
            return Verdict(False, agent=agent, keyid=str(keyid),
                           reason="signature did not verify")
        return Verdict(True, agent=agent, keyid=str(keyid), reason="ok")
    except Exception as exc:
        return Verdict(False, reason=f"verify error: {type(exc).__name__}")
