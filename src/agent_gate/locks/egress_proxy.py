from __future__ import annotations

import http.client
import ipaddress
import json
import os
import socket
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field, replace
from enum import IntEnum
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Optional

from loomground_lock.core import AuditLog, Finding, Mode, _redact_text_with_regex, lock_text

from ..ports import CAPABILITY_HEADER
from ..subject import Subject
from . import host_deps
from .credentials import SubjectCredentialSource


class OversightLevel(IntEnum):

    AUTONOMOUS = 1
    NOTIFY = 2
    REVIEW = 3
    APPROVE = 4
    SUPERVISED = 5
    MANUAL = 6

    @property
    def label(self) -> str:
        return self.name.lower()


_DEFAULT_PORT = 8443
_DEFAULT_OVERSIGHT = OversightLevel.APPROVE

_ALLOWED_UPSTREAMS = {
    "api.anthropic.com": "https://api.anthropic.com",
    "api.openai.com": "https://api.openai.com",
    "api.cohere.ai": "https://api.cohere.ai",
    "generativelanguage.googleapis.com": "https://generativelanguage.googleapis.com",
}

_CREDENTIAL_HEADERS = frozenset({"authorization", "x-api-key", "x-goog-api-key", "api-key"})
_UPSTREAM_CREDENTIALS = {
    "api.anthropic.com": frozenset({"x-api-key"}),
    "api.openai.com": frozenset({"authorization"}),
    "api.cohere.ai": frozenset({"authorization"}),
    "generativelanguage.googleapis.com": frozenset({"x-goog-api-key"}),
}
_UPSTREAM_INJECT = {
    "api.anthropic.com": ("x-api-key", "{secret}"),
    "api.openai.com": ("Authorization", "Bearer {secret}"),
    "api.cohere.ai": ("Authorization", "Bearer {secret}"),
    "generativelanguage.googleapis.com": ("x-goog-api-key", "{secret}"),
}


def _egress_timeout_secs() -> float:
    raw = os.environ.get("AGENT_GATE_EGRESS_TIMEOUT_SECS", "").strip()
    if not raw:
        return 60.0
    try:
        val = float(raw)
    except ValueError:
        return 60.0
    return val if val > 0 else 60.0


def _egress_max_concurrency() -> int:
    raw = os.environ.get("AGENT_GATE_EGRESS_MAX_CONCURRENCY", "").strip()
    if not raw:
        return 64
    try:
        val = int(raw)
    except ValueError:
        return 64
    return val if val > 0 else 64


def _credential_binding_violation(headers, upstream_host: str) -> Optional[str]:
    allowed = _UPSTREAM_CREDENTIALS.get(upstream_host, frozenset())
    for name in headers.keys():
        low = name.lower()
        if low in _CREDENTIAL_HEADERS and low not in allowed:
            return low
    return None


ApprovalCallback = Callable[["PendingRequest"], "ApprovalDecision"]


@dataclass
class ApprovalDecision:
    action: str
    modified_body: bytes | None = None
    reason: str = ""
    waived_findings: list[str] = field(default_factory=list)


@dataclass
class PendingRequest:
    request_id: str
    upstream_host: str
    method: str
    path: str
    body: bytes
    extracted_text: str
    findings: list[Finding]
    oversight: OversightLevel
    timestamp: float = field(default_factory=time.time)


@dataclass
class GateDecision:

    action: str
    findings: list[Finding] = field(default_factory=list)
    redacted_text: str | None = None
    reason: str = ""
    source: str = "cloud_llm_request"


def extract_prompt_text(host: str, body: bytes) -> str:
    try:
        payload = json.loads(body.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return ""

    parts: list[str] = []
    if isinstance(payload.get("prompt"), str):
        parts.append(payload["prompt"])
    elif isinstance(payload.get("prompt"), list):
        parts.extend(str(p) for p in payload["prompt"])

    parts.extend(_block_strings(payload.get("system")))

    messages = payload.get("messages") or []
    for msg in messages:
        parts.extend(_block_strings(msg.get("content")))

    return "\n\n".join(p for p in parts if p)


def _block_strings(node: Any) -> list[str]:
    out: list[str] = []
    if node is None:
        return out
    if isinstance(node, str):
        out.append(node)
        return out
    if isinstance(node, list):
        for b in node:
            out.extend(_block_strings(b))
        return out
    if isinstance(node, dict):
        if isinstance(node.get("text"), str):
            out.append(node["text"])
        if "content" in node:
            out.extend(_block_strings(node["content"]))
        if "input" in node:
            out.extend(_all_strings(node["input"]))
        src = node.get("source")
        if isinstance(src, dict) and isinstance(src.get("data"), str):
            mt = str(src.get("media_type", ""))
            if not mt or mt.startswith("text"):
                out.append(src["data"])
    return out


def _all_strings(obj: Any) -> list[str]:
    if isinstance(obj, str):
        return [obj]
    if isinstance(obj, list):
        return [s for x in obj for s in _all_strings(x)]
    if isinstance(obj, dict):
        return [s for v in obj.values() for s in _all_strings(v)]
    return []


def _translate(td, oversight: OversightLevel) -> GateDecision:
    if td.action in ("allow", "minimise"):
        return GateDecision(action=td.action, findings=td.findings,
                            redacted_text=td.redacted_text, reason=td.reason,
                            source=td.source)
    if oversight in (OversightLevel.APPROVE, OversightLevel.SUPERVISED, OversightLevel.MANUAL):
        return GateDecision(action="ask_user", findings=td.findings,
                            reason=td.reason, source=td.source)
    return GateDecision(action="refuse", findings=td.findings, reason=td.reason,
                        source=td.source)


def _egress_policy_enabled() -> bool:
    return os.environ.get("AGENT_GATE_EGRESS_POLICY", "").strip().lower() in (
        "1", "on", "true", "yes")


def _compose_policy_admit(decision: GateDecision, actor: str) -> GateDecision:
    host_deps.ensure_wired()
    if host_deps.policy_admit is None:
        return decision
    try:
        gov = host_deps.policy_admit(actor=actor, target_kind="egress.cloud-llm")
        light = gov.get("light")
    except Exception as exc:  # noqa: BLE001
        return replace(decision, action="refuse",
                       reason=(decision.reason + f" | policy unavailable: {type(exc).__name__}").strip(" |"))
    rank = {"allow": 0, "minimise": 1, "ask_user": 2, "refuse": 3}
    want = {"go": "allow", "ask": "ask_user", "block": "refuse"}.get(light)
    if want and rank.get(want, 0) > rank.get(decision.action, 0):
        extra = str(gov.get("reason") or "").strip()
        return replace(decision, action=want,
                      reason=(decision.reason + (f" | policy: {extra}" if extra else "")
                              ).strip(" |"))
    return decision


def gate_prompt(
    text: str,
    *,
    oversight: OversightLevel,
    audit: AuditLog | None = None,
    source: str = "cloud_llm_request",
    task_id: str | None = None,
    actor: str = "agent",
) -> GateDecision:
    try:
        td = lock_text(text, mode=Mode.STANDARD, audit=audit, source=source, task_id=task_id)
    except Exception as e:  # noqa: BLE001
        return GateDecision(action="refuse", reason=f"lock_text raised unexpectedly: {e}",
                            source=source)
    decision = _translate(td, oversight)
    if _egress_policy_enabled():
        decision = _compose_policy_admit(decision, actor)
    return decision


def redact_body_in_place(body: bytes, host: str) -> bytes:
    try:
        payload = json.loads(body.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return body

    def _redact_value(v):
        if isinstance(v, str):
            return _redact_text_with_regex(v)
        return v

    if isinstance(payload.get("prompt"), str):
        payload["prompt"] = _redact_value(payload["prompt"])
    elif isinstance(payload.get("prompt"), list):
        payload["prompt"] = [_redact_value(p) for p in payload["prompt"]]

    if "system" in payload:
        payload["system"] = _redact_block(payload["system"])

    messages = payload.get("messages") or []
    for msg in messages:
        if "content" in msg:
            msg["content"] = _redact_block(msg["content"])

    return json.dumps(payload).encode("utf-8")


def _redact_any(obj: Any) -> Any:
    if isinstance(obj, str):
        return _redact_text_with_regex(obj)
    if isinstance(obj, list):
        return [_redact_any(x) for x in obj]
    if isinstance(obj, dict):
        return {k: _redact_any(v) for k, v in obj.items()}
    return obj


def _redact_block(node: Any) -> Any:
    if isinstance(node, str):
        return _redact_text_with_regex(node)
    if isinstance(node, list):
        return [_redact_block(b) for b in node]
    if isinstance(node, dict):
        nb = dict(node)
        if isinstance(nb.get("text"), str):
            nb["text"] = _redact_text_with_regex(nb["text"])
        if "content" in nb:
            nb["content"] = _redact_block(nb["content"])
        if "input" in nb:
            nb["input"] = _redact_any(nb["input"])
        src = nb.get("source")
        if isinstance(src, dict) and isinstance(src.get("data"), str):
            mt = str(src.get("media_type", ""))
            if not mt or mt.startswith("text"):
                nb["source"] = {**src, "data": _redact_text_with_regex(src["data"])}
        return nb
    return node


def autonomous_callback(pending: PendingRequest) -> ApprovalDecision:
    return ApprovalDecision(action="allow", reason="oversight=autonomous (silent)")


def notify_callback(pending: PendingRequest) -> ApprovalDecision:
    return ApprovalDecision(action="allow", reason="oversight=notify (audit-logged)")


def block_on_findings_callback(pending: PendingRequest) -> ApprovalDecision:
    high = [f for f in pending.findings if f.severity == "high"]
    if high:
        return ApprovalDecision(action="block",
                                reason=f"oversight=strict and {len(high)} HIGH finding(s) present")
    return ApprovalDecision(action="allow", reason="no HIGH findings")


def interactive_callback_stdin(pending: PendingRequest) -> ApprovalDecision:
    print(f"\n-- outbound LLM request {pending.request_id} --")
    print(f"  upstream:   {pending.upstream_host}")
    print(f"  path:       {pending.path}")
    print(f"  bytes:      {len(pending.body)}")
    print(f"  findings:   {len(pending.findings)}")
    for i, f in enumerate(pending.findings, 1):
        marker = "H" if f.severity == "high" else "M" if f.severity == "medium" else "L"
        print(f"    [{i}] {marker} {f.severity.upper():6} tier={f.tier} {f.type}: {f.detail}")
    print("\n  Action? [a]llow once [A]llow always [s]ession [b]lock once [B]lock always [w]aive")
    print("  > ", end="", flush=True)
    try:
        raw = sys.stdin.readline().strip()
    except Exception:
        raw = ""

    if raw == "A":
        return ApprovalDecision(action="allow", reason="user allowed (remember always)",
                                waived_findings=["scope:always"])
    if raw == "B":
        return ApprovalDecision(action="block", reason="user blocked (remember always)",
                                waived_findings=["scope:always"])
    if raw.lower().startswith("s"):
        return ApprovalDecision(action="allow", reason="user allowed (remember session)",
                                waived_findings=["scope:session"])
    if raw.lower().startswith("a"):
        return ApprovalDecision(action="allow", reason="user allowed (once)")
    if raw.lower().startswith("w"):
        print("  Waiver reason: ", end="", flush=True)
        try:
            reason = sys.stdin.readline().strip()
        except Exception:
            reason = ""
        return ApprovalDecision(action="allow", reason=f"user waived: {reason}",
                                waived_findings=[f.detail for f in pending.findings])
    return ApprovalDecision(action="block", reason="user blocked (once)")


def make_default_callback(oversight: OversightLevel, *, allow_user_override: bool = True) -> ApprovalCallback:
    if oversight == OversightLevel.AUTONOMOUS:
        if not allow_user_override:
            return autonomous_callback
        return _conditional_interactive(threshold="high")
    if oversight == OversightLevel.NOTIFY:
        return notify_callback
    if oversight == OversightLevel.REVIEW:
        return notify_callback
    if oversight == OversightLevel.APPROVE:
        return _conditional_interactive(threshold="high")
    if oversight == OversightLevel.SUPERVISED:
        return interactive_callback_stdin
    return _block_all_callback


def _conditional_interactive(threshold: str) -> ApprovalCallback:
    severity_rank = {"low": 0, "medium": 1, "high": 2}

    def callback(pending: PendingRequest) -> ApprovalDecision:
        threshold_rank = severity_rank.get(threshold, 2)
        triggered = [f for f in pending.findings if severity_rank.get(f.severity, 0) >= threshold_rank]
        if not triggered:
            return ApprovalDecision(action="allow", reason=f"no findings >= {threshold}; auto-allowed")
        return interactive_callback_stdin(pending)

    return callback


def _block_all_callback(pending: PendingRequest) -> ApprovalDecision:
    return ApprovalDecision(action="block",
                            reason="oversight=manual (proxy never forwards; user executes manually)")


_AGENT_ID_HEADERS = ("Signature-Agent", "X-Lock-Agent")
_MAX_AGENT_ID = 128


def _sanitise_agent_id(raw: str) -> str:
    s = raw.strip().strip('"').strip()
    s = "".join(ch for ch in s if ch >= " " and ch != "\x7f")
    return " ".join(s.split())[:_MAX_AGENT_ID]


def request_agent_identity(headers, *, env_default: Optional[str] = None) -> str:
    try:
        for name in _AGENT_ID_HEADERS:
            raw = headers.get(name) if headers is not None else None
            if raw:
                ident = _sanitise_agent_id(raw)
                if ident:
                    return ident
    except Exception:  # noqa: BLE001
        pass
    env = (env_default if env_default is not None
           else os.environ.get("AGENT_GATE_AGENT", "")).strip()
    return env or "agent"


@dataclass
class AgentIdentity:
    actor: str
    verified: bool = False
    keyid: Optional[str] = None
    reason: str = ""


def resolve_agent_identity(headers, *, authority: str = "", method: str = "",
                           path: str = "", now: Optional[float] = None) -> AgentIdentity:
    declared = request_agent_identity(headers)
    try:
        h = {str(k).lower(): v for k, v in dict(headers).items()}
    except Exception:  # noqa: BLE001
        return AgentIdentity(declared, reason="declared (unreadable headers)")
    if not h.get("signature") or not h.get("signature-input"):
        return AgentIdentity(declared, reason="declared (no signature)")
    host_deps.ensure_wired()
    verifier = host_deps.verify_agent_identity
    if verifier is None:
        return AgentIdentity(declared, reason="declared (verifier not wired)")
    try:
        res = verifier(h, authority=authority, method=method, path=path,
                       expected_agent=declared, now=now) or {}
    except Exception:  # noqa: BLE001
        return AgentIdentity(declared, reason="declared (verify error)")
    if res.get("verified"):
        return AgentIdentity(actor=(res.get("agent") or declared), verified=True,
                             keyid=res.get("keyid"), reason="verified")
    return AgentIdentity(declared, verified=False, keyid=res.get("keyid"),
                         reason=f"declared ({res.get('reason') or 'unverified'})")


def _require_verified_egress() -> bool:
    return os.environ.get(
        "AGENT_GATE_REQUIRE_VERIFIED_EGRESS", "").strip().lower() in ("1", "on", "true", "yes")


class EgressProxy:

    def __init__(
        self,
        *,
        port: int | None = None,
        oversight: OversightLevel | None = None,
        approval_callback: ApprovalCallback | None = None,
        upstream_overrides: dict[str, str] | None = None,
        audit_log_path: str | None = None,
        track_subject: Subject | None = None,
        credentials: SubjectCredentialSource | None = None,
        capability_verifier: Any | None = None,
    ):
        self.port = port or int(os.environ.get("AGENT_GATE_PROXY_PORT", _DEFAULT_PORT))
        oversight_env = os.environ.get("AGENT_GATE_PROXY_OVERSIGHT", "")
        if oversight is None and oversight_env:
            try:
                oversight = OversightLevel[oversight_env.upper()]
            except KeyError:
                oversight = _DEFAULT_OVERSIGHT
        self.oversight = oversight or _DEFAULT_OVERSIGHT
        self.callback: ApprovalCallback = approval_callback or make_default_callback(self.oversight)
        self.allowed_upstreams = dict(_ALLOWED_UPSTREAMS)
        if upstream_overrides:
            self.allowed_upstreams.update(upstream_overrides)
        self.audit_log_path = audit_log_path or os.environ.get("AGENT_GATE_AUDIT_LOG", "")
        self.operator = os.environ.get("AGENT_GATE_DEFAULT_ACTOR", "").strip() or "egress-operator"

        self.track_subject = track_subject
        self.credentials = credentials if credentials is not None else SubjectCredentialSource()

        if capability_verifier is None:
            host_deps.ensure_wired()
            factory = host_deps.capability_verifier_factory
            if factory is None:
                raise RuntimeError("session capability verifier is not wired")
            capability_verifier = factory()
        self.capability_verifier = capability_verifier
        self._lock_audit = AuditLog(self.audit_log_path) if self.audit_log_path else None

        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

        self.max_concurrency = _egress_max_concurrency()
        self._inflight = threading.BoundedSemaphore(self.max_concurrency)

        self.stats = {
            "received": 0, "allowed": 0, "blocked": 0, "modified": 0,
            "user_approved": 0, "shed": 0, "errors": 0,
        }

    def start(self, *, host: str = "127.0.0.1") -> None:
        if self._server is not None:
            return
        handler = _make_handler(self)
        self._server = ThreadingHTTPServer((host, self.port), handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._server is None:
            return
        self._server.shutdown()
        self._server.server_close()
        self._server = None
        self._thread = None

    def audit_log(self, entry: dict) -> None:
        if not self.audit_log_path:
            return
        try:
            with open(self.audit_log_path, "a") as fh:
                fh.write(json.dumps(entry) + "\n")
        except OSError as exc:
            _report_audit_drop("egress_proxy.audit_log", exc,
                               path=str(self.audit_log_path), entry_kind=entry.get("kind"))

    def record_capability_refusal(self, reason: str, path: str) -> None:
        try:
            host_deps.ensure_wired()
            recorder = host_deps.record_capability_refusal
            if recorder is None:
                return
            recorder(reason=reason, path=path)
        except Exception:
            return


def _report_audit_drop(where: str, exc: BaseException, **context: Any) -> None:
    host_deps.ensure_wired()
    sink = host_deps.record_audit_drop
    if sink is not None:
        try:
            sink(where, exc, **context)
            return
        except Exception:  # noqa: BLE001
            pass
    print(f"[agent-gate] AUDIT WRITE DROPPED at {where}: {type(exc).__name__}: {exc}",
          file=sys.stderr, flush=True)


def _is_loopback_host(hostname: str) -> bool:
    h = (hostname or "").strip("[]").lower()
    if h == "localhost":
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_open = urllib.request.build_opener(_NoRedirect).open


def _capability_sink_is_safe(url: str) -> bool:
    parts = urllib.parse.urlsplit(url)
    if parts.scheme == "https":
        return True
    if parts.scheme == "http":
        return _is_loopback_host(parts.hostname or "")
    return False


def _upstream_request_url(base_url: str, request_target: str) -> str:
    if (not request_target.startswith("/")
            or request_target.startswith("//")
            or any(ch in request_target for ch in ("\r", "\n", "\x00"))):
        raise ValueError("request target must be an origin-form path")

    target = urllib.parse.urlsplit(request_target)
    if target.scheme or target.netloc or target.fragment:
        raise ValueError("request target may not select an authority or fragment")

    base = urllib.parse.urlsplit(base_url)
    if base.scheme not in ("http", "https") or not base.netloc:
        raise ValueError("configured upstream base URL is invalid")

    joined = urllib.parse.urljoin(base_url.rstrip("/") + "/", request_target)
    final = urllib.parse.urlsplit(joined)
    if (final.scheme, final.netloc) != (base.scheme, base.netloc):
        raise ValueError("request target changed the configured upstream authority")
    return joined


def _make_handler(proxy: EgressProxy):
    class EgressProxyHandler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            return

        def do_POST(self):
            self._handle_request()

        def do_GET(self):
            if self.path == "/__lock_health__":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({
                    "status": "ok",
                    "oversight": proxy.oversight.label,
                    "stats": proxy.stats,
                    "max_concurrency": proxy.max_concurrency,
                    "broker_bound": bool(proxy.track_subject),
                    "broker_subject": str(proxy.track_subject) if proxy.track_subject else None,
                }).encode("utf-8"))
                return
            self.send_error(405, "Use POST for LLM requests")

        def _handle_request(self):
            if not proxy._inflight.acquire(blocking=False):
                proxy.stats["shed"] += 1
                proxy.audit_log({
                    "kind": "proxy_shed", "ts": time.time(),
                    "reason": f"egress concurrency cap ({proxy.max_concurrency}) reached -- shedding load",
                    "path": self.path,
                })
                self.send_error(503, "egress proxy at capacity")
                return
            try:
                self._forward()
            finally:
                proxy._inflight.release()

        def _forward(self):
            proxy.stats["received"] += 1
            content_length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(content_length) if content_length > 0 else b""

            token = self.headers.get(CAPABILITY_HEADER, "")
            try:
                proxy.capability_verifier.verify(token)
            except Exception as exc:
                proxy.stats["blocked"] += 1
                proxy.record_capability_refusal(str(exc), self.path)
                proxy.audit_log({
                    "kind": "capability_refused", "ts": time.time(),
                    "reason": str(exc), "path": self.path,
                })
                self.send_error(403, f"session capability refused: {exc}")
                return

            upstream_host = (
                self.headers.get("X-Lock-Upstream")
                or self.headers.get("Host", "").split(":")[0]
                or "api.anthropic.com"
            )

            if upstream_host not in proxy.allowed_upstreams:
                proxy.stats["blocked"] += 1
                proxy.audit_log({
                    "kind": "proxy_block", "ts": time.time(),
                    "reason": f"upstream '{upstream_host}' not in allowlist",
                    "path": self.path,
                })
                self.send_error(403, f"upstream '{upstream_host}' not allowed by lock")
                return

            try:
                upstream_url = _upstream_request_url(proxy.allowed_upstreams[upstream_host], self.path)
            except ValueError as exc:
                proxy.stats["blocked"] += 1
                proxy.audit_log({"kind": "proxy_block", "ts": time.time(),
                                 "reason": str(exc), "path": self.path})
                self.send_error(403, "invalid request target")
                return

            if not _capability_sink_is_safe(upstream_url):
                proxy.stats["blocked"] += 1
                reason = (f"refusing to send session capability token to '{upstream_url}' "
                          "-- neither https nor loopback")
                proxy.record_capability_refusal(reason, self.path)
                proxy.audit_log({
                    "kind": "capability_refused", "ts": time.time(),
                    "reason": reason, "path": self.path,
                })
                self.send_error(403, reason)
                return

            binding = None
            if proxy.track_subject is not None:
                from .track_broker import TRACK_HEADER, TrackBinding, bind_track
                binding = bind_track(proxy.credentials, proxy.track_subject,
                                     self.headers.get(TRACK_HEADER))
                if binding.ok and upstream_host not in _UPSTREAM_INJECT:
                    binding = TrackBinding(
                        ok=False,
                        reason=f"upstream '{upstream_host}' has no credential injection "
                               "binding; cannot broker",
                        connector_id=binding.connector_id)
                if not binding.ok:
                    proxy.stats["blocked"] += 1
                    proxy.audit_log({
                        "kind": "proxy_block", "ts": time.time(),
                        "reason": binding.reason, "track": binding.connector_id,
                        "path": self.path,
                    })
                    self.send_error(403, f"egress refused: {binding.reason}")
                    return
            else:
                _bad_cred = _credential_binding_violation(self.headers, upstream_host)
                if _bad_cred is not None:
                    proxy.stats["blocked"] += 1
                    proxy.audit_log({
                        "kind": "proxy_block", "ts": time.time(),
                        "reason": f"credential header '{_bad_cred}' not valid for upstream "
                                  f"'{upstream_host}' -- refusing cross-provider key forward",
                        "path": self.path,
                    })
                    self.send_error(403, "credential does not match upstream (lock D4)")
                    return

            text = extract_prompt_text(upstream_host, body)
            request_id = f"req-{int(time.time()*1000)}-{proxy.stats['received']}"

            identity = resolve_agent_identity(
                self.headers, authority=self.headers.get("Host", ""),
                method=self.command, path=self.path)
            if self.headers.get("Signature-Input"):
                proxy.audit_log({
                    "kind": "agent_identity", "ts": time.time(),
                    "agent": identity.actor, "verified": identity.verified,
                    "keyid": identity.keyid, "reason": identity.reason, "path": self.path,
                })

            if _require_verified_egress() and not identity.verified:
                gate = GateDecision(
                    action="refuse",
                    reason=("verified agent identity required "
                            "(AGENT_GATE_REQUIRE_VERIFIED_EGRESS), but this request is "
                            f"{identity.reason}"),
                    source="cloud_llm_request")
            elif not text.strip() and len(body.strip()) > 2:
                gate = GateDecision(
                    action="refuse",
                    reason="cannot verify request content -- no scannable text in a "
                           "non-empty body (fail-closed)",
                    source="cloud_llm_request")
            else:
                gate = gate_prompt(text, oversight=proxy.oversight, audit=proxy._lock_audit,
                                   source="cloud_llm_request", task_id=request_id,
                                   actor=identity.actor)

            final_action = gate.action
            final_reason = gate.reason
            forward_body = body
            waived_findings: list[str] = []

            if gate.action == "minimise":
                forward_body = redact_body_in_place(body, upstream_host)
                proxy.stats["modified"] += 1
            elif gate.action == "ask_user":
                pending = PendingRequest(
                    request_id=request_id, upstream_host=upstream_host, method=self.command,
                    path=self.path, body=body, extracted_text=text, findings=gate.findings,
                    oversight=proxy.oversight)
                cb_decision = proxy.callback(pending)
                if cb_decision.action == "block":
                    final_action = "refuse"
                    final_reason = cb_decision.reason
                    waived_findings = cb_decision.waived_findings
                elif cb_decision.action == "modify":
                    final_action = "minimise"
                    final_reason = cb_decision.reason
                    forward_body = cb_decision.modified_body or body
                    proxy.stats["modified"] += 1
                else:
                    final_action = "allow"
                    final_reason = cb_decision.reason
                    proxy.stats["user_approved"] += 1
                    waived_findings = cb_decision.waived_findings

            if (binding is not None and binding.hold
                    and gate.action != "ask_user"
                    and final_action in ("allow", "minimise")):
                pending = PendingRequest(
                    request_id=request_id, upstream_host=upstream_host, method=self.command,
                    path=self.path, body=forward_body, extracted_text=text,
                    findings=gate.findings, oversight=proxy.oversight)
                cb_decision = proxy.callback(pending)
                if cb_decision.action == "block":
                    final_action = "refuse"
                    final_reason = (cb_decision.reason
                                    or f"track '{binding.connector_id}' floor is hold -- blocked")
                elif cb_decision.action == "modify":
                    final_action = "minimise"
                    final_reason = cb_decision.reason
                    forward_body = cb_decision.modified_body or forward_body
                    proxy.stats["modified"] += 1
                else:
                    final_reason = (cb_decision.reason
                                    or f"track '{binding.connector_id}' floor is hold -- approved")
                    proxy.stats["user_approved"] += 1

            _legacy_action_map = {"allow": "allow", "minimise": "modify", "refuse": "block"}
            audit_entry = {
                "kind": "proxy_decision", "ts": time.time(), "request_id": request_id,
                "upstream": upstream_host, "path": self.path, "bytes_in": len(body),
                "text_length": len(text),
                "findings_count": len(gate.findings),
                "findings_summary": [
                    {"tier": f.tier, "severity": f.severity, "type": f.type, "field": f.field}
                    for f in gate.findings],
                "oversight": proxy.oversight.label,
                "action": _legacy_action_map.get(final_action, final_action),
                "gate_action": gate.action, "final_action": final_action, "reason": final_reason,
                "waived_findings": waived_findings,
            }
            if binding is not None:
                audit_entry["track"] = binding.connector_id
                audit_entry["credential_ref"] = binding.credential_ref
                audit_entry["track_floor"] = binding.floor
                audit_entry["mode"] = "brokered"
            proxy.audit_log(audit_entry)

            if final_action == "refuse":
                proxy.stats["blocked"] += 1
                self.send_response(403)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({
                    "error": "blocked by agent-gate", "request_id": request_id,
                    "reason": final_reason, "findings": audit_entry["findings_summary"],
                }).encode("utf-8"))
                return

            if final_action == "allow":
                proxy.stats["allowed"] += 1

            try:
                req = urllib.request.Request(upstream_url, data=forward_body, method=self.command)
                _hop_by_hop = {"host", "x-lock-upstream", "content-length", "connection",
                               "transfer-encoding", "signature-agent", "x-lock-agent",
                               CAPABILITY_HEADER.lower()}
                if binding is not None:
                    _hop_by_hop = _hop_by_hop | {"x-lock-track"} | _CREDENTIAL_HEADERS
                for k, v in self.headers.items():
                    if k.lower() not in _hop_by_hop:
                        req.add_header(k, v)
                if binding is not None:
                    _hdr, _tpl = _UPSTREAM_INJECT[upstream_host]
                    req.add_header(_hdr, _tpl.format(secret=binding.secret))
                req.add_header("Content-Length", str(len(forward_body)))
                with _open(req, timeout=_egress_timeout_secs()) as resp:
                    self.send_response(resp.status)
                    for k, v in resp.headers.items():
                        if k.lower() not in _hop_by_hop:
                            self.send_header(k, v)
                    self.end_headers()
                    self.wfile.write(resp.read())
            except urllib.error.HTTPError as e:
                self.send_response(e.code)
                self.end_headers()
                self.wfile.write(e.read())
            except (urllib.error.URLError, OSError, socket.timeout,
                    http.client.HTTPException) as e:
                proxy.stats["errors"] += 1
                self.send_error(502, f"upstream error: {e}")

    return EgressProxyHandler


def main(argv: list[str] | None = None) -> int:
    import argparse
    parser = argparse.ArgumentParser(prog="agent-gate proxy")
    parser.add_argument("--port", type=int, default=_DEFAULT_PORT)
    parser.add_argument("--oversight", default=os.environ.get("AGENT_GATE_PROXY_OVERSIGHT", "approve"),
                        choices=["autonomous", "notify", "review", "approve", "supervised", "manual"])
    parser.add_argument("--audit-log", default=os.environ.get("AGENT_GATE_AUDIT_LOG", ""))
    args = parser.parse_args(argv)

    proxy = EgressProxy(port=args.port, oversight=OversightLevel[args.oversight.upper()],
                        audit_log_path=args.audit_log)
    proxy.start()

    print("-- agent-gate egress proxy --")
    print(f"  listening:  http://127.0.0.1:{args.port}")
    print(f"  oversight:  {proxy.oversight.label} (level {proxy.oversight.value})")
    print(f"  upstreams:  {sorted(proxy.allowed_upstreams.keys())}")
    print(f"  audit log:  {args.audit_log or '(not set -- pass --audit-log)'}")
    print("  Ctrl+C to stop.")

    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        print("\n  stopping...")
        proxy.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
