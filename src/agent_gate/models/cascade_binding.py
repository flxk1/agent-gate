from __future__ import annotations

import hashlib
import json
import os
import warnings
from copy import deepcopy
from pathlib import Path
from typing import Any, Callable, Optional
from urllib.parse import parse_qsl, urlsplit

from agent_gate.ports import RecordSink
from agent_gate.subject import Subject

from . import local_llm, models_registry
from .cascade import Shield, Tier, Verifier, default_shield, nonempty_verifier, run_cascade

LOCAL_URL_ENV = local_llm.URL_ENV
LOCAL_MODEL_ENV = local_llm.MODEL_ENV
CLOUD_URL_ENV = "AGENT_GATE_CLOUD_LLM_URL"
CLOUD_MODEL_ENV = "AGENT_GATE_CLOUD_LLM_MODEL"
CLOUD_PRICE_ENV = "AGENT_GATE_CLOUD_PRICE_PER_1K"
EGRESS_PROXY_ENV = "AGENT_GATE_EGRESS_PROXY_URL"
CONFIG_PATH_ENV = "AGENT_GATE_MODELS_CONFIG"

DEFAULT_EGRESS_PROXY = "http://127.0.0.1:8443/v1"
DEFAULT_CLOUD_PRICE = 0.30
RECORD_KIND = "model_cascade"

AirGap = Callable[[Subject], bool]

_SENSITIVE_QUERY_KEYS = frozenset({
    "api_key", "apikey", "key", "token", "access_token", "secret", "password", "authorization",
})


def config_path() -> Path:
    override = os.environ.get(CONFIG_PATH_ENV, "").strip()
    if override:
        return Path(override).expanduser()
    base = os.environ.get("XDG_CONFIG_HOME", "").strip()
    root = Path(base).expanduser() if base else Path.home() / ".config"
    return root / "agent-gate" / "models.json"


def _sanitise(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        return {}
    cfg = deepcopy(raw)
    cloud = cfg.get("cloud")
    if isinstance(cloud, dict):
        cloud.pop("api_key", None)
    return cfg


def load_config() -> dict[str, Any]:
    p = config_path()
    try:
        return _sanitise(json.loads(p.read_text())) if p.exists() else {}
    except Exception:  # noqa: BLE001
        return {}


def _validate_endpoint_url(value: str, field: str) -> None:
    if not value:
        return
    parsed = urlsplit(value)
    if parsed.username is not None or parsed.password is not None:
        raise ValueError(f"{field} must not contain embedded credentials")
    keys = {k.lower() for k, _ in parse_qsl(parsed.query, keep_blank_values=True)}
    if keys & _SENSITIVE_QUERY_KEYS:
        raise ValueError(f"{field} must not contain credential query parameters")


def write_config(*, local_url: str = "", local_model: str = "",
                 local_models: list[dict[str, Any]] | None = None,
                 cloud_url: str = "", cloud_model: str = "", cloud_api_key: str = "",
                 cloud_price_per_1k: float | None = None, merge: bool = True) -> Path:
    _validate_endpoint_url(local_url, "local_url")
    _validate_endpoint_url(cloud_url, "cloud_url")
    for e in local_models or []:
        if isinstance(e, dict):
            _validate_endpoint_url(str(e.get("url", "")), "local_models[].url")
    if cloud_api_key:
        warnings.warn("cloud_api_key is deprecated and ignored; bind a credential "
                      "reference to the egress track", DeprecationWarning, stacklevel=2)
    cfg: dict[str, Any] = load_config() if merge else {}
    if local_models is not None:
        cfg["local"] = [e for e in local_models if isinstance(e, dict) and e.get("model")]
    else:
        local = dict(cfg["local"]) if isinstance(cfg.get("local"), dict) else {}
        if local_url:
            local["url"] = local_url
        if local_model:
            local["model"] = local_model
        if local:
            cfg["local"] = local
    cloud = dict(cfg.get("cloud") or {})
    if cloud_url:
        cloud["url"] = cloud_url
    if cloud_model:
        cloud["model"] = cloud_model
    if cloud_price_per_1k is not None:
        cloud["price_per_1k"] = cloud_price_per_1k
    if cloud:
        cfg["cloud"] = cloud
    p = config_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(cfg, indent=2) + "\n")
    try:
        p.chmod(0o600)
    except OSError:
        pass
    return p


def _label(model: str) -> str:
    name = Path(model).name if "/" in model else model
    return name[:-5] if name.endswith(".gguf") else name


def local_tiers(cfg: dict[str, Any]) -> list[Tier]:
    env_url = os.environ.get(LOCAL_URL_ENV, "").strip()
    if env_url:
        env_model = os.environ.get(LOCAL_MODEL_ENV, "").strip()
        if not env_model:
            env_model = next(iter(models_registry.models_for_role(models_registry.DEFAULT_ROLE)), "")
        if env_model:
            return [Tier(name="local", url=env_url, model=env_model)]
    raw = cfg.get("local")
    if isinstance(raw, dict):
        entries = [raw]
    elif isinstance(raw, list):
        entries = [e for e in raw if isinstance(e, dict)]
    else:
        entries = []
    usable = [(str(e.get("url", "")).strip(), str(e.get("model", "")).strip()) for e in entries]
    usable = [(u, m) for u, m in usable if m and u.lower().startswith(("http://", "https://"))]
    return [Tier(name="local" if len(usable) == 1 else f"local-{_label(m) or i + 1}", url=u, model=m)
            for i, (u, m) in enumerate(usable)]


def tiers(*, capability_token: str = "", track_id: str = "") -> list[Tier]:
    cfg = load_config()
    out = local_tiers(cfg)
    cfg_cloud = cfg.get("cloud") if isinstance(cfg.get("cloud"), dict) else {}
    cu = os.environ.get(CLOUD_URL_ENV, "").strip() or str(cfg_cloud.get("url", "")).strip()
    cm = os.environ.get(CLOUD_MODEL_ENV, "").strip() or str(cfg_cloud.get("model", "")).strip()
    if cu and cm:
        try:
            price = float(os.environ.get(CLOUD_PRICE_ENV, "")
                          or cfg_cloud.get("price_per_1k", DEFAULT_CLOUD_PRICE))
        except (TypeError, ValueError):
            price = DEFAULT_CLOUD_PRICE
        out.append(Tier(name="cloud", url=cu, model=cm, is_cloud=True, price_per_1k=price,
                        proxy_url=os.environ.get(EGRESS_PROXY_ENV, DEFAULT_EGRESS_PROXY).strip(),
                        capability_token=capability_token, track_id=track_id))
    return out


def _is_air_gapped(subject: Subject, air_gapped: Optional[AirGap]) -> bool:
    if air_gapped is None:
        return False
    try:
        return bool(air_gapped(subject))
    except Exception:  # noqa: BLE001
        return True


def _digest(record: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(record, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def cascade_for(
    subject: Subject,
    prompt: str,
    *,
    sink: Optional[RecordSink] = None,
    air_gapped: Optional[AirGap] = None,
    verifier: Verifier = nonempty_verifier,
    shield: Shield = default_shield,
    completer: Optional[Callable[..., dict[str, Any]]] = None,
    max_tokens: int = 512,
    temperature: float = 0.0,
    capability_token: str = "",
    track_id: str = "",
) -> dict[str, Any]:
    if not isinstance(subject, Subject):
        raise TypeError("cascade_for requires an agent_gate.subject.Subject")
    all_tiers = tiers(capability_token=capability_token, track_id=track_id)
    gapped = _is_air_gapped(subject, air_gapped)
    run_tiers = [t for t in all_tiers if not t.is_cloud] if gapped else all_tiers
    withheld = len(all_tiers) - len(run_tiers)
    base = {"subject": str(subject), "air_gapped": gapped, "cloud_tiers_withheld": withheld,
            "config_path": str(config_path())}

    if not run_tiers:
        if gapped:
            note = (f"the {withheld} configured cloud rung(s) were withheld" if withheld
                    else "no cloud rung is configured (and none could be used anyway)")
            return {"ok": False, "served_is_cloud": False, "tiers": 0,
                    "error": "air-gapped: cloud egress is forbidden for this subject "
                             "and no local model tier is configured",
                    "advice": (f"{subject} is air-gapped: {note}. Configure a LOCAL model "
                               f"({LOCAL_URL_ENV} + {LOCAL_MODEL_ENV}, or write_config) "
                               f"or lift the air-gap for this subject."),
                    **base}
        return {"ok": False, "served_is_cloud": False, "tiers": 0,
                "error": "no model tier configured",
                "advice": (f"set {LOCAL_URL_ENV} + {LOCAL_MODEL_ENV} or write_config(...) "
                           f"for a local rung; {CLOUD_URL_ENV} + {CLOUD_MODEL_ENV} plus a "
                           f"capability token and egress track for a cloud rung."),
                **base}

    kw: dict[str, Any] = {"verifier": verifier, "shield": shield,
                          "max_tokens": max_tokens, "temperature": temperature}
    if completer is not None:
        kw["completer"] = completer
    res = run_cascade(prompt, run_tiers, **kw)

    record = {"kind": RECORD_KIND, "subject": str(subject),
              "prompt_sha256": hashlib.sha256((prompt or "").encode("utf-8")).hexdigest(),
              "served_by": res.served_by, "served_is_cloud": res.served_is_cloud,
              "ok": res.ok, "escalation_withheld": res.escalation_withheld,
              "air_gapped": gapped, "cloud_tiers_withheld": withheld,
              "attempts": [{"tier": a.tier, "is_cloud": a.is_cloud, "ran": a.ran,
                            "accepted": a.accepted} for a in res.attempts]}
    out = res.to_dict()
    out.update(base)
    out["audit_id"] = None
    if sink is None:
        out["audit_dropped"] = "no record sink configured"
    else:
        try:
            sink.append(record)
            out["audit_id"] = _digest(record)
        except Exception as exc:  # noqa: BLE001
            out["audit_dropped"] = f"{type(exc).__name__}: {exc}"
    return out
