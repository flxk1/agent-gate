from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urlparse

URL_ENV = "AGENT_GATE_LOCAL_LLM_URL"
MODEL_ENV = "AGENT_GATE_LOCAL_LLM_MODEL"
API_KEY_ENV = "AGENT_GATE_LOCAL_LLM_API_KEY"
TIMEOUT_ENV = "AGENT_GATE_LOCAL_LLM_TIMEOUT_SECS"

_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1", "[::1]"}


def _endpoint_url() -> str | None:
    return os.environ.get(URL_ENV)


def _default_model() -> str:
    return os.environ.get(MODEL_ENV, "")


def _api_key() -> str:
    return os.environ.get(API_KEY_ENV, "")


def timeout_secs(default: float = 30.0) -> float:
    try:
        return float(os.environ.get(TIMEOUT_ENV, str(default)))
    except ValueError:
        return default


def _host_only(url: str) -> str:
    try:
        return urlparse(url).hostname or url
    except Exception:
        return url


def _is_secure_or_loopback(url: str) -> bool:
    try:
        p = urlparse(url)
    except Exception:
        return False
    if (p.scheme or "").lower() == "https":
        return True
    return (p.hostname or "").lower() in _LOOPBACK_HOSTS


def _post_json(url: str, body: dict, headers: dict, timeout: float) -> dict:
    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json", **headers},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _get_json(url: str, headers: dict, timeout: float) -> dict:
    req = urllib.request.Request(url, headers=headers, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def complete_via(
    url: str,
    model_id: str,
    prompt: str,
    *,
    api_key: str = "",
    temperature: float = 0.0,
    max_tokens: int = 512,
    timeout: float | None = None,
    extra_headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    if api_key and not _is_secure_or_loopback(url):
        return {"ok": False,
                "error": ("refusing to send an API key over a non-HTTPS endpoint "
                          f"({_host_only(url)}) - use an https:// URL"),
                "endpoint_host": _host_only(url)}
    headers = dict(extra_headers or {})
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    body = {
        "model": model_id,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    started = time.time()
    try:
        result = _post_json(url.rstrip("/") + "/chat/completions", body, headers,
                            timeout if timeout is not None else timeout_secs())
        elapsed_ms = int((time.time() - started) * 1000)
    except urllib.error.HTTPError as e:
        return {"ok": False, "error": f"LLM HTTP {e.code}: {e.reason}",
                "endpoint_host": _host_only(url)}
    except urllib.error.URLError as e:
        return {"ok": False, "error": f"LLM unreachable: {e.reason}",
                "endpoint_host": _host_only(url)}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"LLM call failed: {type(e).__name__}: {e}",
                "endpoint_host": _host_only(url)}
    try:
        response_text = result["choices"][0]["message"]["content"]
        model_used = result.get("model", model_id)
    except (KeyError, IndexError, TypeError) as e:
        return {"ok": False,
                "error": f"unexpected response shape: {type(e).__name__}: {e}",
                "endpoint_host": _host_only(url),
                "raw_response": str(result)[:500]}
    return {"ok": True, "response": response_text, "model_used": model_used,
            "latency_ms": elapsed_ms, "endpoint_host": _host_only(url),
            "usage": result.get("usage", {})}


def complete(prompt: str, model: str | None = None, temperature: float = 0.0,
             max_tokens: int = 512) -> dict[str, Any]:
    url = _endpoint_url()
    if not url:
        return {"ok": False,
                "error": (f"no local-LLM endpoint configured. Set {URL_ENV} to an "
                          "OpenAI-compatible URL (e.g. http://localhost:1234/v1).")}
    model_id = model or _default_model()
    if not model_id:
        return {"ok": False,
                "error": f"no model configured. Set {MODEL_ENV} or pass model=.",
                "endpoint_host": _host_only(url)}
    return complete_via(url, model_id, prompt, api_key=_api_key(),
                        temperature=temperature, max_tokens=max_tokens)


def classify(text: str, categories: list[str], model: str | None = None) -> dict[str, Any]:
    cat_list = ", ".join(f'"{c}"' for c in categories)
    prompt = (f"Classify the following text into exactly one of these categories: "
              f"{cat_list}.\n\nReturn ONLY the category name, nothing else.\n\n"
              f"Text: {text!r}\n\nCategory:")
    result = complete(prompt, model=model, temperature=0.0, max_tokens=64)
    if not result.get("ok"):
        return result
    raw = result["response"].strip().strip('"').strip("'")
    chosen = next((c for c in categories if c.lower() == raw.lower()), None)
    if chosen is None:
        chosen = next((c for c in categories if c.lower() in raw.lower()), None)
    return {"ok": True, "category": chosen, "raw_response": raw,
            "model_used": result.get("model_used"),
            "latency_ms": result.get("latency_ms"),
            "endpoint_host": result.get("endpoint_host")}


def resolve_models_for_role(role: str) -> list[str]:
    from . import models_registry
    return models_registry.models_for_role(role)


def list_available() -> dict[str, Any]:
    url = _endpoint_url()
    if not url:
        return {"ok": False, "error": f"no local-LLM endpoint configured ({URL_ENV})",
                "reachable": False}
    api_key = _api_key()
    headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
    if api_key and not _is_secure_or_loopback(url):
        return {"ok": False, "endpoint": _host_only(url), "reachable": False,
                "error": "refusing to send an API key over a non-HTTPS endpoint"}
    try:
        result = _get_json(url.rstrip("/") + "/models", headers, timeout_secs())
    except urllib.error.URLError as e:
        return {"ok": False, "endpoint": _host_only(url),
                "error": f"unreachable: {e.reason}", "reachable": False}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "endpoint": _host_only(url),
                "error": f"{type(e).__name__}: {e}", "reachable": False}
    models = [m.get("id") for m in result.get("data", []) if m.get("id")]
    return {"ok": True, "endpoint": _host_only(url), "models": models, "reachable": True}
