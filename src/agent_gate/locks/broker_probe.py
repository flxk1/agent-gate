from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any, Optional

_HEALTH_PATH = "/__lock_health__"
_DEFAULT_PORT = 8443


def probe_broker(subject: str, *, proxy_url: Optional[str] = None,
                 timeout: float = 1.5) -> dict[str, Any]:
    if proxy_url is None:
        port = os.environ.get("AGENT_GATE_PROXY_PORT", "") or _DEFAULT_PORT
        proxy_url = f"http://127.0.0.1:{port}"
    try:
        with urllib.request.urlopen(proxy_url.rstrip("/") + _HEALTH_PATH,
                                    timeout=timeout) as resp:
            health = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, OSError, ValueError):
        return {"reachable": False, "bound_here": False}
    bound_here = (bool(health.get("broker_bound"))
                 and health.get("broker_subject") == subject)
    return {"reachable": True, "bound_here": bound_here}
