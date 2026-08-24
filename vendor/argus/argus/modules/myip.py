"""Discover the machine's own public IP and (optionally) geolocate it."""
from __future__ import annotations

from typing import Optional

from ..config import Config
from ..utils import build_session
from . import ip_tracker

PROVIDERS = (
    "https://api.ipify.org?format=json",
    "https://ifconfig.co/json",
    "https://api64.ipify.org?format=json",
)


def my_ip(config: Optional[Config] = None, geolocate: bool = True) -> dict:
    config = config or Config.load()
    session = build_session(config)

    public_ip = None
    for url in PROVIDERS:
        try:
            resp = session.get(url, timeout=config.timeout)
            data = resp.json()
            public_ip = data.get("ip")
            if public_ip:
                break
        except Exception:  # pragma: no cover - network dependent
            continue

    if not public_ip:
        return {"error": "could not determine public IP from any provider"}

    result = {"public_ip": public_ip}
    if geolocate:
        geo = ip_tracker.lookup(public_ip, config)
        if "error" not in geo:
            result["geo"] = geo
    return result
