"""IP geolocation lookup.

Features:
  * Uses HTTPS and a resilient session with retries.
  * Falls back to a second provider if the first fails.
  * Validates input and refuses obviously private/reserved addresses with a warning.
  * Returns a structured dict so results can be exported.
"""
from __future__ import annotations

from typing import Optional

from ..config import Config
from ..utils import build_session, is_public_ip, is_valid_ip

PRIMARY = "https://ipwho.is/{ip}"
FALLBACK = "http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,zip,lat,lon,timezone,isp,org,as,query"


def _from_ipwhois(data: dict) -> dict:
    conn = data.get("connection", {}) or {}
    return {
        "ip": data.get("ip"),
        "type": data.get("type"),
        "country": data.get("country"),
        "country_code": data.get("country_code"),
        "region": data.get("region"),
        "city": data.get("city"),
        "postal": data.get("postal"),
        "latitude": data.get("latitude"),
        "longitude": data.get("longitude"),
        "timezone": (data.get("timezone") or {}).get("id"),
        "utc_offset": (data.get("timezone") or {}).get("utc"),
        "isp": conn.get("isp"),
        "org": conn.get("org"),
        "asn": conn.get("asn"),
        "source": "ipwho.is",
    }


def _from_ipapi(data: dict) -> dict:
    return {
        "ip": data.get("query"),
        "type": None,
        "country": data.get("country"),
        "country_code": None,
        "region": data.get("regionName"),
        "city": data.get("city"),
        "postal": data.get("zip"),
        "latitude": data.get("lat"),
        "longitude": data.get("lon"),
        "timezone": data.get("timezone"),
        "utc_offset": None,
        "isp": data.get("isp"),
        "org": data.get("org"),
        "asn": data.get("as"),
        "source": "ip-api.com",
    }


def lookup(ip: str, config: Optional[Config] = None) -> dict:
    """Look up geolocation info for an IPv4/IPv6 address.

    Returns a dict with an ``error`` key on failure, otherwise a structured
    record including a ready-to-open Google Maps link.
    """
    config = config or Config.load()
    ip = ip.strip()

    if not is_valid_ip(ip):
        return {"error": f"'{ip}' is not a valid IP address", "ip": ip}

    warning = None
    if not is_public_ip(ip):
        warning = "This is a private / reserved address; geolocation will not be meaningful."

    session = build_session(config)

    result: Optional[dict] = None
    # Primary provider
    try:
        resp = session.get(PRIMARY.format(ip=ip), timeout=config.timeout)
        data = resp.json()
        if data.get("success", True) and data.get("ip"):
            result = _from_ipwhois(data)
        elif data.get("message"):
            warning = warning or data.get("message")
    except Exception:  # pragma: no cover - network dependent, fall back below
        pass

    # Fallback provider
    if result is None:
        try:
            resp = session.get(FALLBACK.format(ip=ip), timeout=config.timeout)
            data = resp.json()
            if data.get("status") == "success":
                result = _from_ipapi(data)
            else:
                return {"error": data.get("message", "lookup failed"), "ip": ip}
        except Exception as exc:  # pragma: no cover - network dependent
            return {"error": f"network error: {exc}", "ip": ip}

    if result is None:
        return {"error": "no data returned by providers", "ip": ip}

    if result.get("latitude") is not None and result.get("longitude") is not None:
        result["google_maps"] = (
            f"https://www.google.com/maps/search/?api=1&query="
            f"{result['latitude']},{result['longitude']}"
        )
    if warning:
        result["warning"] = warning
    return result
