"""MAC address vendor (OUI) lookup.

Identifies the hardware manufacturer registered to a MAC address's OUI (the
first 24 bits) using the public ``macvendors.com`` API. No key required.
"""
from __future__ import annotations

import re
from typing import Optional

from ..config import Config
from ..utils import build_session

API = "https://api.macvendors.com/{mac}"

_MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}([:-]?)(?:[0-9A-Fa-f]{2}\1){4}[0-9A-Fa-f]{2}$")


def _clean(mac: str) -> str:
    return re.sub(r"[^0-9A-Fa-f]", "", mac).upper()


def is_valid_mac(mac: str) -> bool:
    hexonly = _clean(mac)
    return bool(_MAC_RE.match(mac.strip())) or len(hexonly) == 12


def lookup(mac: str, config: Optional[Config] = None) -> dict:
    config = config or Config.load()
    raw = mac.strip()
    if not is_valid_mac(raw):
        return {"error": f"'{raw}' is not a valid MAC address", "input": raw}

    hexonly = _clean(raw)
    oui = ":".join(hexonly[i:i + 2] for i in range(0, 6, 2))
    normalized = ":".join(hexonly[i:i + 2] for i in range(0, 12, 2))

    session = build_session(config)
    vendor = None
    try:
        resp = session.get(API.format(mac=hexonly[:6]), timeout=config.timeout)
        if resp.status_code == 200:
            vendor = resp.text.strip()
        elif resp.status_code == 404:
            vendor = None
    except Exception as exc:  # pragma: no cover - network dependent
        return {"error": f"network error: {exc}", "mac": normalized, "oui": oui}

    # The 2nd-least-significant bit of the first octet marks locally administered
    # addresses; the least-significant bit marks multicast.
    first_octet = int(hexonly[0:2], 16)
    return {
        "mac": normalized,
        "oui": oui,
        "vendor": vendor or "unknown (not in registry / randomized)",
        "locally_administered": bool(first_octet & 0b10),
        "multicast": bool(first_octet & 0b01),
        "source": "macvendors.com",
    }
