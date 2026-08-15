"""Scope enforcement for authorized Helios network discovery."""

from __future__ import annotations

import ipaddress
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


class ScopeError(ValueError):
    """Raised for invalid scope configuration or targets."""


class OutOfScopeError(PermissionError):
    """Raised after an unauthorized target has been blocked and logged."""


def enforce_scope(
    target: str, scope_path: Path, log_path: Path
) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Return a validated target address or block and audit an out-of-scope request."""
    try:
        payload: Any = json.loads(scope_path.read_text(encoding="utf-8"))
        address = ipaddress.ip_address(target)
        networks = [
            ipaddress.ip_network(item, strict=False) for item in payload["allowed_networks"]
        ]
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ScopeError(f"invalid scope or target: {exc}") from exc
    if any(address in network for network in networks):
        return address
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as audit:
        audit.write(f"{datetime.now(UTC).isoformat()} BLOCK target={address}\n")
    raise OutOfScopeError(str(address))
