"""Scope enforcement for authorized Helios network discovery."""

from __future__ import annotations

import ipaddress
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from olympus.core.execution import StructuredAuditRecord, append_structured_audit


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
    append_structured_audit(
        log_path,
        StructuredAuditRecord(
            timestamp=datetime.now(UTC).isoformat(),
            execution_id=str(uuid4()),
            action="helios.scope",
            outcome="blocked",
            target=str(address),
            metadata={"reason": "address_not_allowed"},
        ),
    )
    raise OutOfScopeError(str(address))
