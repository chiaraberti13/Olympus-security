"""Target validation and scope/SSRF enforcement for AEGIS live scans.

Every real scan validates its target here first. Two guarantees:

* the target host is inside the operator's explicit authorized scope; and
* a non-global IP literal (loopback/private/link-local) is refused as an SSRF
  pivot **unless** the operator listed that exact host in scope — an authorized
  local laboratory target is intentional, an accidental pivot is not.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlparse


class TargetValidationError(ValueError):
    """Raised when a target is malformed."""


class OutOfScopeError(RuntimeError):
    """Raised when a target host is outside the authorized scope."""


class SsrfBlockedError(RuntimeError):
    """Raised when a non-global IP literal is not explicitly authorized."""


def host_of(target_kind: str, target_value: str) -> str:
    """Return the bare host for a ``host``, ``domain``, or ``url`` target."""
    value = target_value.strip()
    if target_kind == "url":
        if "://" not in value:
            value = "https://" + value
        parsed = urlparse(value)
        if not parsed.hostname:
            raise TargetValidationError(f"invalid url target: {target_value!r}")
        return parsed.hostname
    host = value.lower().rstrip(".")
    if not host or "/" in host or " " in host:
        raise TargetValidationError(f"invalid target: {target_value!r}")
    return host


def _covered(host: str, allowed: tuple[str, ...]) -> bool:
    target = host.strip().lower().rstrip(".")
    for entry in allowed:
        norm = entry.strip().lower().rstrip(".")
        if target == norm or target.endswith(f".{norm}"):
            return True
    return False


def ensure_allowed(target_kind: str, target_value: str, allowed: tuple[str, ...]) -> str:
    """Validate a target and confirm it is in scope and not an SSRF pivot.

    Returns the validated host. A loopback/private IP literal is permitted only
    when it is listed *exactly* in ``allowed`` (an authorized lab target).
    """
    host = host_of(target_kind, target_value)
    in_scope = _covered(host, allowed)
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address is not None and not address.is_global:
        # Non-global IP literal: only allowed if explicitly, exactly authorized.
        if host not in allowed:
            raise SsrfBlockedError(
                f"target {host} is a non-global IP and is not explicitly authorized (SSRF guard)"
            )
        return host
    if not in_scope:
        raise OutOfScopeError(f"target {host} is out of scope")
    return host
