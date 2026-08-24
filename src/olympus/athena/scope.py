"""Target validation and SSRF protection for Athena adapters.

Every adapter re-validates its target here immediately before doing any
network work, independently of the plan-time check. Two guarantees:

* the target host is inside the plan's authorized scope; and
* the host is not an IP literal pointing at a private, loopback, link-local,
  or otherwise non-global address (a classic SSRF pivot).
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlparse


class TargetValidationError(ValueError):
    """Raised when a target is malformed."""


class TargetOutOfScopeError(RuntimeError):
    """Raised when a target host is outside the authorized scope."""


class SsrfBlockedError(RuntimeError):
    """Raised when a target host resolves to a non-global IP literal."""


def host_of(target_kind: str, target_value: str) -> str:
    """Return the bare host for a ``domain`` or ``url`` target."""
    if target_kind == "domain":
        host = target_value.strip().lower().rstrip(".")
        if "/" in host or " " in host or "." not in host:
            raise TargetValidationError(f"invalid domain target: {target_value!r}")
        return host
    if target_kind == "url":
        value = target_value.strip()
        if "://" not in value:
            value = "https://" + value
        parsed = urlparse(value)
        if not parsed.hostname:
            raise TargetValidationError(f"invalid url target: {target_value!r}")
        return parsed.hostname
    raise TargetValidationError(f"unsupported target kind: {target_kind!r}")


def _reject_non_global_ip(host: str) -> None:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return  # not an IP literal; a hostname is resolved by the network layer
    if not address.is_global:
        raise SsrfBlockedError(
            f"target host {host} is a non-global IP address and is blocked (SSRF guard)"
        )


def ensure_target_allowed(
    target_kind: str,
    target_value: str,
    allowed_domains: tuple[str, ...],
) -> str:
    """Validate a target and confirm it is in scope and not an SSRF pivot.

    Returns the validated host on success; raises the appropriate error
    otherwise.
    """
    host = host_of(target_kind, target_value)
    _reject_non_global_ip(host)
    normalized = host.rstrip(".")
    covered = any(
        normalized == allowed.strip().lower().rstrip(".")
        or normalized.endswith(f".{allowed.strip().lower().rstrip('.')}")
        for allowed in allowed_domains
    )
    if not covered:
        raise TargetOutOfScopeError(f"target host {host} is out of scope")
    return host
