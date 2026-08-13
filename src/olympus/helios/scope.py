"""Scope enforcement for Helios.

Every offensive module in Olympus only ever touches explicitly authorized
targets. A scan target is checked against a JSON scope file before any
probe runs; anything outside the perimeter is blocked and the attempt is
appended to an audit log (never silently dropped). Helios operates on
hosts/IPs, so its scope matches CIDR ranges and exact hostnames — unlike
Argus's domain-suffix matching, which doesn't apply here.
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path


class ScopeError(Exception):
    """Raised when the scope file is missing, unreadable or malformed."""


class OutOfScopeError(Exception):
    """Raised when a target host/IP is not covered by the loaded scope."""

    def __init__(self, target: str, scope_path: Path) -> None:
        super().__init__(f"{target!r} is out of scope ({scope_path})")
        self.target = target
        self.scope_path = scope_path


def _matches(target: str, pattern: str) -> bool:
    """Return ``True`` if ``target`` (hostname or IP) matches ``pattern``.

    ``pattern`` may be a CIDR range (matched against ``target`` parsed as an
    IP address) or an exact hostname/IP (case-insensitive string match).
    """
    try:
        network = ipaddress.ip_network(pattern, strict=False)
        address = ipaddress.ip_address(target)
    except ValueError:
        return target.lower() == pattern.lower()
    return address in network


@dataclass(frozen=True)
class Scope:
    """Authorized engagement perimeter: which hosts/CIDRs Helios may probe."""

    engagement: str
    allowed_targets: tuple[str, ...]
    excluded_targets: tuple[str, ...] = ()

    def covers(self, target: str) -> bool:
        """Return ``True`` if ``target`` is allowed and not excluded."""
        if any(_matches(target, excluded) for excluded in self.excluded_targets):
            return False
        return any(_matches(target, allowed) for allowed in self.allowed_targets)


def load_scope(path: Path) -> Scope:
    """Load and validate a JSON scope file.

    Expected shape::

        {
          "engagement": "olympus-demo-corp-2026",
          "allowed_targets": ["203.0.113.0/24"],
          "excluded_targets": []
        }
    """
    try:
        raw_text = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise ScopeError(f"scope file not found: {path}") from exc
    except OSError as exc:
        raise ScopeError(f"scope file could not be read: {path} ({exc})") from exc

    try:
        raw = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise ScopeError(f"scope file is not valid JSON: {path} ({exc})") from exc

    if not isinstance(raw, dict):
        raise ScopeError(f"scope file {path} must contain a JSON object")

    try:
        engagement = str(raw["engagement"])
        allowed = tuple(str(item) for item in raw["allowed_targets"])
    except (KeyError, TypeError) as exc:
        raise ScopeError(
            f"scope file {path} must define 'engagement' and 'allowed_targets'"
        ) from exc
    if not allowed:
        raise ScopeError(f"scope file {path} defines no allowed_targets")

    excluded = tuple(str(item) for item in raw.get("excluded_targets", []))
    return Scope(engagement=engagement, allowed_targets=allowed, excluded_targets=excluded)


def log_blocked(target: str, scope_path: Path, log_path: Path) -> None:
    """Append an audit record for a blocked, out-of-scope scan attempt."""
    entry = {
        "timestamp": datetime.now(UTC).isoformat(),
        "target": target,
        "scope_file": str(scope_path),
        "action": "blocked_out_of_scope",
    }
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, sort_keys=True) + "\n")


def enforce_scope(target: str, scope_path: Path, log_path: Path) -> Scope:
    """Load ``scope_path`` and ensure ``target`` is covered.

    Blocks (raises :class:`OutOfScopeError`) and logs the attempt otherwise.
    """
    scope = load_scope(scope_path)
    if not scope.covers(target):
        log_blocked(target, scope_path, log_path)
        raise OutOfScopeError(target, scope_path)
    return scope
