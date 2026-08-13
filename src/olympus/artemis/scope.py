"""Scope enforcement for Artemis.

Every offensive module in Olympus only ever touches explicitly authorized
targets. Artemis is an active module (it sends real HTTP requests), so
SECURITY.md requires a mandatory scope file: a target is checked before
any request runs, and anything outside the perimeter is blocked and the
attempt is appended to an audit log (never silently dropped). Artemis
operates on web hosts, so its scope matches domain suffixes — the same
semantics as Argus's passive recon scope.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path


class ScopeError(Exception):
    """Raised when the scope file is missing, unreadable or malformed."""


class OutOfScopeError(Exception):
    """Raised when a target host is not covered by the loaded scope."""

    def __init__(self, target: str, scope_path: Path) -> None:
        super().__init__(f"{target!r} is out of scope ({scope_path})")
        self.target = target
        self.scope_path = scope_path


@dataclass(frozen=True)
class Scope:
    """Authorized engagement perimeter: which hosts Artemis may probe."""

    engagement: str
    allowed_hosts: tuple[str, ...]
    excluded_hosts: tuple[str, ...] = ()

    def covers(self, host: str) -> bool:
        """Return ``True`` if ``host`` (or a subdomain) is allowed and not excluded."""
        target = host.lower().rstrip(".")
        if any(_matches(target, excluded) for excluded in self.excluded_hosts):
            return False
        return any(_matches(target, allowed) for allowed in self.allowed_hosts)


def _matches(target: str, pattern: str) -> bool:
    """Return ``True`` if ``target`` equals ``pattern`` or is one of its subdomains."""
    normalized = pattern.lower().rstrip(".")
    return target == normalized or target.endswith(f".{normalized}")


def load_scope(path: Path) -> Scope:
    """Load and validate a JSON scope file.

    Expected shape::

        {
          "engagement": "olympus-demo-corp-2026",
          "allowed_hosts": ["olympusdemocorp.example"],
          "excluded_hosts": []
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
        allowed = tuple(str(item) for item in raw["allowed_hosts"])
    except (KeyError, TypeError) as exc:
        raise ScopeError(f"scope file {path} must define 'engagement' and 'allowed_hosts'") from exc
    if not allowed:
        raise ScopeError(f"scope file {path} defines no allowed_hosts")

    excluded = tuple(str(item) for item in raw.get("excluded_hosts", []))
    return Scope(engagement=engagement, allowed_hosts=allowed, excluded_hosts=excluded)


def log_blocked(target: str, scope_path: Path, log_path: Path) -> None:
    """Append an audit record for a blocked, out-of-scope request attempt."""
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
