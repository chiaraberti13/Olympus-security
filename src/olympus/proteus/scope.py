"""Scope enforcement for Proteus authorized phishing simulations.

A simulation only ever targets recipients whose email domain is explicitly
authorized for the engagement. Each target address is checked against a JSON
allowlist of domains before it enters a campaign; anything outside the
perimeter is blocked and the attempt is appended to an audit log.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path


class ProteusScopeError(Exception):
    """Raised when the scope file is missing, unreadable or malformed."""


class ProteusOutOfScopeError(Exception):
    """Raised when a target email is not covered by the loaded scope."""

    def __init__(self, email: str, scope_path: Path) -> None:
        super().__init__(f"{email!r} is out of scope ({scope_path})")
        self.email = email
        self.scope_path = scope_path


@dataclass(frozen=True)
class ProteusScope:
    """Authorized perimeter: which email domains a simulation may target."""

    engagement: str
    allowed_domains: tuple[str, ...]

    def covers(self, email: str) -> bool:
        """Return ``True`` if ``email``'s domain is in the allowlist."""
        _, _, domain = email.strip().lower().partition("@")
        if not domain:
            return False
        return any(domain == allowed.strip().lower() for allowed in self.allowed_domains)


def load_scope(path: Path) -> ProteusScope:
    """Load and validate a JSON Proteus scope file (engagement + domain allowlist)."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ProteusScopeError(f"scope file not found: {path}") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise ProteusScopeError(f"scope file could not be read: {path} ({exc})") from exc

    if not isinstance(raw, dict):
        raise ProteusScopeError(f"scope file {path} must contain a JSON object")
    try:
        engagement = str(raw["engagement"])
        allowed = tuple(str(item) for item in raw["allowed_domains"])
    except (KeyError, TypeError) as exc:
        raise ProteusScopeError(
            f"scope file {path} must define 'engagement' and 'allowed_domains'"
        ) from exc
    if not allowed:
        raise ProteusScopeError(f"scope file {path} defines no allowed_domains")
    return ProteusScope(engagement=engagement, allowed_domains=allowed)


def log_blocked(email: str, scope_path: Path, log_path: Path) -> None:
    """Append an audit record for a blocked, out-of-scope target."""
    entry = {
        "timestamp": datetime.now(UTC).isoformat(),
        "target": email,
        "scope_file": str(scope_path),
        "action": "blocked_out_of_scope",
    }
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, sort_keys=True) + "\n")


def enforce_scope(email: str, scope_path: Path, log_path: Path) -> ProteusScope:
    """Load ``scope_path`` and ensure ``email`` is covered, blocking+logging otherwise."""
    scope = load_scope(scope_path)
    if not scope.covers(email):
        log_blocked(email, scope_path, log_path)
        raise ProteusOutOfScopeError(email, scope_path)
    return scope
