"""Recipient scope enforcement for Proteus.

A phishing simulation must only ever target explicitly authorized
recipients. Every campaign checks each recipient's email domain against
a scope file before simulating anything; a recipient outside the
perimeter is blocked and the attempt is appended to an audit log — the
same non-negotiable discipline as Helios/Artemis, applied to recipient
domains instead of hosts.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path


class ScopeError(Exception):
    """Raised when the scope file is missing, unreadable or malformed."""


class OutOfScopeError(Exception):
    """Raised when a recipient's email domain is not covered by the loaded scope."""

    def __init__(self, email: str, scope_path: Path) -> None:
        super().__init__(f"{email!r} is out of scope ({scope_path})")
        self.email = email
        self.scope_path = scope_path


def _domain_of(email: str) -> str:
    """Return the domain part of ``email``, or the whole string if there's no '@'."""
    return email.rsplit("@", 1)[-1].lower()


@dataclass(frozen=True)
class Scope:
    """Authorized engagement perimeter: which recipient domains Proteus may target."""

    engagement: str
    allowed_domains: tuple[str, ...]
    excluded_recipients: tuple[str, ...] = ()

    def covers(self, email: str) -> bool:
        """Return ``True`` if ``email``'s domain is allowed and the address isn't excluded."""
        normalized = email.lower()
        if normalized in {excluded.lower() for excluded in self.excluded_recipients}:
            return False
        domain = _domain_of(normalized)
        return any(domain == allowed.lower() for allowed in self.allowed_domains)


def load_scope(path: Path) -> Scope:
    """Load and validate a JSON scope file.

    Expected shape::

        {
          "engagement": "olympus-demo-corp-2026",
          "allowed_domains": ["olympusdemocorp.example"],
          "excluded_recipients": []
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
        allowed = tuple(str(item) for item in raw["allowed_domains"])
    except (KeyError, TypeError) as exc:
        raise ScopeError(
            f"scope file {path} must define 'engagement' and 'allowed_domains'"
        ) from exc
    if not allowed:
        raise ScopeError(f"scope file {path} defines no allowed_domains")

    excluded = tuple(str(item) for item in raw.get("excluded_recipients", []))
    return Scope(engagement=engagement, allowed_domains=allowed, excluded_recipients=excluded)


def log_blocked(email: str, scope_path: Path, log_path: Path) -> None:
    """Append an audit record for a blocked, out-of-scope recipient."""
    entry = {
        "timestamp": datetime.now(UTC).isoformat(),
        "recipient": email,
        "scope_file": str(scope_path),
        "action": "blocked_out_of_scope",
    }
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, sort_keys=True) + "\n")


def enforce_scope(email: str, scope_path: Path, log_path: Path) -> Scope:
    """Load ``scope_path`` and ensure ``email`` is covered.

    Blocks (raises :class:`OutOfScopeError`) and logs the attempt otherwise.
    """
    scope = load_scope(scope_path)
    if not scope.covers(email):
        log_blocked(email, scope_path, log_path)
        raise OutOfScopeError(email, scope_path)
    return scope


def filter_in_scope(
    emails: list[str], scope_path: Path, log_path: Path
) -> tuple[list[str], list[str]]:
    """Split ``emails`` into (in_scope, blocked), logging every blocked attempt."""
    scope = load_scope(scope_path)
    in_scope: list[str] = []
    blocked: list[str] = []
    for email in emails:
        if scope.covers(email):
            in_scope.append(email)
        else:
            log_blocked(email, scope_path, log_path)
            blocked.append(email)
    return in_scope, blocked
