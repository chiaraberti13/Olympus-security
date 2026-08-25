"""Shared authorization, resource, cancellation, retry, and audit policy.

Scope syntax remains owned by each module (domain suffix, CIDR, E.164, OUI,
handle, or URL+resolved address). This module standardizes when checks happen
and the bounded execution/redaction behavior around those dedicated gates.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

MAX_TIMEOUT_SECONDS = 3600.0
MAX_DEADLINE_SECONDS = 86_400.0
MAX_CONCURRENCY = 64
MAX_RETRIES = 5
MAX_BACKOFF_SECONDS = 60.0
MAX_MIN_INTERVAL_SECONDS = 60.0

_SENSITIVE_KEY_PARTS = (
    "authorization",
    "cookie",
    "credential",
    "password",
    "secret",
    "token",
    "api_key",
    "apikey",
    "access_key",
)


class ExecutionPolicyError(ValueError):
    """Raised when shared execution settings are missing, ambiguous, or unsafe."""


class AuthorizationRequiredError(PermissionError):
    """Raised before work when a policy lacks explicit authorization."""


class CancellationRequested(RuntimeError):
    """Raised when cooperative work observes a cancellation request."""


class Cancellation(Protocol):
    """Minimal cooperative cancellation port shared by workers/adapters."""

    def is_cancelled(self) -> bool:
        """Return whether cancellation was requested."""
        ...


class NeverCancelled:
    """Default cancellation token for bounded synchronous operations."""

    def is_cancelled(self) -> bool:
        return False


class CancellationToken:
    """Thread-safe mutable cooperative cancellation token."""

    def __init__(self) -> None:
        self._event = threading.Event()

    def cancel(self) -> None:
        """Request cancellation; repeated calls are idempotent."""
        self._event.set()

    def is_cancelled(self) -> bool:
        return self._event.is_set()


@dataclass(frozen=True)
class ExecutionPolicy:
    """Validated resource and authorization policy for one operation."""

    authorized: bool = False
    approval_reference: str | None = None
    timeout_seconds: float = 10.0
    deadline_seconds: float = 600.0
    max_concurrency: int = 1
    retries: int = 0
    backoff_seconds: float = 0.5
    min_interval_seconds: float = 0.0

    def __post_init__(self) -> None:
        if not 0.05 <= self.timeout_seconds <= MAX_TIMEOUT_SECONDS:
            raise ExecutionPolicyError(
                f"timeout_seconds must be between 0.05 and {MAX_TIMEOUT_SECONDS:g}"
            )
        if not 0.05 <= self.deadline_seconds <= MAX_DEADLINE_SECONDS:
            raise ExecutionPolicyError(
                f"deadline_seconds must be between 0.05 and {MAX_DEADLINE_SECONDS:g}"
            )
        if not 1 <= self.max_concurrency <= MAX_CONCURRENCY:
            raise ExecutionPolicyError(f"max_concurrency must be between 1 and {MAX_CONCURRENCY}")
        if not 0 <= self.retries <= MAX_RETRIES:
            raise ExecutionPolicyError(f"retries must be between 0 and {MAX_RETRIES}")
        if not 0.0 <= self.backoff_seconds <= MAX_BACKOFF_SECONDS:
            raise ExecutionPolicyError(
                f"backoff_seconds must be between 0 and {MAX_BACKOFF_SECONDS:g}"
            )
        if not 0.0 <= self.min_interval_seconds <= MAX_MIN_INTERVAL_SECONDS:
            raise ExecutionPolicyError(
                f"min_interval_seconds must be between 0 and {MAX_MIN_INTERVAL_SECONDS:g}"
            )
        if self.approval_reference is not None and not self.approval_reference.strip():
            raise ExecutionPolicyError("approval_reference must not be blank")

    def require_authorization(self, operation: str) -> None:
        """Refuse an operation before its scope gate or adapter can run."""
        if not self.authorized:
            raise AuthorizationRequiredError(
                f"{operation} requires explicit documented authorization"
            )

    def authorize_target(
        self, operation: str, target: str, scope_authorizer: Callable[[str], object]
    ) -> None:
        """Require authorization, then invoke the module's dedicated scope gate."""
        self.require_authorization(operation)
        scope_authorizer(target)

    def check_cancellation(self, cancellation: Cancellation) -> None:
        """Raise a stable exception when cooperative cancellation is requested."""
        if cancellation.is_cancelled():
            raise CancellationRequested("operation cancelled")


def _sensitive_key(key: object) -> bool:
    normalized = str(key).strip().lower().replace("-", "_")
    return any(part in normalized for part in _SENSITIVE_KEY_PARTS)


def redact_url(value: str) -> str:
    """Redact sensitive query values while preserving a URL's useful shape."""
    try:
        parsed = urlsplit(value)
    except ValueError:
        return value
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return value
    query = urlencode(
        [
            (key, "[REDACTED]" if _sensitive_key(key) else item)
            for key, item in parse_qsl(parsed.query)
        ],
        doseq=True,
    )
    hostname = parsed.hostname or ""
    port = f":{parsed.port}" if parsed.port is not None else ""
    return urlunsplit((parsed.scheme, f"{hostname}{port}", parsed.path, query, parsed.fragment))


def redact_mapping(value: Mapping[str, Any]) -> dict[str, Any]:
    """Recursively redact secret-bearing keys and URL query parameters."""
    redacted: dict[str, Any] = {}
    for key, item in value.items():
        if _sensitive_key(key):
            redacted[key] = "[REDACTED]"
        elif isinstance(item, Mapping):
            redacted[key] = redact_mapping(item)
        elif isinstance(item, list):
            redacted[key] = [
                redact_mapping(entry) if isinstance(entry, Mapping) else entry for entry in item
            ]
        elif isinstance(item, str):
            redacted[key] = redact_url(item)
        else:
            redacted[key] = item
    return redacted


@dataclass(frozen=True)
class StructuredAuditRecord:
    """Redacted JSON audit record shared by application and worker surfaces."""

    timestamp: str
    execution_id: str
    action: str
    outcome: str
    target: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Return the redacted serialization; raw metadata is never exposed."""
        return {
            "timestamp": self.timestamp,
            "execution_id": self.execution_id,
            "action": self.action,
            "outcome": self.outcome,
            "target": redact_url(self.target) if self.target is not None else None,
            "metadata": redact_mapping(self.metadata),
        }

    def to_json(self) -> str:
        """Return deterministic one-line JSON suitable for append-only logs."""
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))


def append_structured_audit(path: Path, record: StructuredAuditRecord) -> None:
    """Append one already-redacted record without exposing raw fields on disk."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as audit:
        audit.write(record.to_json() + "\n")
