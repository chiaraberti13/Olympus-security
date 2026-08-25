"""Authorized web content/directory discovery for Artemis.

A real, working content-discovery engine (the technique behind gobuster /
dirsearch / dirb): it requests a list of candidate paths under an authorized
base URL and reports which ones exist, so an operator can map the hidden
attack surface of a target they are **authorized** to test — and practise the
technique against a lab.

Safety is structural, not cosmetic:

* every candidate URL is re-checked against the Artemis scope before the
  request, so discovery can only ever touch authorized origins and path
  prefixes (out-of-scope candidates are blocked and audited);
* requests go through the DNS-pinned :func:`fetch_scoped` transport, are
  GET-only and bounded (timeout + max body), and never send a payload — this
  is discovery, not exploitation;
* it is rate-limited and capped, so it is not a stress/flood tool.

Discovered paths become ``core.Finding`` records; a curated set of
sensitive names (``.git``, ``.env``, backups, admin panels…) is raised to
``LOW`` with remediation, everything else stays informational.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, replace
from pathlib import Path

from olympus.artemis.http import HttpClientError, Resolver, Transport, fetch_scoped
from olympus.artemis.scope import OutOfScopeError, ScopeError
from olympus.core.enums import Severity, Source
from olympus.core.execution import Cancellation, ExecutionPolicy, NeverCancelled
from olympus.core.models import Finding

# Response statuses that mean "this path exists / is worth reporting".
_INTERESTING_STATUSES = frozenset({200, 201, 204, 301, 302, 307, 308, 401, 403, 405})

# Substrings that, when present in a discovered path, indicate a sensitive
# exposure worth escalating above a plain informational hit.
_SENSITIVE_MARKERS = (
    ".git",
    ".svn",
    ".env",
    ".htpasswd",
    "backup",
    "dump",
    "config",
    "admin",
    "phpinfo",
    "wp-admin",
    "id_rsa",
    ".bak",
    ".sql",
)

_MAX_WORDS = 5000


class WordlistError(RuntimeError):
    """Raised when a wordlist file is missing, unreadable or empty."""


@dataclass(frozen=True)
class DiscoveredPath:
    """One candidate path that returned an interesting status."""

    path: str
    url: str
    status: int
    length: int

    @property
    def sensitive(self) -> bool:
        """Return ``True`` if the path name matches a sensitive marker."""
        lowered = self.path.lower()
        return any(marker in lowered for marker in _SENSITIVE_MARKERS)


def load_wordlist(path: Path) -> list[str]:
    """Load a newline-delimited wordlist, skipping blanks/comments, deduped and capped."""
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise WordlistError(f"wordlist could not be read: {path} ({exc})") from exc
    words: list[str] = []
    seen: set[str] = set()
    for line in raw.splitlines():
        candidate = line.strip().lstrip("/")
        if not candidate or candidate.startswith("#") or candidate in seen:
            continue
        seen.add(candidate)
        words.append(candidate)
        if len(words) >= _MAX_WORDS:
            break
    if not words:
        raise WordlistError(f"wordlist {path} contains no usable entries")
    return words


def _candidate_url(base_url: str, word: str) -> str:
    """Join ``base_url`` and ``word`` with exactly one separating slash."""
    return f"{base_url.rstrip('/')}/{word}"


def discover_content(
    base_url: str,
    words: list[str],
    scope_path: Path,
    log_path: Path,
    resolver: Resolver,
    transport: Transport,
    *,
    policy: ExecutionPolicy,
    max_bytes: int = 1_000_000,
    cancellation: Cancellation | None = None,
) -> list[DiscoveredPath]:
    """Request each candidate path under ``base_url`` and collect existing ones.

    Out-of-scope candidates and transport errors are skipped (scope blocks are
    audited by :func:`fetch_scoped`). ``min_interval`` throttles requests for
    politeness. Returns the interesting paths in wordlist order.
    """
    policy.require_authorization("Artemis content discovery")
    token = cancellation or NeverCancelled()
    deadline = time.monotonic() + policy.deadline_seconds
    discovered: list[DiscoveredPath] = []
    last_request = 0.0
    for word in words:
        policy.check_cancellation(token)
        if time.monotonic() >= deadline:
            break
        if policy.min_interval_seconds > 0.0:
            wait = policy.min_interval_seconds - (time.monotonic() - last_request)
            if wait > 0:
                policy.check_cancellation(token)
                if wait >= deadline - time.monotonic():
                    break
                time.sleep(wait)
                policy.check_cancellation(token)
        url = _candidate_url(base_url, word)
        remaining = deadline - time.monotonic()
        if remaining < 0.05:
            break
        request_policy = replace(
            policy,
            deadline_seconds=min(policy.deadline_seconds, remaining),
        )
        try:
            result = fetch_scoped(
                url,
                scope_path,
                log_path,
                resolver,
                transport,
                max_bytes=max_bytes,
                policy=request_policy,
                cancellation=token,
            )
        except (HttpClientError, ScopeError, OutOfScopeError, ValueError):
            continue
        finally:
            last_request = time.monotonic()
        if result.response.status in _INTERESTING_STATUSES:
            discovered.append(
                DiscoveredPath(
                    path=word,
                    url=result.response.url,
                    status=result.response.status,
                    length=len(result.response.body),
                )
            )
    return discovered


def discoveries_to_findings(asset_id: str, discovered: list[DiscoveredPath]) -> list[Finding]:
    """Turn discovered paths into findings; sensitive names are raised to LOW."""
    findings: list[Finding] = []
    for item in discovered:
        sensitive = item.sensitive
        findings.append(
            Finding(
                asset_id=asset_id,
                source=Source.ARTEMIS,
                title=(
                    f"Sensitive path exposed: /{item.path} (HTTP {item.status})"
                    if sensitive
                    else f"Path discovered: /{item.path} (HTTP {item.status})"
                ),
                description=(
                    f"{item.url} returned HTTP {item.status} ({item.length} bytes) to an "
                    "authorized content-discovery request."
                ),
                severity=Severity.LOW if sensitive else Severity.INFO,
                evidence=[f"GET {item.url} -> {item.status}"],
                remediation=(
                    "Remove or access-restrict this resource if it is not meant to be public."
                    if sensitive
                    else ""
                ),
            )
        )
    return findings
