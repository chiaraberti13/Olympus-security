"""Minimal, honest HTTP client shared by Argus OSINT lookups.

Consumers talk to the :class:`HttpClient` protocol, never to ``urllib``
directly, so a real client (production) and a fake in-memory client (tests)
are interchangeable. Every request identifies itself with a fixed, honest
``User-Agent``: Olympus performs *authorized*, transparent security testing
and never impersonates a browser or rotates TLS fingerprints to evade
detection.

This is intentionally separate from Artemis's pinned, scope-safe transport:
it serves passive OSINT enrichment (phone/account lookups) rather than
authorized fetches against a target's own web perimeter.
"""

from __future__ import annotations

import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Protocol

#: Honest, fixed identifier sent on every Olympus OSINT HTTP request.
USER_AGENT = "Olympus/1.0 (+authorized-security-testing)"

#: HTTP statuses worth retrying (rate-limited / transient server errors).
_RETRYABLE_STATUSES = frozenset({429, 502, 503, 504})


@dataclass(frozen=True)
class HttpResponse:
    """A normalized HTTP response: status, headers, and body text."""

    status_code: int
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""


class HttpClient(Protocol):
    """Anything able to perform a passive HTTP GET request."""

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> HttpResponse:
        """Return the response for a GET request to ``url``, with optional extra headers."""
        ...


class HttpRequestError(RuntimeError):
    """Raised when the HTTP request fails (network error, timeout...)."""


class UrllibHttpClient:
    """Production :class:`HttpClient` backed by ``urllib``.

    Robust for real-network use: bounded ``timeout``, automatic retries with
    exponential backoff on transient failures (network errors and 429/5xx),
    and an optional client-side rate limit (a minimum interval between
    requests) so bulk lookups stay polite.
    """

    def __init__(
        self,
        timeout: float = 10.0,
        *,
        retries: int = 2,
        backoff: float = 0.5,
        min_interval: float = 0.0,
    ) -> None:
        self._timeout = timeout
        self._retries = max(retries, 0)
        self._backoff = max(backoff, 0.0)
        self._min_interval = max(min_interval, 0.0)
        self._last_request_at = 0.0

    @classmethod
    def from_config(cls, *, min_interval: float | None = None) -> UrllibHttpClient:
        """Build a client using ``[http]`` config defaults (CLI overrides win).

        ``min_interval`` from the caller (e.g. a ``--rate`` flag) takes
        precedence over the config file; everything else comes from ``[http]``.
        """
        from olympus.core import config

        data = config.load_config()
        rate = min_interval if min_interval is not None else config.get("http", "rate", 0.0, data)
        return cls(
            config.get("http", "timeout", 10.0, data),
            retries=config.get("http", "retries", 2, data),
            backoff=config.get("http", "backoff", 0.5, data),
            min_interval=rate,
        )

    def _throttle(self) -> None:
        """Sleep just enough to honor the configured minimum request interval."""
        if self._min_interval <= 0.0:
            return
        elapsed = time.monotonic() - self._last_request_at
        if 0.0 <= elapsed < self._min_interval:
            time.sleep(self._min_interval - elapsed)
        self._last_request_at = time.monotonic()

    def _perform(self, request: urllib.request.Request, url: str) -> HttpResponse:
        try:
            with urllib.request.urlopen(  # noqa: S310 (scheme checked by caller)
                request, timeout=self._timeout
            ) as response:
                body_bytes = response.read()
                status_code = response.status
                response_headers = dict(response.headers.items())
        except urllib.error.HTTPError as exc:
            body_bytes = exc.read()
            status_code = exc.code
            response_headers = dict(exc.headers.items()) if exc.headers else {}
        except (urllib.error.URLError, TimeoutError) as exc:
            raise HttpRequestError(f"HTTP GET failed for {url}: {exc}") from exc
        return HttpResponse(
            status_code=status_code,
            headers=response_headers,
            body=body_bytes.decode("utf-8", errors="replace"),
        )

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> HttpResponse:
        """Perform an HTTP GET with retry/backoff/rate-limit, returning a response."""
        if not url.startswith(("http://", "https://")):
            raise HttpRequestError(f"refusing to fetch a non-HTTP(S) URL: {url}")

        request_headers = {"User-Agent": USER_AGENT, **(headers or {})}
        request = urllib.request.Request(  # noqa: S310 (scheme already checked above)
            url, headers=request_headers
        )

        last_error: HttpRequestError | None = None
        for attempt in range(self._retries + 1):
            self._throttle()
            try:
                response = self._perform(request, url)
            except HttpRequestError as exc:
                last_error = exc
            else:
                if response.status_code not in _RETRYABLE_STATUSES:
                    return response
                last_error = HttpRequestError(
                    f"HTTP GET for {url} returned retryable status {response.status_code}"
                )
                if attempt == self._retries:
                    return response  # out of retries: hand back the last response
            if attempt < self._retries:
                time.sleep(self._backoff * (2**attempt))

        raise last_error or HttpRequestError(f"HTTP GET failed for {url}")
