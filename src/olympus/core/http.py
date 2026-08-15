"""Shared HTTP client abstraction for every Olympus module that speaks HTTP.

Consumers talk to the :class:`HttpClient` protocol, never to ``urllib``
directly, so a real client (production) and a fake in-memory client (tests)
are interchangeable. This mirrors Argus's ``DnsResolver`` design and is the
single source of truth reused by Artemis (web recon), Argus (account
enumeration) and the Metabase exposure check.

Every request identifies itself honestly through a fixed ``User-Agent``:
Olympus performs *authorized*, transparent security testing and never
impersonates a browser or rotates TLS fingerprints to evade detection.
"""

from __future__ import annotations

import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Protocol

#: Honest, fixed identifier sent on every Olympus HTTP request.
USER_AGENT = "Olympus/1.0 (+authorized-security-testing)"


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
    """Production :class:`HttpClient` backed by ``urllib``, doing real HTTP GET requests."""

    def __init__(self, timeout: float = 10.0) -> None:
        self._timeout = timeout

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> HttpResponse:
        """Perform a real HTTP GET against ``url`` and return a normalized response."""
        if not url.startswith(("http://", "https://")):
            raise HttpRequestError(f"refusing to fetch a non-HTTP(S) URL: {url}")

        request_headers = {"User-Agent": USER_AGENT, **(headers or {})}
        request = urllib.request.Request(  # noqa: S310 (scheme already checked above)
            url, headers=request_headers
        )
        try:
            with urllib.request.urlopen(  # noqa: S310 (scheme already checked above)
                request, timeout=self._timeout
            ) as response:
                body_bytes = response.read()
                status_code = response.status
                response_headers = dict(response.headers.items())
        except urllib.error.HTTPError as exc:
            # An HTTP error status is still a valid, informative response for recon.
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
