"""Bounded GET-only HTTP client with scope validation on every redirect."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from olympus.artemis.scope import enforce_scope

USER_AGENT = "Olympus-Security-Artemis/0.1 (authorized-recon)"
REDIRECT_STATUSES = {301, 302, 303, 307, 308}


class HttpClientError(RuntimeError):
    """Raised for transport, redirect or response limit failures."""


@dataclass(frozen=True)
class HttpResponse:
    """One bounded response returned by a transport."""

    url: str
    status: int
    headers: dict[str, str]
    body: bytes


@dataclass(frozen=True)
class FetchResult:
    """Final response plus the scoped redirect chain."""

    response: HttpResponse
    redirects: list[str]


class Transport(Protocol):
    """Injectable transport that performs exactly one non-redirecting GET."""

    def get(self, url: str, timeout: float, max_bytes: int) -> HttpResponse:
        """Return one response without following redirects."""
        ...


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args: object, **kwargs: object) -> None:
        return None


class UrllibTransport:
    """Production standard-library transport with redirects disabled."""

    def get(self, url: str, timeout: float, max_bytes: int) -> HttpResponse:
        if urlsplit(url).scheme not in {"http", "https"}:
            raise HttpClientError("transport accepts HTTP(S) URLs only")
        request = Request(  # noqa: S310 - scheme is explicitly allowlisted above
            url, headers={"User-Agent": USER_AGENT}, method="GET"
        )
        opener = build_opener(_NoRedirect)
        try:
            try:
                response = opener.open(request, timeout=timeout)
            except HTTPError as exc:
                response = exc
            with response:
                body = response.read(max_bytes + 1)
                if len(body) > max_bytes:
                    raise HttpClientError(f"response exceeds {max_bytes} byte limit")
                headers = {key.lower(): value for key, value in response.headers.items()}
                return HttpResponse(response.geturl(), response.status, headers, body)
        except (OSError, URLError) as exc:
            raise HttpClientError(f"HTTP GET failed: {exc}") from exc


def fetch_scoped(
    target: str,
    scope_path: Path,
    log_path: Path,
    transport: Transport,
    *,
    timeout: float = 5.0,
    max_bytes: int = 1_000_000,
    max_redirects: int = 5,
) -> FetchResult:
    """Perform bounded GET requests, reauthorizing every redirect before transport use."""
    if not 0.1 <= timeout <= 30.0:
        raise ValueError("timeout must be between 0.1 and 30 seconds")
    if not 1 <= max_bytes <= 10_000_000:
        raise ValueError("max_bytes must be between 1 and 10000000")
    if not 0 <= max_redirects <= 10:
        raise ValueError("max_redirects must be between 0 and 10")
    current = enforce_scope(target, scope_path, log_path).url
    redirects: list[str] = []
    for redirect_count in range(max_redirects + 1):
        response = transport.get(current, timeout, max_bytes)
        if response.status not in REDIRECT_STATUSES:
            return FetchResult(response, redirects)
        location = response.headers.get("location")
        if location is None:
            raise HttpClientError("redirect response is missing Location header")
        if redirect_count == max_redirects:
            raise HttpClientError("redirect limit exceeded")
        current = enforce_scope(urljoin(current, location), scope_path, log_path).url
        redirects.append(current)
    raise HttpClientError("redirect limit exceeded")
