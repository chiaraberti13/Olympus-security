"""CORS misconfiguration detection.

Checks two well-known CORS misconfigurations that fully defeat the
same-origin policy CORS is meant to enforce:

- a wildcard ``Access-Control-Allow-Origin`` combined with
  ``Access-Control-Allow-Credentials: true`` (invalid per spec, but a
  server that sends it anyway indicates a misconfigured CORS policy);
- an arbitrary ``Origin`` being reflected back verbatim in
  ``Access-Control-Allow-Origin`` while credentials are allowed, letting
  any origin make authenticated cross-origin requests.
"""

from __future__ import annotations

from olympus.artemis.http_client import HttpResponse
from olympus.core.enums import Severity, Source
from olympus.core.models import Finding


def _header(response: HttpResponse, name: str) -> str | None:
    """Case-insensitive lookup of a single response header."""
    for key, value in response.headers.items():
        if key.lower() == name.lower():
            return value
    return None


def analyze_cors(
    asset_id: str, response: HttpResponse, request_origin: str | None = None
) -> list[Finding]:
    """Return CORS misconfiguration Findings for ``response``.

    ``request_origin`` is the ``Origin`` header value sent with the
    probing request, if any — needed to detect origin reflection.
    """
    allow_origin = _header(response, "Access-Control-Allow-Origin")
    if allow_origin is None:
        return []

    allow_credentials = (_header(response, "Access-Control-Allow-Credentials") or "").lower() == (
        "true"
    )

    if allow_origin == "*" and allow_credentials:
        return [
            Finding(
                asset_id=asset_id,
                source=Source.ARTEMIS,
                title="CORS wildcard origin with credentials allowed",
                description=(
                    "Access-Control-Allow-Origin: * combined with "
                    "Access-Control-Allow-Credentials: true is invalid per spec but "
                    "indicates a misconfigured CORS policy."
                ),
                severity=Severity.HIGH,
            )
        ]

    if (
        request_origin is not None
        and request_origin != "null"
        and allow_origin == request_origin
        and allow_credentials
    ):
        return [
            Finding(
                asset_id=asset_id,
                source=Source.ARTEMIS,
                title="CORS reflects arbitrary Origin with credentials allowed",
                description=(
                    f"The server reflected the request Origin ({request_origin}) back in "
                    "Access-Control-Allow-Origin while allowing credentials, letting any "
                    "origin make authenticated cross-origin requests."
                ),
                severity=Severity.HIGH,
            )
        ]

    return []
