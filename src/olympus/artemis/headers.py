"""Security header analysis: missing headers become Findings.

Checks the small set of security-relevant response headers a
well-configured web server should set, and produces one `core.Finding`
per header that is missing. Header names are matched case-insensitively
(HTTP header names are case-insensitive by spec).
"""

from __future__ import annotations

from olympus.artemis.http_client import HttpResponse
from olympus.core.enums import Severity, Source
from olympus.core.models import Finding

# header name (lowercase) -> (severity if missing, description)
REQUIRED_HEADERS: dict[str, tuple[Severity, str]] = {
    "content-security-policy": (
        Severity.MEDIUM,
        "Content-Security-Policy mitigates XSS/injection by restricting allowed content "
        "sources.",
    ),
    "strict-transport-security": (
        Severity.MEDIUM,
        "Strict-Transport-Security enforces HTTPS, preventing downgrade/SSL-stripping "
        "attacks.",
    ),
    "x-frame-options": (
        Severity.LOW,
        "X-Frame-Options prevents clickjacking via iframe embedding.",
    ),
    "x-content-type-options": (
        Severity.LOW,
        "X-Content-Type-Options: nosniff prevents MIME-sniffing attacks.",
    ),
    "referrer-policy": (
        Severity.LOW,
        "Referrer-Policy controls how much referrer information leaks cross-origin.",
    ),
}


def analyze_headers(asset_id: str, response: HttpResponse) -> list[Finding]:
    """Return one Finding per missing security header in ``response``."""
    present = {name.lower() for name in response.headers}
    return [
        Finding(
            asset_id=asset_id,
            source=Source.ARTEMIS,
            title=f"Missing security header: {header_name}",
            description=description,
            severity=severity,
        )
        for header_name, (severity, description) in REQUIRED_HEADERS.items()
        if header_name not in present
    ]
