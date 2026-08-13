"""Content discovery: probe a small set of commonly exposed, sensitive paths.

Checks a fixed, well-known list of paths that frequently leak sensitive
information when accidentally exposed (VCS metadata, env files, admin
panels, backups...). Only a single GET per path through the injected
HttpClient — no brute forcing, no wordlists, no active exploitation.
"""

from __future__ import annotations

from olympus.artemis.http_client import HttpClient
from olympus.core.enums import Severity, Source
from olympus.core.models import Finding

# path -> (severity, description) for sensitive paths worth flagging when reachable (2xx).
COMMON_PATHS: dict[str, tuple[Severity, str]] = {
    "/.git/config": (
        Severity.CRITICAL,
        "An exposed .git directory can leak the full source history.",
    ),
    "/.env": (
        Severity.CRITICAL,
        "An exposed .env file commonly contains secrets/credentials.",
    ),
    "/.htpasswd": (
        Severity.HIGH,
        "An exposed .htpasswd file can leak basic-auth credential hashes.",
    ),
    "/backup.zip": (
        Severity.HIGH,
        "A reachable backup archive may contain sensitive data.",
    ),
    "/admin": (
        Severity.MEDIUM,
        "An admin panel is reachable without any apparent access restriction.",
    ),
}


def discover_content(
    asset_id: str,
    base_url: str,
    client: HttpClient,
    paths: dict[str, tuple[Severity, str]] = COMMON_PATHS,
) -> list[Finding]:
    """Probe each path in ``paths`` against ``base_url`` and flag reachable (2xx) ones."""
    findings: list[Finding] = []
    for path, (severity, description) in paths.items():
        url = base_url.rstrip("/") + path
        response = client.get(url)
        if 200 <= response.status_code < 300:
            findings.append(
                Finding(
                    asset_id=asset_id,
                    source=Source.ARTEMIS,
                    title=f"Exposed path: {path}",
                    description=description,
                    severity=severity,
                    evidence=[f"GET {url} -> {response.status_code}"],
                )
            )
    return findings
