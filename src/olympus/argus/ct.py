"""Certificate Transparency passive subdomain enumeration.

Queries public CT logs (crt.sh) for certificates issued under a domain and
extracts the Subject Alternative Names as candidate subdomains. Purely
passive: no active DNS/HTTP probing of any discovered host, only a lookup
against a public, append-only log.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol

CRTSH_BASE_URL = "https://crt.sh/"


class CertificateTransparencyClient(Protocol):
    """Anything able to answer a passive CT-log query for a domain."""

    def query(self, domain: str) -> list[dict[str, Any]]:
        """Return raw CT log entries (crt.sh JSON shape) mentioning ``domain``."""
        ...


class CtQueryError(RuntimeError):
    """Raised when the CT log query fails (network error, malformed response)."""


class CrtShClient:
    """Production :class:`CertificateTransparencyClient` backed by the public crt.sh API."""

    def __init__(self, timeout: float = 10.0) -> None:
        self._timeout = timeout

    def query(self, domain: str) -> list[dict[str, Any]]:
        """Fetch every certificate crt.sh has logged for ``domain`` and its subdomains."""
        query = urllib.parse.quote(f"%.{domain}")
        url = f"{CRTSH_BASE_URL}?q={query}&output=json"
        if not url.startswith(CRTSH_BASE_URL):  # defensive: keep the scheme/host fixed
            raise CtQueryError(f"refusing to query unexpected URL: {url}")

        try:
            with urllib.request.urlopen(url, timeout=self._timeout) as response:  # noqa: S310
                raw = response.read()
        except (urllib.error.URLError, TimeoutError) as exc:
            raise CtQueryError(f"crt.sh query failed for {domain}: {exc}") from exc

        if not raw:
            return []
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise CtQueryError(f"crt.sh returned invalid JSON for {domain}: {exc}") from exc
        if not isinstance(data, list):
            raise CtQueryError(f"crt.sh returned an unexpected payload for {domain}")
        return data


def _clean_name(raw_name: str, domain: str) -> str | None:
    """Normalize one candidate SAN; return ``None`` if it is not in ``domain``."""
    candidate = raw_name.strip().lower().removeprefix("*.")
    if not candidate:
        return None
    normalized_domain = domain.lower()
    if candidate == normalized_domain or candidate.endswith(f".{normalized_domain}"):
        return candidate
    return None


def extract_subdomains(entries: list[dict[str, Any]], domain: str) -> list[str]:
    """Extract unique, in-domain subdomains from raw crt.sh entries."""
    found: set[str] = set()
    for entry in entries:
        name_value = str(entry.get("name_value", ""))
        for raw_name in name_value.splitlines():
            cleaned = _clean_name(raw_name, domain)
            if cleaned is not None:
                found.add(cleaned)
    return sorted(found)


@dataclass(frozen=True)
class CtRecon:
    """Passive CT-log snapshot of the subdomains observed for a domain."""

    domain: str
    subdomains: list[str] = field(default_factory=list)
    queried_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable view of this CT recon snapshot."""
        return {
            "domain": self.domain,
            "subdomains": self.subdomains,
            "queried_at": self.queried_at.isoformat(),
        }


def enumerate_subdomains(domain: str, client: CertificateTransparencyClient) -> CtRecon:
    """Run a passive CT-log subdomain enumeration pass against ``domain``."""
    entries = client.query(domain)
    return CtRecon(domain=domain, subdomains=extract_subdomains(entries, domain))
