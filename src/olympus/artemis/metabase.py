"""Non-exploitative detection of Metabase instances vulnerable to CVE-2026-72898.

The Metabase advisory GHSA-vwf4-m7j8-wcjf describes an unauthenticated SQL
injection in ``/api/session/reset_password``. This check only *fingerprints*
exposure — it reads the public version from ``/api/session/properties`` and
notes whether the vulnerable endpoint is reachable. It **never** sends a SQL
injection payload: Olympus reports the risk, it does not exploit it.
"""

from __future__ import annotations

import json
import re

from olympus.core.enums import Severity, Source
from olympus.core.http import HttpClient, HttpRequestError
from olympus.core.models import Finding

CVE_ID = "CVE-2026-72898"
ADVISORY_URL = "https://github.com/metabase/metabase/security/advisories/GHSA-vwf4-m7j8-wcjf"

# Metabase release line -> (highest affected release, first patched version).
# Ranges taken from the advisory; a version is affected when its release
# number is at or below the highest-affected value for its line.
_AFFECTED: dict[int, tuple[int, str]] = {
    58: (23, "58.24"),
    59: (20, "59.21"),
    60: (16, "60.17"),
    61: (10, "61.11"),
    62: (8, "62.9"),
    63: (3, "63.5"),
}

_VERSION_RE = re.compile(r"v?(?:[01]\.)?(\d+)\.(\d+)")


def _parse_line_release(tag: str) -> tuple[int, int] | None:
    """Parse a Metabase version tag (e.g. ``v0.60.16``) into ``(line, release)``."""
    match = _VERSION_RE.match(tag.strip())
    if match is None:
        return None
    return int(match.group(1)), int(match.group(2))


def _extract_version_tag(body: str) -> str | None:
    """Return the Metabase version tag from a ``/api/session/properties`` body."""
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict) or "version" not in data:
        return None
    version = data["version"]
    if isinstance(version, dict):
        tag = version.get("tag")
        return str(tag) if tag is not None else None
    return str(version)


def _reset_password_reachable(base_url: str, client: HttpClient) -> int | None:
    """Return the status code of a GET to the vulnerable endpoint, or ``None``.

    Only a plain GET is issued — never a POST, never a payload. A non-404
    status means the endpoint is present and worth flagging.
    """
    url = base_url.rstrip("/") + "/api/session/reset_password"
    try:
        return client.get(url).status_code
    except HttpRequestError:
        return None


def detect_metabase(asset_id: str, base_url: str, client: HttpClient) -> list[Finding]:
    """Fingerprint a possible Metabase instance and flag CVE-2026-72898 exposure."""
    properties_url = base_url.rstrip("/") + "/api/session/properties"
    try:
        response = client.get(properties_url)
    except HttpRequestError:
        return []

    if response.status_code != 200:
        return []
    version_tag = _extract_version_tag(response.body)
    if version_tag is None:
        return []  # not a Metabase properties endpoint

    reset_status = _reset_password_reachable(base_url, client)
    line_release = _parse_line_release(version_tag)
    evidence = [f"version={version_tag}", f"GET /api/session/properties -> {response.status_code}"]
    if reset_status is not None:
        evidence.append(f"GET /api/session/reset_password -> {reset_status}")

    if line_release is not None and line_release[0] in _AFFECTED:
        highest_affected, patched = _AFFECTED[line_release[0]]
        if line_release[1] <= highest_affected:
            return [
                Finding(
                    asset_id=asset_id,
                    source=Source.ARTEMIS,
                    title=f"Metabase vulnerable to {CVE_ID} (unauthenticated SQL injection)",
                    description=(
                        f"The instance reports version {version_tag}, within the range "
                        f"affected by {CVE_ID}: an unauthenticated attacker can inject SQL via "
                        "/api/session/reset_password to read credentials and escalate to admin."
                    ),
                    severity=Severity.CRITICAL,
                    cvss=9.8,
                    evidence=evidence,
                    remediation=f"Upgrade Metabase to {patched} or later; until then block the "
                    "/api/session/reset_password endpoint at the network edge.",
                    references=[ADVISORY_URL],
                )
            ]

    # Metabase detected but version could not be confirmed as vulnerable: still
    # worth a low-severity heads-up so the operator verifies manually.
    return [
        Finding(
            asset_id=asset_id,
            source=Source.ARTEMIS,
            title="Metabase instance exposed — verify version against CVE-2026-72898",
            description=(
                f"A Metabase instance was fingerprinted (version {version_tag}). Confirm it is "
                f"not within the range affected by {CVE_ID}."
            ),
            severity=Severity.LOW,
            evidence=evidence,
            remediation=f"Confirm the version is patched (see {ADVISORY_URL}).",
            references=[ADVISORY_URL],
        )
    ]
