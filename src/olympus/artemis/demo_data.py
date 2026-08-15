"""Synthetic, fully offline "Olympus Demo Corp" website used by `artemis demo`.

Deliberately misconfigured so the demo has something real to find: no
security headers, a wildcard CORS policy combined with credentials, and
an exposed ``.env`` file. Everything else responds 404, exactly like a
real content-discovery sweep against a mostly-clean site.
"""

from __future__ import annotations

from typing import ClassVar

from olympus.artemis.http_client import HttpResponse

DEMO_URL = "https://olympusdemocorp.example"


class DemoClient:
    """Offline HttpClient double serving a synthetic, misconfigured demo website."""

    _RESPONSES: ClassVar[dict[str, HttpResponse]] = {
        DEMO_URL: HttpResponse(
            status_code=200,
            headers={
                "Content-Type": "text/html",
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true",
            },
            body="<html><body>Olympus Demo Corp</body></html>",
        ),
        f"{DEMO_URL}/.env": HttpResponse(status_code=200, body="DB_PASSWORD=hunter2"),
        # A synthetic Metabase instance on an affected version line (60.10),
        # so the CVE-2026-72898 check has something real to flag.
        f"{DEMO_URL}/api/session/properties": HttpResponse(
            status_code=200,
            headers={"Content-Type": "application/json"},
            body='{"version": {"tag": "v0.60.10"}, "engine": "metabase"}',
        ),
        f"{DEMO_URL}/api/session/reset_password": HttpResponse(status_code=405),
    }

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> HttpResponse:
        """Return the canned response for ``url``, or a plain 404."""
        return self._RESPONSES.get(url, HttpResponse(status_code=404))
