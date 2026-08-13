"""Unit tests for Artemis content discovery."""

from __future__ import annotations

from olympus.artemis.discovery import discover_content
from olympus.artemis.http_client import HttpResponse

ASSET_ID = "AST-2026-00001"
BASE_URL = "https://olympusdemocorp.example"


class _FakeClient:
    """Offline HttpClient double returning canned status codes per path."""

    def __init__(self, reachable_paths: set[str]) -> None:
        self._reachable_paths = reachable_paths

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> HttpResponse:
        path = url.removeprefix(BASE_URL)
        status = 200 if path in self._reachable_paths else 404
        return HttpResponse(status_code=status)


def test_discover_content_flags_reachable_sensitive_paths() -> None:
    client = _FakeClient({"/.env"})
    findings = discover_content(ASSET_ID, BASE_URL, client)

    assert len(findings) == 1
    assert findings[0].title == "Exposed path: /.env"
    assert findings[0].asset_id == ASSET_ID
    assert findings[0].severity.value == "critical"


def test_discover_content_no_findings_when_nothing_reachable() -> None:
    client = _FakeClient(set())
    assert discover_content(ASSET_ID, BASE_URL, client) == []


def test_discover_content_flags_every_reachable_path() -> None:
    client = _FakeClient({"/.git/config", "/.env", "/admin"})
    findings = discover_content(ASSET_ID, BASE_URL, client)

    titles = {f.title for f in findings}
    assert titles == {
        "Exposed path: /.git/config",
        "Exposed path: /.env",
        "Exposed path: /admin",
    }


def test_discover_content_records_evidence_with_status_code() -> None:
    client = _FakeClient({"/.env"})
    findings = discover_content(ASSET_ID, BASE_URL, client)

    assert findings[0].evidence == [f"GET {BASE_URL}/.env -> 200"]


def test_discover_content_strips_trailing_slash_from_base_url() -> None:
    client = _FakeClient({"/.env"})
    findings = discover_content(ASSET_ID, f"{BASE_URL}/", client)
    assert findings[0].evidence == [f"GET {BASE_URL}/.env -> 200"]
