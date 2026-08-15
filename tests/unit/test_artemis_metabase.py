"""Unit tests for the Artemis Metabase CVE-2026-72898 exposure check."""

from __future__ import annotations

from olympus.artemis.metabase import CVE_ID, detect_metabase
from olympus.core.enums import Severity
from olympus.core.http import HttpRequestError, HttpResponse

ASSET = "AST-2026-00001"
BASE = "https://target.example"


class _Client:
    """Offline HttpClient double: canned responses keyed by URL suffix."""

    def __init__(self, responses: dict[str, HttpResponse], *, error: bool = False) -> None:
        self._responses = responses
        self._error = error

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> HttpResponse:
        if self._error:
            raise HttpRequestError("boom")
        for suffix, response in self._responses.items():
            if url.endswith(suffix):
                return response
        return HttpResponse(status_code=404)


def _properties(tag: str) -> HttpResponse:
    return HttpResponse(status_code=200, body=f'{{"version": {{"tag": "{tag}"}}}}')


def test_flags_affected_version_as_critical() -> None:
    client = _Client(
        {
            "/api/session/properties": _properties("v0.60.10"),
            "/api/session/reset_password": HttpResponse(status_code=405),
        }
    )
    findings = detect_metabase(ASSET, BASE, client)
    assert len(findings) == 1
    assert findings[0].severity is Severity.CRITICAL
    assert CVE_ID in findings[0].title
    assert findings[0].cvss == 9.8
    assert any("reset_password" in e for e in findings[0].evidence)


def test_patched_version_is_not_flagged_critical() -> None:
    client = _Client({"/api/session/properties": _properties("v0.60.17")})
    findings = detect_metabase(ASSET, BASE, client)
    # 60.17 is patched -> only the low-severity "verify" heads-up, never critical.
    assert all(f.severity is not Severity.CRITICAL for f in findings)
    assert findings[0].severity is Severity.LOW


def test_boundary_highest_affected_is_critical() -> None:
    client = _Client({"/api/session/properties": _properties("v0.62.8")})
    findings = detect_metabase(ASSET, BASE, client)
    assert findings[0].severity is Severity.CRITICAL


def test_non_metabase_endpoint_yields_nothing() -> None:
    client = _Client({"/api/session/properties": HttpResponse(status_code=200, body="hello")})
    assert detect_metabase(ASSET, BASE, client) == []


def test_missing_endpoint_yields_nothing() -> None:
    client = _Client({"/api/session/properties": HttpResponse(status_code=404)})
    assert detect_metabase(ASSET, BASE, client) == []


def test_network_error_yields_nothing() -> None:
    assert detect_metabase(ASSET, BASE, _Client({}, error=True)) == []


def test_unparseable_version_is_low_severity() -> None:
    client = _Client({"/api/session/properties": _properties("nightly-build")})
    findings = detect_metabase(ASSET, BASE, client)
    assert len(findings) == 1
    assert findings[0].severity is Severity.LOW


def test_invalid_json_properties_yields_nothing() -> None:
    client = _Client({"/api/session/properties": HttpResponse(status_code=200, body="{not json")})
    assert detect_metabase(ASSET, BASE, client) == []


def test_reset_endpoint_unreachable_still_flags_version() -> None:
    class _OnlyProps:
        def get(self, url: str, *, headers: dict[str, str] | None = None) -> HttpResponse:
            if url.endswith("/api/session/properties"):
                return _properties("v0.60.10")
            raise HttpRequestError("reset endpoint down")

    findings = detect_metabase(ASSET, BASE, _OnlyProps())
    assert findings[0].severity is Severity.CRITICAL
    assert all("reset_password" not in e for e in findings[0].evidence)


def test_check_never_posts_a_payload() -> None:
    """The detector must only ever issue GET requests (no exploitation)."""
    seen: list[str] = []

    class _Recorder:
        def get(self, url: str, *, headers: dict[str, str] | None = None) -> HttpResponse:
            seen.append(url)
            if url.endswith("/api/session/properties"):
                return _properties("v0.60.10")
            return HttpResponse(status_code=405)

    detect_metabase(ASSET, BASE, _Recorder())
    # Only the two known GET endpoints, nothing else, and no payload in any URL.
    assert all("UNION" not in url and "'" not in url for url in seen)
