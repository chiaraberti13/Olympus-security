"""Unit tests for Artemis security header analysis."""

from __future__ import annotations

from olympus.artemis.headers import REQUIRED_HEADERS, analyze_headers
from olympus.artemis.http_client import HttpResponse

ASSET_ID = "AST-2026-00001"

ALL_HEADERS_PRESENT = {
    "Content-Security-Policy": "default-src 'self'",
    "Strict-Transport-Security": "max-age=63072000",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
}


def test_analyze_headers_no_findings_when_all_present() -> None:
    response = HttpResponse(status_code=200, headers=ALL_HEADERS_PRESENT)
    assert analyze_headers(ASSET_ID, response) == []


def test_analyze_headers_flags_every_missing_header() -> None:
    response = HttpResponse(status_code=200, headers={})
    findings = analyze_headers(ASSET_ID, response)

    assert len(findings) == len(REQUIRED_HEADERS)
    assert all(f.asset_id == ASSET_ID for f in findings)
    titles = {f.title for f in findings}
    assert "Missing security header: content-security-policy" in titles


def test_analyze_headers_is_case_insensitive() -> None:
    # Same headers as ALL_HEADERS_PRESENT, but with different casing.
    response = HttpResponse(
        status_code=200,
        headers={name.upper(): value for name, value in ALL_HEADERS_PRESENT.items()},
    )
    assert analyze_headers(ASSET_ID, response) == []


def test_analyze_headers_flags_only_the_missing_subset() -> None:
    headers = dict(ALL_HEADERS_PRESENT)
    del headers["Strict-Transport-Security"]
    response = HttpResponse(status_code=200, headers=headers)

    findings = analyze_headers(ASSET_ID, response)

    assert len(findings) == 1
    assert findings[0].title == "Missing security header: strict-transport-security"
