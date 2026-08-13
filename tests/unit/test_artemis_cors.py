"""Unit tests for Artemis CORS misconfiguration detection."""

from __future__ import annotations

from olympus.artemis.cors import analyze_cors
from olympus.artemis.http_client import HttpResponse

ASSET_ID = "AST-2026-00001"


def test_no_cors_headers_yields_no_findings() -> None:
    response = HttpResponse(status_code=200, headers={})
    assert analyze_cors(ASSET_ID, response) == []


def test_wildcard_with_credentials_is_flagged() -> None:
    response = HttpResponse(
        status_code=200,
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        },
    )
    findings = analyze_cors(ASSET_ID, response)

    assert len(findings) == 1
    assert findings[0].title == "CORS wildcard origin with credentials allowed"
    assert findings[0].asset_id == ASSET_ID


def test_wildcard_without_credentials_is_safe() -> None:
    response = HttpResponse(status_code=200, headers={"Access-Control-Allow-Origin": "*"})
    assert analyze_cors(ASSET_ID, response) == []


def test_reflected_origin_with_credentials_is_flagged() -> None:
    response = HttpResponse(
        status_code=200,
        headers={
            "Access-Control-Allow-Origin": "https://evil.example",
            "Access-Control-Allow-Credentials": "true",
        },
    )
    findings = analyze_cors(ASSET_ID, response, request_origin="https://evil.example")

    assert len(findings) == 1
    assert findings[0].title == "CORS reflects arbitrary Origin with credentials allowed"


def test_reflected_origin_without_credentials_is_safe() -> None:
    response = HttpResponse(
        status_code=200,
        headers={"Access-Control-Allow-Origin": "https://evil.example"},
    )
    assert analyze_cors(ASSET_ID, response, request_origin="https://evil.example") == []


def test_fixed_trusted_origin_with_credentials_is_safe() -> None:
    # A specific, legitimate partner origin allowed with credentials is a
    # normal, intentional CORS configuration -- not a misconfiguration.
    response = HttpResponse(
        status_code=200,
        headers={
            "Access-Control-Allow-Origin": "https://partner.olympusdemocorp.example",
            "Access-Control-Allow-Credentials": "true",
        },
    )
    findings = analyze_cors(ASSET_ID, response, request_origin="https://evil.example")
    assert findings == []


def test_null_origin_reflection_is_not_flagged_as_reflection() -> None:
    # "null" is a special Origin value (sandboxed iframes, file://) and
    # reflecting it is a distinct, separately-known issue -- not counted
    # as arbitrary-origin reflection here.
    response = HttpResponse(
        status_code=200,
        headers={
            "Access-Control-Allow-Origin": "null",
            "Access-Control-Allow-Credentials": "true",
        },
    )
    assert analyze_cors(ASSET_ID, response, request_origin="null") == []
