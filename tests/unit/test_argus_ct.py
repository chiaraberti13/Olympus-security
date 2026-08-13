"""Unit tests for Argus Certificate Transparency subdomain enumeration.

CrtShClient network calls are stubbed via monkeypatch: no unit test in this
suite ever performs a real HTTP request.
"""

from __future__ import annotations

import io
import json
import urllib.error
from typing import Any

import pytest

from olympus.argus.ct import (
    CrtShClient,
    CtQueryError,
    CtRecon,
    enumerate_subdomains,
    extract_subdomains,
)

DOMAIN = "olympusdemocorp.example"

DEMO_CORP_CT_ENTRIES: list[dict[str, Any]] = [
    {
        "name_value": "olympusdemocorp.example\nwww.olympusdemocorp.example",
        "issuer_name": "Demo CA",
    },
    {"name_value": "*.mail.olympusdemocorp.example", "issuer_name": "Demo CA"},
    {"name_value": "unrelated-domain.example", "issuer_name": "Demo CA"},
    {"name_value": "WWW.OlympusDemoCorp.example", "issuer_name": "Demo CA"},  # dup, mixed case
]


class FakeCtClient:
    """Offline CertificateTransparencyClient double backed by an in-memory fixture."""

    def __init__(self, entries: list[dict[str, Any]]) -> None:
        self._entries = entries

    def query(self, domain: str) -> list[dict[str, Any]]:
        return list(self._entries)


def test_extract_subdomains_filters_dedups_and_strips_wildcards() -> None:
    subdomains = extract_subdomains(DEMO_CORP_CT_ENTRIES, DOMAIN)

    assert subdomains == [
        "mail.olympusdemocorp.example",
        "olympusdemocorp.example",
        "www.olympusdemocorp.example",
    ]


def test_extract_subdomains_ignores_unrelated_domains() -> None:
    subdomains = extract_subdomains(DEMO_CORP_CT_ENTRIES, DOMAIN)
    assert "unrelated-domain.example" not in subdomains


def test_extract_subdomains_handles_missing_name_value() -> None:
    assert extract_subdomains([{}], DOMAIN) == []


def test_enumerate_subdomains_returns_ct_recon() -> None:
    result = enumerate_subdomains(DOMAIN, FakeCtClient(DEMO_CORP_CT_ENTRIES))

    assert isinstance(result, CtRecon)
    assert result.domain == DOMAIN
    assert "www.olympusdemocorp.example" in result.subdomains
    payload = result.to_dict()
    assert payload["subdomains"] == result.subdomains
    assert isinstance(payload["queried_at"], str)


class _FakeHttpResponse:
    def __init__(self, payload: bytes) -> None:
        self._buffer = io.BytesIO(payload)

    def read(self) -> bytes:
        return self._buffer.read()

    def __enter__(self) -> _FakeHttpResponse:
        return self

    def __exit__(self, *exc_info: object) -> None:
        return None


def test_crtsh_client_parses_valid_response(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = json.dumps(DEMO_CORP_CT_ENTRIES).encode("utf-8")
    monkeypatch.setattr(
        "urllib.request.urlopen", lambda url, timeout=0.0: _FakeHttpResponse(payload)
    )

    client = CrtShClient()
    entries = client.query(DOMAIN)

    assert entries == DEMO_CORP_CT_ENTRIES


def test_crtsh_client_empty_response_returns_empty_list(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("urllib.request.urlopen", lambda url, timeout=0.0: _FakeHttpResponse(b""))
    assert CrtShClient().query(DOMAIN) == []


def test_crtsh_client_network_error_is_wrapped(monkeypatch: pytest.MonkeyPatch) -> None:
    def _raise(url: str, timeout: float = 0.0) -> Any:
        raise urllib.error.URLError("boom")

    monkeypatch.setattr("urllib.request.urlopen", _raise)
    with pytest.raises(CtQueryError, match="query failed"):
        CrtShClient().query(DOMAIN)


def test_crtsh_client_invalid_json_is_wrapped(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "urllib.request.urlopen", lambda url, timeout=0.0: _FakeHttpResponse(b"{not json")
    )
    with pytest.raises(CtQueryError, match="invalid JSON"):
        CrtShClient().query(DOMAIN)


def test_crtsh_client_unexpected_payload_shape_is_wrapped(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "urllib.request.urlopen",
        lambda url, timeout=0.0: _FakeHttpResponse(b'{"not": "a list"}'),
    )
    with pytest.raises(CtQueryError, match="unexpected payload"):
        CrtShClient().query(DOMAIN)
