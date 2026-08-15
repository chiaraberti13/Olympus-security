"""Unit tests for the shared core HTTP client (network calls are stubbed)."""

from __future__ import annotations

import io
from typing import Any

import pytest

from olympus.core.http import USER_AGENT, HttpRequestError, UrllibHttpClient


class _FakeHttpResponse:
    def __init__(self, status: int, headers: dict[str, str], body: bytes) -> None:
        self.status = status
        self.headers = headers
        self._body = io.BytesIO(body)

    def read(self) -> bytes:
        return self._body.read()

    def __enter__(self) -> _FakeHttpResponse:
        return self

    def __exit__(self, *exc_info: object) -> None:
        return None


def test_request_sends_honest_user_agent(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    def _capture(request: Any, timeout: float = 0.0) -> _FakeHttpResponse:
        captured["headers"] = request.headers
        return _FakeHttpResponse(200, {}, b"ok")

    monkeypatch.setattr("urllib.request.urlopen", _capture)

    UrllibHttpClient().get("https://olympusdemocorp.example/")

    # urllib title-cases header keys; the honest Olympus UA must be present and
    # must NOT impersonate a browser (no detection evasion).
    assert captured["headers"]["User-agent"] == USER_AGENT
    assert "Mozilla" not in USER_AGENT


def test_extra_headers_are_merged(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    def _capture(request: Any, timeout: float = 0.0) -> _FakeHttpResponse:
        captured["headers"] = request.headers
        return _FakeHttpResponse(200, {}, b"ok")

    monkeypatch.setattr("urllib.request.urlopen", _capture)

    UrllibHttpClient().get(
        "https://olympusdemocorp.example/", headers={"Accept": "application/json"}
    )

    assert captured["headers"]["Accept"] == "application/json"
    assert captured["headers"]["User-agent"] == USER_AGENT


def test_rejects_non_http_scheme() -> None:
    with pytest.raises(HttpRequestError, match="non-HTTP"):
        UrllibHttpClient().get("file:///etc/passwd")
