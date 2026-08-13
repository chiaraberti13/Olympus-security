"""Unit tests for Artemis's UrllibHttpClient (network calls are stubbed)."""

from __future__ import annotations

import io
import urllib.error
from typing import Any

import pytest

from olympus.artemis.http_client import HttpRequestError, UrllibHttpClient


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


def test_get_returns_normalized_response(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeHttpResponse(200, {"Content-Type": "text/html"}, b"<html>hi</html>")
    monkeypatch.setattr("urllib.request.urlopen", lambda request, timeout=0.0: fake)

    response = UrllibHttpClient().get("https://olympusdemocorp.example/")

    assert response.status_code == 200
    assert response.headers["Content-Type"] == "text/html"
    assert response.body == "<html>hi</html>"


def test_get_rejects_non_http_scheme() -> None:
    with pytest.raises(HttpRequestError, match="non-HTTP"):
        UrllibHttpClient().get("ftp://olympusdemocorp.example/")


def test_get_returns_response_for_http_error_status(monkeypatch: pytest.MonkeyPatch) -> None:
    def _raise(request: Any, timeout: float = 0.0) -> Any:
        raise urllib.error.HTTPError(
            "https://olympusdemocorp.example/missing",
            404,
            "Not Found",
            {"Content-Type": "text/plain"},  # type: ignore[arg-type]
            io.BytesIO(b"not found"),
        )

    monkeypatch.setattr("urllib.request.urlopen", _raise)

    response = UrllibHttpClient().get("https://olympusdemocorp.example/missing")

    assert response.status_code == 404
    assert response.body == "not found"


def test_get_network_error_is_wrapped(monkeypatch: pytest.MonkeyPatch) -> None:
    def _raise(request: Any, timeout: float = 0.0) -> Any:
        raise urllib.error.URLError("boom")

    monkeypatch.setattr("urllib.request.urlopen", _raise)

    with pytest.raises(HttpRequestError, match="HTTP GET failed"):
        UrllibHttpClient().get("https://olympusdemocorp.example/")
