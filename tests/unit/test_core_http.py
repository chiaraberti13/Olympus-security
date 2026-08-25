"""Unit tests for the shared core HTTP client (network calls are stubbed)."""

from __future__ import annotations

import io
import urllib.request
from typing import Any

import pytest

from olympus.core.http import (
    USER_AGENT,
    HttpRequestError,
    UrllibHttpClient,
    _ValidatingRedirectHandler,
)


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


def test_redirect_handler_validates_destination_before_following() -> None:
    checked: list[str] = []
    handler = _ValidatingRedirectHandler(checked.append)
    request = handler.redirect_request(
        urllib.request.Request("https://allowed.example/start"),
        None,
        302,
        "Found",
        {},
        "https://redirected.example/path",
    )

    assert checked == ["https://redirected.example/path"]
    assert request is not None


def test_redirect_handler_does_not_follow_rejected_destination() -> None:
    def reject(url: str) -> None:
        raise PermissionError(f"blocked: {url}")

    handler = _ValidatingRedirectHandler(reject)

    with pytest.raises(PermissionError, match="blocked"):
        handler.redirect_request(
            urllib.request.Request("https://allowed.example/start"),
            None,
            302,
            "Found",
            {},
            "http://127.0.0.1/admin",
        )


def test_request_sends_honest_user_agent(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    def _capture(request: Any, timeout: float = 0.0) -> _FakeHttpResponse:
        captured["headers"] = request.headers
        return _FakeHttpResponse(200, {}, b"ok")

    monkeypatch.setattr("urllib.request.urlopen", _capture)
    UrllibHttpClient().get("https://olympusdemocorp.example/")

    assert captured["headers"]["User-agent"] == USER_AGENT
    assert "Mozilla" not in USER_AGENT


def test_returns_normalized_response(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeHttpResponse(200, {"Content-Type": "text/html"}, b"<html>hi</html>")
    monkeypatch.setattr("urllib.request.urlopen", lambda request, timeout=0.0: fake)

    response = UrllibHttpClient().get("https://olympusdemocorp.example/")
    assert response.status_code == 200
    assert response.headers["Content-Type"] == "text/html"
    assert response.body == "<html>hi</html>"


def test_http_error_status_is_returned(monkeypatch: pytest.MonkeyPatch) -> None:
    import urllib.error

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


def test_network_error_is_wrapped(monkeypatch: pytest.MonkeyPatch) -> None:
    import urllib.error

    def _raise(request: Any, timeout: float = 0.0) -> Any:
        raise urllib.error.URLError("boom")

    monkeypatch.setattr("urllib.request.urlopen", _raise)
    with pytest.raises(HttpRequestError, match="HTTP GET failed"):
        UrllibHttpClient().get("https://olympusdemocorp.example/")


def test_rejects_non_http_scheme() -> None:
    with pytest.raises(HttpRequestError, match="non-HTTP"):
        UrllibHttpClient().get("file:///etc/passwd")


def test_retries_on_network_error_then_succeeds(monkeypatch: pytest.MonkeyPatch) -> None:
    import urllib.error

    calls = {"n": 0}
    monkeypatch.setattr("time.sleep", lambda _seconds: None)

    def _flaky(request: Any, timeout: float = 0.0) -> _FakeHttpResponse:
        calls["n"] += 1
        if calls["n"] < 3:
            raise urllib.error.URLError("temporary")
        return _FakeHttpResponse(200, {}, b"ok")

    monkeypatch.setattr("urllib.request.urlopen", _flaky)
    response = UrllibHttpClient(retries=2).get("https://olympusdemocorp.example/")
    assert response.status_code == 200
    assert calls["n"] == 3  # two failures then success


def test_raises_after_exhausting_retries(monkeypatch: pytest.MonkeyPatch) -> None:
    import urllib.error

    monkeypatch.setattr("time.sleep", lambda _seconds: None)

    def _always_fail(request: Any, timeout: float = 0.0) -> Any:
        raise urllib.error.URLError("down")

    monkeypatch.setattr("urllib.request.urlopen", _always_fail)
    with pytest.raises(HttpRequestError, match="HTTP GET failed"):
        UrllibHttpClient(retries=1).get("https://olympusdemocorp.example/")


def test_retries_on_retryable_status(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = {"n": 0}
    monkeypatch.setattr("time.sleep", lambda _seconds: None)

    def _rate_limited(request: Any, timeout: float = 0.0) -> _FakeHttpResponse:
        calls["n"] += 1
        if calls["n"] == 1:
            return _FakeHttpResponse(429, {}, b"slow down")
        return _FakeHttpResponse(200, {}, b"ok")

    monkeypatch.setattr("urllib.request.urlopen", _rate_limited)
    response = UrllibHttpClient(retries=2).get("https://olympusdemocorp.example/")
    assert response.status_code == 200
    assert calls["n"] == 2


def test_returns_last_response_when_retries_exhausted_on_5xx(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("time.sleep", lambda _seconds: None)
    monkeypatch.setattr(
        "urllib.request.urlopen", lambda request, timeout=0.0: _FakeHttpResponse(503, {}, b"busy")
    )
    response = UrllibHttpClient(retries=1).get("https://olympusdemocorp.example/")
    assert response.status_code == 503  # handed back, not raised


def test_rate_limit_sleeps_between_requests(monkeypatch: pytest.MonkeyPatch) -> None:
    slept: list[float] = []
    monkeypatch.setattr("time.sleep", lambda seconds: slept.append(seconds))
    times = iter([0.0, 0.0, 0.0, 0.1])  # monotonic() readings
    monkeypatch.setattr("time.monotonic", lambda: next(times))
    monkeypatch.setattr(
        "urllib.request.urlopen", lambda request, timeout=0.0: _FakeHttpResponse(200, {}, b"ok")
    )
    client = UrllibHttpClient(min_interval=1.0)
    client.get("https://olympusdemocorp.example/a")
    client.get("https://olympusdemocorp.example/b")
    assert any(s > 0 for s in slept)  # throttled the second request
