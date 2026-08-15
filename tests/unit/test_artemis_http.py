"""Offline tests for bounded and redirect-safe Artemis HTTP flows."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from olympus.artemis import cli as artemis_cli
from olympus.artemis import http as artemis_http
from olympus.artemis.http import HttpClientError, HttpResponse, UrllibTransport, fetch_scoped
from olympus.artemis.scope import OutOfScopeError
from olympus.cli import app

runner = CliRunner()


class FakeTransport:
    def __init__(self, responses: dict[str, HttpResponse]) -> None:
        self.responses = responses
        self.requested: list[tuple[str, float, int]] = []

    def get(self, url: str, timeout: float, max_bytes: int) -> HttpResponse:
        self.requested.append((url, timeout, max_bytes))
        return self.responses[url]


def _scope(path: Path) -> Path:
    path.write_text(json.dumps({
        "allowed_origins": ["https://portal.olympusdemocorp.example"],
        "allowed_path_prefixes": ["/app"],
    }))
    return path


def test_fetch_follows_only_scope_checked_redirects(tmp_path: Path) -> None:
    login = "https://portal.olympusdemocorp.example/app/login"
    home = "https://portal.olympusdemocorp.example/app/home"
    transport = FakeTransport({
        login: HttpResponse(login, 302, {"location": "/app/home"}, b""),
        home: HttpResponse(home, 200, {"content-type": "text/html"}, b"demo"),
    })

    result = fetch_scoped(login, _scope(tmp_path / "scope.json"), tmp_path / "log", transport)

    assert result.response.body == b"demo"
    assert result.redirects == [home]
    assert [request[0] for request in transport.requested] == [login, home]


def test_fetch_blocks_redirect_before_second_request(tmp_path: Path) -> None:
    login = "https://portal.olympusdemocorp.example/app/login"
    transport = FakeTransport({
        login: HttpResponse(login, 302, {"location": "https://outside.example/steal"}, b"")
    })

    with pytest.raises(OutOfScopeError):
        fetch_scoped(login, _scope(tmp_path / "scope.json"), tmp_path / "log", transport)
    assert len(transport.requested) == 1


def test_fetch_enforces_redirect_and_option_limits(tmp_path: Path) -> None:
    login = "https://portal.olympusdemocorp.example/app/login"
    transport = FakeTransport({
        login: HttpResponse(login, 302, {"location": "/app/login"}, b"")
    })
    scope = _scope(tmp_path / "scope.json")

    with pytest.raises(HttpClientError, match="redirect limit"):
        fetch_scoped(login, scope, tmp_path / "log", transport, max_redirects=0)
    with pytest.raises(ValueError, match="timeout"):
        fetch_scoped(login, scope, tmp_path / "log", transport, timeout=0)
    with pytest.raises(ValueError, match="max_bytes"):
        fetch_scoped(login, scope, tmp_path / "log", transport, max_bytes=0)


def test_fetch_rejects_redirect_without_location(tmp_path: Path) -> None:
    login = "https://portal.olympusdemocorp.example/app/login"
    transport = FakeTransport({login: HttpResponse(login, 301, {}, b"")})
    with pytest.raises(HttpClientError, match="Location"):
        fetch_scoped(
            login, _scope(tmp_path / "scope.json"), tmp_path / "log", transport
        )


class FakeRawResponse:
    status = 200

    def __init__(self, body: bytes) -> None:
        self.body = body
        self.headers = {"Content-Type": "text/plain"}

    def read(self, size: int) -> bytes:
        return self.body[:size]

    def geturl(self) -> str:
        return "https://portal.olympusdemocorp.example/app"

    def __enter__(self) -> FakeRawResponse:
        return self

    def __exit__(self, *args: object) -> None:
        return None


class FakeOpener:
    def __init__(self, response: FakeRawResponse) -> None:
        self.response = response

    def open(self, request: object, timeout: float) -> FakeRawResponse:
        del request, timeout
        return self.response


def test_urllib_transport_enforces_scheme_and_size(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        artemis_http,
        "build_opener",
        lambda handler: FakeOpener(FakeRawResponse(b"demo")),
    )
    response = UrllibTransport().get(
        "https://portal.olympusdemocorp.example/app", 1.0, 4
    )
    assert response.body == b"demo"
    assert response.headers == {"content-type": "text/plain"}

    with pytest.raises(HttpClientError, match=r"HTTP\(S\)"):
        UrllibTransport().get("file:///etc/passwd", 1.0, 4)
    monkeypatch.setattr(
        artemis_http,
        "build_opener",
        lambda handler: FakeOpener(FakeRawResponse(b"oversized")),
    )
    with pytest.raises(HttpClientError, match="byte limit"):
        UrllibTransport().get(
            "https://portal.olympusdemocorp.example/app", 1.0, 4
        )


def test_fetch_cli_prints_metadata_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = "https://portal.olympusdemocorp.example/app"
    transport = FakeTransport({target: HttpResponse(target, 200, {}, b"BODY-CONTENT")})
    monkeypatch.setattr(artemis_cli, "UrllibTransport", lambda: transport)

    result = runner.invoke(
        app,
        [
            "artemis",
            "fetch",
            "--url",
            target,
            "--scope",
            str(_scope(tmp_path / "scope.json")),
            "--log",
            str(tmp_path / "log"),
        ],
    )

    assert result.exit_code == 0
    assert json.loads(result.stdout)["body_bytes"] == 12
    assert "BODY-CONTENT" not in result.stdout
