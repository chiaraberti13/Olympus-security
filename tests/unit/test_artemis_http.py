"""Offline tests for bounded and redirect-safe Artemis HTTP flows."""

from __future__ import annotations

import json
import socket
import ssl
from pathlib import Path

import pytest
from typer.testing import CliRunner

from olympus.artemis import cli as artemis_cli
from olympus.artemis import http as artemis_http
from olympus.artemis.http import (
    HttpClientError,
    HttpResponse,
    PinnedTransport,
    SocketResolver,
    fetch_scoped,
)
from olympus.artemis.scope import OutOfScopeError, ScopeError
from olympus.cli import app

runner = CliRunner()


class FakeTransport:
    def __init__(self, responses: dict[str, HttpResponse]) -> None:
        self.responses = responses
        self.requested: list[tuple[str, tuple[str, ...], float, int]] = []

    def get(
        self, url: str, addresses: tuple[str, ...], timeout: float, max_bytes: int
    ) -> HttpResponse:
        self.requested.append((url, addresses, timeout, max_bytes))
        return self.responses[url]


class FakeResolver:
    def __init__(self, addresses: list[str] | None = None) -> None:
        self.addresses = ["192.0.2.10"] if addresses is None else addresses

    def resolve(self, hostname: str, port: int) -> list[str]:
        del hostname, port
        return self.addresses


def _scope(path: Path) -> Path:
    path.write_text(json.dumps({
        "allowed_origins": ["https://portal.olympusdemocorp.example"],
        "allowed_path_prefixes": ["/app"],
        "allowed_ip_networks": ["192.0.2.0/24", "2001:db8::/32"],
    }))
    return path


def test_fetch_follows_only_scope_checked_redirects(tmp_path: Path) -> None:
    login = "https://portal.olympusdemocorp.example/app/login"
    home = "https://portal.olympusdemocorp.example/app/home"
    transport = FakeTransport({
        login: HttpResponse(login, 302, {"location": "/app/home"}, b""),
        home: HttpResponse(home, 200, {"content-type": "text/html"}, b"demo"),
    })

    result = fetch_scoped(
        login,
        _scope(tmp_path / "scope.json"),
        tmp_path / "log",
        FakeResolver(),
        transport,
    )

    assert result.response.body == b"demo"
    assert result.redirects == [home]
    assert [request[0] for request in transport.requested] == [login, home]
    assert all(request[1] == ("192.0.2.10",) for request in transport.requested)


def test_fetch_blocks_redirect_before_second_request(tmp_path: Path) -> None:
    login = "https://portal.olympusdemocorp.example/app/login"
    transport = FakeTransport({
        login: HttpResponse(login, 302, {"location": "https://outside.example/steal"}, b"")
    })

    with pytest.raises(OutOfScopeError):
        fetch_scoped(
            login,
            _scope(tmp_path / "scope.json"),
            tmp_path / "log",
            FakeResolver(),
            transport,
        )
    assert len(transport.requested) == 1


def test_fetch_requires_every_ipv4_ipv6_answer_in_scope(tmp_path: Path) -> None:
    target = "https://portal.olympusdemocorp.example/app"
    transport = FakeTransport({target: HttpResponse(target, 200, {}, b"")})
    scope = _scope(tmp_path / "scope.json")

    fetch_scoped(
        target,
        scope,
        tmp_path / "log",
        FakeResolver(["192.0.2.10", "2001:db8::10"]),
        transport,
    )
    assert transport.requested[0][1] == ("192.0.2.10", "2001:db8::10")

    with pytest.raises(OutOfScopeError):
        fetch_scoped(
            target,
            scope,
            tmp_path / "blocked.log",
            FakeResolver(["192.0.2.10", "127.0.0.1"]),
            transport,
        )
    assert "resolved_address_not_allowed" in (tmp_path / "blocked.log").read_text()
    with pytest.raises(ScopeError, match="no addresses"):
        fetch_scoped(target, scope, tmp_path / "log", FakeResolver([]), transport)


def test_fetch_enforces_redirect_and_option_limits(tmp_path: Path) -> None:
    login = "https://portal.olympusdemocorp.example/app/login"
    transport = FakeTransport({
        login: HttpResponse(login, 302, {"location": "/app/login"}, b"")
    })
    scope = _scope(tmp_path / "scope.json")

    with pytest.raises(HttpClientError, match="redirect limit"):
        fetch_scoped(login, scope, tmp_path / "log", FakeResolver(), transport, max_redirects=0)
    with pytest.raises(ValueError, match="timeout"):
        fetch_scoped(login, scope, tmp_path / "log", FakeResolver(), transport, timeout=0)
    with pytest.raises(ValueError, match="max_bytes"):
        fetch_scoped(login, scope, tmp_path / "log", FakeResolver(), transport, max_bytes=0)


def test_fetch_rejects_redirect_without_location(tmp_path: Path) -> None:
    login = "https://portal.olympusdemocorp.example/app/login"
    transport = FakeTransport({login: HttpResponse(login, 301, {}, b"")})
    with pytest.raises(HttpClientError, match="Location"):
        fetch_scoped(
            login,
            _scope(tmp_path / "scope.json"),
            tmp_path / "log",
            FakeResolver(),
            transport,
        )


class FakeRawResponse:
    status = 200

    def __init__(self, body: bytes) -> None:
        self.body = body
        self.headers = {"Content-Type": "text/plain"}

    def read(self, size: int) -> bytes:
        return self.body[:size]

    def getheaders(self) -> list[tuple[str, str]]:
        return list(self.headers.items())


class FakeConnection:
    response = FakeRawResponse(b"demo")

    def __init__(self, hostname: str, address: str, port: int, timeout: float) -> None:
        self.arguments = (hostname, address, port, timeout)

    def request(self, method: str, path: str, headers: dict[str, str]) -> None:
        del method, path, headers

    def getresponse(self) -> FakeRawResponse:
        return self.response

    def close(self) -> None:
        return None


def test_pinned_transport_enforces_scheme_address_and_size(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(artemis_http, "_PinnedHTTPSConnection", FakeConnection)
    response = PinnedTransport().get(
        "https://portal.olympusdemocorp.example/app", ("192.0.2.10",), 1.0, 4
    )
    assert response.body == b"demo"
    assert response.headers == {"content-type": "text/plain"}
    monkeypatch.setattr(artemis_http, "_PinnedHTTPConnection", FakeConnection)
    assert PinnedTransport().get(
        "http://portal.olympusdemocorp.example/app", ("192.0.2.10",), 1.0, 4
    ).status == 200

    with pytest.raises(HttpClientError, match=r"HTTP\(S\)"):
        PinnedTransport().get("file:///etc/passwd", ("192.0.2.10",), 1.0, 4)
    with pytest.raises(HttpClientError, match="pinned address"):
        PinnedTransport().get("https://example.test/", (), 1.0, 4)
    FakeConnection.response = FakeRawResponse(b"oversized")
    with pytest.raises(HttpClientError, match="byte limit"):
        PinnedTransport().get(
            "https://portal.olympusdemocorp.example/app", ("192.0.2.10",), 1.0, 4
        )


def test_socket_resolver_deduplicates_and_wraps_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    records = [
        (2, 1, 6, "", ("192.0.2.10", 443)),
        (2, 1, 6, "", ("192.0.2.10", 443)),
        (10, 1, 6, "", ("2001:db8::10", 443, 0, 0)),
    ]
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: records)
    assert SocketResolver().resolve("demo.example", 443) == ["192.0.2.10", "2001:db8::10"]

    def fail(*args: object, **kwargs: object) -> list[object]:
        raise OSError("synthetic DNS failure")

    monkeypatch.setattr(socket, "getaddrinfo", fail)
    with pytest.raises(HttpClientError, match="DNS resolution failed"):
        SocketResolver().resolve("demo.example", 443)


def test_pinned_connections_use_only_supplied_address(monkeypatch: pytest.MonkeyPatch) -> None:
    connected: list[tuple[str, int]] = []

    def connect(address: tuple[str, int], timeout: float) -> object:
        del timeout
        connected.append(address)
        return object()

    class FakeContext:
        # http.client reads these SSLContext attributes before wrapping the
        # socket (Python 3.11+); expose them so the stub matches a real context.
        verify_mode = ssl.CERT_NONE
        check_hostname = False

        def wrap_socket(self, raw_socket: object, server_hostname: str) -> object:
            del server_hostname
            return raw_socket

    monkeypatch.setattr(socket, "create_connection", connect)
    monkeypatch.setattr(ssl, "create_default_context", FakeContext)
    plain = artemis_http._PinnedHTTPConnection("demo.example", "192.0.2.10", 80, 1.0)
    secure = artemis_http._PinnedHTTPSConnection("demo.example", "2001:db8::10", 443, 1.0)
    plain.connect()
    secure.connect()

    assert connected == [("192.0.2.10", 80), ("2001:db8::10", 443)]


def test_fetch_cli_prints_metadata_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = "https://portal.olympusdemocorp.example/app"
    transport = FakeTransport({target: HttpResponse(target, 200, {}, b"BODY-CONTENT")})
    monkeypatch.setattr(artemis_cli, "PinnedTransport", lambda: transport)
    monkeypatch.setattr(artemis_cli, "SocketResolver", FakeResolver)

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
