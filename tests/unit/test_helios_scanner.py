"""Unit tests for Helios's TcpConnectScanner (socket calls are stubbed)."""

from __future__ import annotations

import socket
from typing import Any

import pytest

from olympus.helios.scanner import TcpConnectScanner


class _FakeConnection:
    def __enter__(self) -> _FakeConnection:
        return self

    def __exit__(self, *exc_info: object) -> None:
        return None


def test_is_open_returns_true_on_successful_connect(monkeypatch: pytest.MonkeyPatch) -> None:
    def _fake_create_connection(address: tuple[str, int], timeout: float = 0.0) -> Any:
        return _FakeConnection()

    monkeypatch.setattr(socket, "create_connection", _fake_create_connection)
    assert TcpConnectScanner().is_open("203.0.113.10", 443) is True


def test_is_open_returns_false_on_connection_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    def _fake_create_connection(address: tuple[str, int], timeout: float = 0.0) -> Any:
        raise ConnectionRefusedError

    monkeypatch.setattr(socket, "create_connection", _fake_create_connection)
    assert TcpConnectScanner().is_open("203.0.113.10", 9) is False


def test_is_open_returns_false_on_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    def _fake_create_connection(address: tuple[str, int], timeout: float = 0.0) -> Any:
        raise TimeoutError

    monkeypatch.setattr(socket, "create_connection", _fake_create_connection)
    assert TcpConnectScanner().is_open("203.0.113.10", 9) is False


def test_is_open_passes_configured_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, Any] = {}

    def _fake_create_connection(address: tuple[str, int], timeout: float = 0.0) -> Any:
        seen["address"] = address
        seen["timeout"] = timeout
        return _FakeConnection()

    monkeypatch.setattr(socket, "create_connection", _fake_create_connection)
    TcpConnectScanner(timeout=0.5).is_open("203.0.113.10", 22)

    assert seen["address"] == ("203.0.113.10", 22)
    assert seen["timeout"] == 0.5
