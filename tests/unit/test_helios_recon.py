"""Unit tests for Helios host recon, against an offline fake PortScanner."""

from __future__ import annotations

from olympus.helios.recon import HostRecon, scan_host

HOST = "203.0.113.10"


class FakeScanner:
    """Offline PortScanner double backed by an in-memory set of open ports."""

    def __init__(self, open_ports: set[int]) -> None:
        self._open_ports = open_ports

    def is_open(self, host: str, port: int) -> bool:
        return port in self._open_ports


def test_scan_host_reports_open_ports_sorted() -> None:
    result = scan_host(HOST, FakeScanner({443, 22, 8080}), ports=(22, 80, 443, 8080))

    assert isinstance(result, HostRecon)
    assert result.host == HOST
    assert result.open_ports == [22, 443, 8080]


def test_scan_host_no_open_ports() -> None:
    result = scan_host(HOST, FakeScanner(set()), ports=(22, 80, 443))
    assert result.open_ports == []


def test_scan_host_only_probes_the_given_ports() -> None:
    # Port 3389 is "open" in the fixture but not in the requested profile.
    result = scan_host(HOST, FakeScanner({3389}), ports=(22, 80, 443))
    assert result.open_ports == []


def test_scan_host_uses_common_ports_by_default() -> None:
    result = scan_host(HOST, FakeScanner({22, 443}))
    assert result.open_ports == [22, 443]


def test_to_dict_is_json_serializable() -> None:
    result = scan_host(HOST, FakeScanner({22}), ports=(22, 80))
    payload = result.to_dict()

    assert payload["host"] == HOST
    assert payload["open_ports"] == [22]
    assert isinstance(payload["scanned_at"], str)
