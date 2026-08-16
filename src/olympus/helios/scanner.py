"""Bounded, non-destructive TCP surface discovery."""

from __future__ import annotations

import socket
from dataclasses import dataclass
from typing import Protocol


class Connector(Protocol):
    """TCP connection probe abstraction."""

    def is_open(self, host: str, port: int, timeout: float) -> bool:
        """Return whether one TCP connection can be established."""
        ...


class SocketConnector:
    """Production connector using one bounded TCP handshake per port."""

    def is_open(self, host: str, port: int, timeout: float) -> bool:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except OSError:
            return False


# Well-known TCP services, identified passively from the port number alone
# (no application data is ever sent — Helios stays non-destructive).
_SERVICE_NAMES: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 135: "msrpc", 139: "netbios-ssn", 143: "imap", 443: "https",
    445: "smb", 465: "smtps", 587: "submission", 993: "imaps", 995: "pop3s",
    1433: "mssql", 1521: "oracle", 2049: "nfs", 3306: "mysql", 3389: "rdp",
    5432: "postgres", 5900: "vnc", 6379: "redis", 8080: "http-alt",
    8443: "https-alt", 9200: "elasticsearch", 27017: "mongodb",
}

# Services that are risky to expose to untrusted networks (cleartext admin,
# databases, remote desktop...). Everything else is informational.
_RISKY_SERVICES: frozenset[str] = frozenset(
    {"telnet", "ftp", "rdp", "vnc", "smb", "mssql", "mysql", "postgres", "redis",
     "mongodb", "elasticsearch", "oracle", "nfs"}
)


def service_for(port: int) -> str:
    """Return the well-known service name for ``port``, or ``"unknown"``."""
    return _SERVICE_NAMES.get(port, "unknown")


def is_risky(service: str) -> bool:
    """Return whether exposing ``service`` to untrusted networks is risky."""
    return service in _RISKY_SERVICES


@dataclass(frozen=True)
class OpenPort:
    """An observed TCP listening port, with its passively identified service."""

    host: str
    port: int
    service: str = "unknown"


def discover(
    host: str, ports: list[int], connector: Connector, timeout: float = 1.0
) -> list[OpenPort]:
    """Probe at most 128 unique valid ports without sending application data."""
    normalized = sorted(set(ports))
    invalid_port = any(not 1 <= port <= 65535 for port in normalized)
    if not normalized or len(normalized) > 128 or invalid_port:
        raise ValueError("ports must contain 1 to 128 values in the range 1..65535")
    if not 0.05 <= timeout <= 10.0:
        raise ValueError("timeout must be between 0.05 and 10 seconds")
    return [
        OpenPort(host, port, service_for(port))
        for port in normalized
        if connector.is_open(host, port, timeout)
    ]
