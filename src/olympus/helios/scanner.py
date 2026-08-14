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


@dataclass(frozen=True)
class OpenPort:
    """An observed TCP listening port."""

    host: str
    port: int


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
    return [OpenPort(host, port) for port in normalized if connector.is_open(host, port, timeout)]
