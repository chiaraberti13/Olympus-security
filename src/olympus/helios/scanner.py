"""TCP connect port scanning.

Minimal-footprint attack-surface mapping: a plain TCP connect per
(host, port) pair, nothing more intrusive (no banner grabbing, no
exploitation). Every consumer talks to the :class:`PortScanner` protocol,
never to :mod:`socket` directly, so a real scanner (production) and a fake
in-memory scanner (tests) are interchangeable — mirroring Argus's
``DnsResolver`` design.
"""

from __future__ import annotations

import socket
from typing import Protocol

# A small, well-known port profile -- not a full 1-65535 sweep -- keeps the
# scan fast and its footprint minimal, per the platform's non-destructive
# posture for offensive modules.
COMMON_PORTS: tuple[int, ...] = (
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    143,
    443,
    445,
    3306,
    3389,
    5432,
    8080,
    8443,
)


class PortScanner(Protocol):
    """Anything able to check whether a single TCP port is open on a host."""

    def is_open(self, host: str, port: int) -> bool:
        """Return ``True`` if a TCP connection to ``host``:``port`` succeeds."""
        ...


class TcpConnectScanner:
    """Production :class:`PortScanner`: a plain TCP connect with a short timeout."""

    def __init__(self, timeout: float = 1.5) -> None:
        self._timeout = timeout

    def is_open(self, host: str, port: int) -> bool:
        """Return ``True`` if a TCP connect to ``host``:``port`` succeeds."""
        try:
            with socket.create_connection((host, port), timeout=self._timeout):
                return True
        except OSError:
            return False
