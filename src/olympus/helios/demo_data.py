"""Synthetic, fully offline "Olympus Demo Corp" dataset used by `helios demo`.

Every address lives in the RFC 5737 TEST-NET-3 documentation range
(``203.0.113.0/24``), matching the same demo range Argus uses, so nothing
here ever touches a real host. One host exposes only low-risk services;
the other intentionally exposes high-risk ones, so the demo's Alert
generation (T-124) has something real to fire on.
"""

from __future__ import annotations

from typing import ClassVar

DEMO_HOSTS: tuple[str, ...] = ("203.0.113.10", "203.0.113.20")


class DemoScanner:
    """Offline PortScanner double serving a synthetic demo port map."""

    _OPEN_PORTS: ClassVar[dict[str, frozenset[int]]] = {
        "203.0.113.10": frozenset({22, 80, 443}),
        "203.0.113.20": frozenset({21, 23, 3389}),  # intentionally high-risk
    }

    def is_open(self, host: str, port: int) -> bool:
        """Return whether ``port`` is in the canned open-port set for ``host``."""
        return port in self._OPEN_PORTS.get(host, frozenset())
