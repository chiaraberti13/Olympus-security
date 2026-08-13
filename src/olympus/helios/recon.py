"""Host-level attack-surface recon: which common ports are open.

Orchestrates :mod:`olympus.helios.scanner` into a snapshot per host,
mirroring the shape of Argus's ``DomainRecon``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from olympus.helios.scanner import COMMON_PORTS, PortScanner


@dataclass(frozen=True)
class HostRecon:
    """A snapshot of which ports were found open on a single host."""

    host: str
    open_ports: list[int] = field(default_factory=list)
    scanned_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable view of this recon snapshot."""
        return {
            "host": self.host,
            "open_ports": self.open_ports,
            "scanned_at": self.scanned_at.isoformat(),
        }


def scan_host(
    host: str, scanner: PortScanner, ports: tuple[int, ...] = COMMON_PORTS
) -> HostRecon:
    """Probe every port in ``ports`` on ``host`` and report which are open."""
    open_ports = sorted(port for port in ports if scanner.is_open(host, port))
    return HostRecon(host=host, open_ports=open_ports)
