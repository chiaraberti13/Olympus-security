"""Synthetic "Olympus Demo Corp" alerts/findings used by `minerva demo`.

A small, fully offline scenario: an Apollo brute-force alert correlated
with a Helios finding for an exposed high-risk service, giving the demo
incident something realistic to aggregate.
"""

from __future__ import annotations

from olympus.core.enums import Severity, Source
from olympus.core.models import Alert, Finding


def demo_alerts() -> list[Alert]:
    """Return a synthetic Apollo-style brute-force alert."""
    return [
        Alert(
            title="Repeated authentication failure",
            description="Apollo rule APOLLO-BRUTE-FORCE-001 fired on the auth log.",
            source=Source.APOLLO,
            rule_id="APOLLO-BRUTE-FORCE-001",
            mitre_technique_id="T1110",
            severity=Severity.HIGH,
        )
    ]


def demo_findings() -> list[Finding]:
    """Return a synthetic Helios-style high-risk exposure finding."""
    return [
        Finding(
            asset_id="AST-2026-00001",
            source=Source.HELIOS,
            title="Open port 3389/tcp (rdp)",
            description="RDP is reachable on the perimeter host.",
            severity=Severity.HIGH,
        )
    ]
