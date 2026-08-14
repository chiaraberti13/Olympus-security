"""Core Finding export for Helios observations."""

import json
from pathlib import Path

from olympus.core.enums import Severity, Source
from olympus.core.models import Finding
from olympus.helios.scanner import OpenPort


def to_findings(asset_id: str, observations: list[OpenPort]) -> list[Finding]:
    """Convert open ports into informational shared findings."""
    return [
        Finding(
            asset_id=asset_id,
            source=Source.HELIOS,
            title=f"TCP port {item.port} exposed",
            description=f"A bounded TCP handshake succeeded on {item.host}:{item.port}.",
            severity=Severity.INFO,
            evidence=[f"tcp://{item.host}:{item.port}"],
        )
        for item in observations
    ]


def export_findings(findings: list[Finding], output: Path) -> None:
    """Write a versioned Helios finding document atomically."""
    output.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_name": "olympus.helios-findings",
        "schema_version": "1.0.0",
        "findings": [item.model_dump(mode="json") for item in findings],
    }
    temporary = output.with_suffix(f"{output.suffix}.tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(output)
