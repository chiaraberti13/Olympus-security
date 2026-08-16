"""Core Finding export for Helios observations."""

import json
from pathlib import Path

from olympus.core.enums import Severity, Source
from olympus.core.models import Finding
from olympus.helios.scanner import OpenPort, is_risky


def to_findings(asset_id: str, observations: list[OpenPort]) -> list[Finding]:
    """Convert open ports into shared findings, flagging risky exposed services."""
    findings: list[Finding] = []
    for item in observations:
        risky = is_risky(item.service)
        findings.append(
            Finding(
                asset_id=asset_id,
                source=Source.HELIOS,
                title=f"TCP port {item.port} exposed ({item.service})",
                description=(
                    f"A bounded TCP handshake succeeded on {item.host}:{item.port} "
                    f"(service: {item.service})."
                    + (
                        " Exposing this service to untrusted networks is high-risk."
                        if risky
                        else ""
                    )
                ),
                severity=Severity.MEDIUM if risky else Severity.INFO,
                evidence=[f"tcp://{item.host}:{item.port} ({item.service})"],
                remediation=(
                    "Restrict access to this service (firewall/VPN) or disable it if unused."
                    if risky
                    else ""
                ),
            )
        )
    return findings


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
