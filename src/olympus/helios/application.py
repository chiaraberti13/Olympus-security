"""Application boundary for authorized, bounded Helios discovery."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from olympus.core.execution import Cancellation, ExecutionPolicy, NeverCancelled
from olympus.core.models import Finding, Observation
from olympus.helios.export import to_findings, to_observations
from olympus.helios.scanner import Connector, OpenPort, discover, normalize_ports
from olympus.helios.scope import enforce_scope


@dataclass(frozen=True)
class SurfaceScanRequest:
    """Command-independent input and policy for one TCP surface scan."""

    target: str
    ports: tuple[int, ...]
    scope_path: Path
    audit_log_path: Path
    asset_id: str
    authorized: bool = False
    timeout_seconds: float = 1.0


@dataclass(frozen=True)
class SurfaceScanOutcome:
    """Real open-port observations and their derived findings."""

    open_ports: tuple[OpenPort, ...]
    observations: tuple[Observation, ...]
    findings: tuple[Finding, ...]


@dataclass(frozen=True)
class SurfaceScanService:
    """Authorize, scope, execute, and normalize Helios without Typer."""

    connector: Connector
    cancellation: Cancellation = field(default_factory=NeverCancelled)

    def run(self, request: SurfaceScanRequest) -> SurfaceScanOutcome:
        ports = normalize_ports(list(request.ports))
        policy = ExecutionPolicy(
            authorized=request.authorized,
            timeout_seconds=request.timeout_seconds,
            deadline_seconds=request.timeout_seconds * len(ports),
        )
        policy.authorize_target(
            "Helios surface scan",
            request.target,
            lambda target: enforce_scope(target, request.scope_path, request.audit_log_path),
        )
        policy.check_cancellation(self.cancellation)
        open_ports = discover(
            request.target,
            list(ports),
            self.connector,
            timeout=policy.timeout_seconds,
            cancellation=self.cancellation,
        )
        findings = to_findings(request.asset_id, open_ports)
        observations = to_observations(request.asset_id, open_ports)
        return SurfaceScanOutcome(tuple(open_ports), tuple(observations), tuple(findings))
