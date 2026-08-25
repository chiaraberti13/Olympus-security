"""Request and result contracts for the AEGIS native scanner execution layer."""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from olympus.aegis.states import ExecutionState
from olympus.core.models import Asset, Finding

#: Maximum bytes of raw scanner output kept as evidence (bounded).
MAX_RAW_EVIDENCE = 200_000


@dataclass(frozen=True)
class ScanRequest:
    """A single, validated request to run one scanner against one target."""

    scanner: str
    target: str
    #: "host" (IP/hostname), "url", or "domain".
    target_kind: str = "host"
    #: Authorized hosts/domains for this engagement (exact host or domain suffix).
    allowed: tuple[str, ...] = ()
    timeout_seconds: int = 300
    #: The operator explicitly confirmed authorization for a real scan.
    authorized: bool = False
    #: Live execution is enabled (AEGIS_ENABLE_LIVE_SCANS / VAP_ENABLE_LIVE_SCANS).
    live_enabled: bool = False
    #: Explicit, opt-in simulation (never auto-enabled by a missing dependency).
    simulate: bool = False


@dataclass(frozen=True)
class Dependency:
    """What a scanner needs to run for real (shown on an UNAVAILABLE result)."""

    executable: str | None
    install: str
    version_expected: str
    diagnostic: str

    def to_dict(self) -> dict[str, object]:
        return {
            "executable": self.executable,
            "install": self.install,
            "version_expected": self.version_expected,
            "diagnostic": self.diagnostic,
        }


@dataclass(frozen=True)
class ScanResult:
    """The outcome of one scanner invocation, with an explicit execution state."""

    scanner: str
    state: ExecutionState
    target: str
    version: str | None = None
    findings: list[Finding] = field(default_factory=list)
    assets: list[Asset] = field(default_factory=list)
    raw_evidence: str = ""
    error: str | None = None
    dependency: Dependency | None = None
    exit_code: int | None = None
    duration_seconds: float = 0.0

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serializable view of the result."""
        return {
            "scanner": self.scanner,
            "state": self.state.value,
            "target": self.target,
            "version": self.version,
            "finding_count": len(self.findings),
            "findings": [json.loads(f.model_dump_json()) for f in self.findings],
            "assets": [json.loads(a.model_dump_json()) for a in self.assets],
            "raw_evidence": self.raw_evidence[:MAX_RAW_EVIDENCE],
            "error": self.error,
            "dependency": self.dependency.to_dict() if self.dependency else None,
            "exit_code": self.exit_code,
            "duration_seconds": round(self.duration_seconds, 3),
        }
