"""Base class for AEGIS external-CLI scanner adapters.

An adapter declares its binary, builds a safe fixed-argv command, and parses the
scanner's real native output into ``core.Finding``/``core.Asset``. The base
orchestrates the explicit execution states so the normal path can never emit
fabricated findings:

    simulate requested ─────────────► SIMULATION (opt-in only)
    live disabled ──────────────────► DISABLED
    binary missing ─────────────────► UNAVAILABLE (+ install instructions)
    process fails / times out ──────► FAILED
    real output parsed ─────────────► LIVE (findings may be empty = "no findings")

Scope/SSRF and authorization are enforced before any execution and raise, so a
denied scan is refused rather than returned as a result.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod

from olympus.aegis.model import Dependency, ScanRequest, ScanResult
from olympus.aegis.runner import CommandError, CommandOutput, CommandTimeout, run_command, which
from olympus.aegis.scope import ensure_allowed
from olympus.aegis.states import ExecutionState
from olympus.core.models import Asset, Finding


class NotAuthorizedError(RuntimeError):
    """Raised when a real scan is requested without explicit authorization."""


class ParseError(RuntimeError):
    """Raised by an adapter when the scanner's output cannot be parsed."""


class ScannerAdapter(ABC):
    """Abstract external-CLI scanner adapter."""

    #: Stable scanner name (matches the registry).
    name: str = ""
    #: External executable resolved on PATH.
    binary: str = ""
    #: Expected version range / note (informational).
    version_expected: str = "any"
    #: How to install the binary (shown on UNAVAILABLE).
    install: str = ""

    @abstractmethod
    def build_argv(self, host: str, request: ScanRequest) -> list[str]:
        """Return the fixed argument vector for a real scan of ``host``."""

    @abstractmethod
    def parse(self, output: CommandOutput, host: str, request: ScanRequest) -> list[Finding]:
        """Parse real scanner output into findings (empty list = no findings)."""

    def asset_id(self, host: str) -> str:
        """Deterministic core.Asset id linking findings to the scanned target."""
        safe = "".join(ch if ch.isalnum() else "-" for ch in host).strip("-").upper()
        return f"AST-AEGIS-{safe}"

    def build_asset(self, host: str, request: ScanRequest) -> Asset:
        """Return a core.Asset representing the scanned target (override as needed)."""
        from olympus.core.enums import AssetType, Source

        kind = AssetType.URL if request.target_kind == "url" else AssetType.HOST
        return Asset(
            asset_id=self.asset_id(host),
            asset_type=kind,
            hostname=host,
            source=Source.AEGIS,
            tags=["aegis", self.name],
        )

    def version(self) -> str | None:
        """Return the scanner's version string, or ``None`` if undetermined."""
        path = which(self.binary)
        if not path:
            return None
        for flag in ("--version", "-version", "-V"):
            try:
                out = run_command([self.binary, flag], timeout=15)
            except (CommandError, CommandTimeout):
                continue
            text = (out.stdout or out.stderr).strip().splitlines()
            if text:
                return text[0].strip()
        return path

    def simulate(self, host: str, request: ScanRequest) -> list[Finding]:
        """Return clearly-labelled illustrative findings (SIMULATION only)."""
        from olympus.core.enums import Severity, Source

        return [
            Finding(
                asset_id="AST-AEGIS-SIM",
                source=Source.AEGIS,
                title=f"[SIMULATION] Example {self.name} finding (not a real scan)",
                description=(
                    "This is illustrative output produced only because simulation was "
                    "explicitly requested. It is NOT a real scanner result."
                ),
                severity=Severity.INFO,
                evidence=[f"scanner={self.name}", f"target={host}", "mode=simulation"],
            )
        ]

    def _dependency(self) -> Dependency:
        return Dependency(
            executable=self.binary,
            install=self.install,
            version_expected=self.version_expected,
            diagnostic=f"olympus aegis deps  (checks '{self.binary}' on PATH)",
        )

    def run(self, request: ScanRequest) -> ScanResult:
        """Execute the adapter honoring the explicit execution states."""
        # Scope + SSRF + authorization are mandatory and raise on denial.
        host = ensure_allowed(request.target_kind, request.target, request.allowed)

        if request.simulate:
            return ScanResult(
                scanner=self.name,
                state=ExecutionState.SIMULATION,
                target=host,
                findings=self.simulate(host, request),
                assets=[self.build_asset(host, request)],
                raw_evidence="simulation mode: no scanner was executed",
            )

        if not request.authorized:
            raise NotAuthorizedError(
                f"a real {self.name} scan requires explicit authorization (--i-am-authorized)"
            )

        if not request.live_enabled:
            return ScanResult(
                scanner=self.name,
                state=ExecutionState.DISABLED,
                target=host,
                error=(
                    "live scanning is disabled; set AEGIS_ENABLE_LIVE_SCANS=true to run a real "
                    "scan, or pass --simulate for explicit illustrative output"
                ),
            )

        if which(self.binary) is None:
            return ScanResult(
                scanner=self.name,
                state=ExecutionState.UNAVAILABLE,
                target=host,
                dependency=self._dependency(),
                error=f"required executable '{self.binary}' is not installed / not on PATH",
            )

        version = self.version()
        argv = self.build_argv(host, request)
        started = time.monotonic()
        try:
            output = run_command(argv, timeout=request.timeout_seconds)
        except CommandTimeout as exc:
            return ScanResult(
                scanner=self.name, state=ExecutionState.FAILED, target=host,
                version=version, error=str(exc), duration_seconds=time.monotonic() - started,
            )
        except CommandError as exc:
            return ScanResult(
                scanner=self.name, state=ExecutionState.FAILED, target=host,
                version=version, error=str(exc), duration_seconds=time.monotonic() - started,
            )
        duration = time.monotonic() - started

        try:
            findings = self.parse(output, host, request)
        except ParseError as exc:
            return ScanResult(
                scanner=self.name, state=ExecutionState.FAILED, target=host, version=version,
                raw_evidence=_evidence(output), error=f"parse failed: {exc}",
                exit_code=output.exit_code, duration_seconds=duration,
            )
        return ScanResult(
            scanner=self.name,
            state=ExecutionState.LIVE,
            target=host,
            version=version,
            findings=findings,
            assets=[self.build_asset(host, request)],
            raw_evidence=_evidence(output),
            exit_code=output.exit_code,
            duration_seconds=duration,
        )


def _evidence(output: CommandOutput) -> str:
    parts = []
    if output.stdout.strip():
        parts.append(output.stdout.strip())
    if output.stderr.strip():
        parts.append("[stderr]\n" + output.stderr.strip())
    return "\n".join(parts)
