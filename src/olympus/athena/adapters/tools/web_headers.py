"""Athena adapter wrapping Argus passive web recon as an assessment step."""

from __future__ import annotations

from olympus.argus.web import WebReconError, build_web_asset, build_web_findings, fetch_web
from olympus.athena.adapters.tools.base import guard_target
from olympus.athena.ports import Cancellation, ToolRequest, ToolResult
from olympus.core.http import HttpClient


class WebHeadersAdapter:
    """Assess the passive HTTP security-header posture of a target host."""

    def __init__(self, http: HttpClient) -> None:
        self._http = http

    @property
    def name(self) -> str:
        return "web-headers"

    @property
    def capabilities(self) -> tuple[str, ...]:
        return ("passive-http-recon", "security-header-audit")

    def run(self, request: ToolRequest, cancellation: Cancellation) -> ToolResult:
        guarded = guard_target(request, cancellation)
        if isinstance(guarded, ToolResult):
            return guarded
        try:
            report = fetch_web(request.target_value, self._http)
        except WebReconError:
            return ToolResult(ok=False, error_code="unreachable")
        asset = build_web_asset(report)
        findings = build_web_findings(asset.asset_id, report)
        return ToolResult(ok=True, assets=[asset], findings=findings)
