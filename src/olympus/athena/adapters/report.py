"""Report renderer adapter delegating to Vulcan without copying its logic."""

from __future__ import annotations

import json

from olympus.core.models import Finding
from olympus.vulcan.report import build_report, render_markdown


class VulcanReportRenderer:
    """Render Athena findings through the shared Vulcan reporting functions."""

    def __init__(self, engagement: str) -> None:
        self._engagement = engagement

    def render(self, findings: list[Finding], fmt: str) -> str:
        if fmt == "markdown":
            return render_markdown(self._engagement, [], findings, [])
        report = build_report(self._engagement, [], findings, [])
        return json.dumps(report, indent=2, sort_keys=True, default=str)
