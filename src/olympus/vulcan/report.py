"""Render an aggregated engagement into a JSON + Markdown security report."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from olympus.core.models import Alert, Asset, Finding
from olympus.vulcan.aggregate import rank_findings, severity_breakdown


def build_report(
    engagement: str, assets: list[Asset], findings: list[Finding], alerts: list[Alert]
) -> dict[str, object]:
    """Assemble a JSON-serializable consolidated report."""
    ranked = rank_findings(findings)
    return {
        "engagement": engagement,
        "generated_at": datetime.now(UTC).isoformat(),
        "summary": {
            "assets": len(assets),
            "findings": len(findings),
            "alerts": len(alerts),
            "severity_breakdown": severity_breakdown(findings),
        },
        "assets": [json.loads(a.model_dump_json()) for a in assets],
        "findings": [json.loads(f.model_dump_json()) for f in ranked],
        "alerts": [json.loads(a.model_dump_json()) for a in alerts],
    }


def render_markdown(
    engagement: str, assets: list[Asset], findings: list[Finding], alerts: list[Alert]
) -> str:
    """Render a human-readable Markdown report of the engagement."""
    ranked = rank_findings(findings)
    breakdown = severity_breakdown(findings)
    lines: list[str] = [
        f"# Security report — {engagement}",
        "",
        f"_Generated {datetime.now(UTC).strftime('%Y-%m-%d %H:%M UTC')} by Olympus Vulcan._",
        "",
        "## Summary",
        f"- Assets: {len(assets)}",
        f"- Findings: {len(findings)}",
        f"- Alerts: {len(alerts)}",
        "",
        "| Severity | Count |",
        "| --- | --- |",
    ]
    for level in ("critical", "high", "medium", "low", "info"):
        lines.append(f"| {level} | {breakdown[level]} |")

    lines += ["", "## Findings (ranked)"]
    if not ranked:
        lines.append("_No findings._")
    for finding in ranked:
        lines += [
            "",
            f"### [{finding.severity.value.upper()}] {finding.title}",
            f"- Source: {finding.source.value}",
            f"- Asset: {finding.asset_id}",
        ]
        if finding.cvss is not None:
            lines.append(f"- CVSS: {finding.cvss}")
        if finding.description:
            lines.append(f"- {finding.description}")
        if finding.remediation:
            lines.append(f"- **Remediation:** {finding.remediation}")

    if alerts:
        lines += ["", "## Alerts"]
        for alert in alerts:
            lines.append(f"- [{alert.severity.value.upper()}] {alert.title} ({alert.source.value})")

    return "\n".join(lines) + "\n"


def export_report(report: dict[str, object], path: Path) -> None:
    """Write the JSON report to ``path``."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")


def export_markdown(markdown: str, path: Path) -> None:
    """Write the Markdown report to ``path``."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(markdown, encoding="utf-8")
