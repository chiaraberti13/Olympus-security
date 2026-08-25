"""Render an aggregated engagement into a JSON + Markdown security report."""

from __future__ import annotations

import html
import json
from datetime import UTC, datetime
from pathlib import Path

from olympus.core.models import Alert, Asset, Finding, ReportSummary, SecurityReport
from olympus.vulcan.aggregate import rank_findings, severity_breakdown


def build_report(
    engagement: str, assets: list[Asset], findings: list[Finding], alerts: list[Alert]
) -> dict[str, object]:
    """Assemble a JSON-serializable consolidated report."""
    ranked = rank_findings(findings)
    report = SecurityReport(
        engagement=engagement,
        summary=ReportSummary(
            assets=len(assets),
            findings=len(findings),
            alerts=len(alerts),
            severity_breakdown=severity_breakdown(findings),
        ),
        assets=assets,
        findings=ranked,
        alerts=alerts,
    )
    return report.model_dump(mode="json")


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


_SEVERITY_COLORS = {
    "critical": "#7f1d1d",
    "high": "#b45309",
    "medium": "#a16207",
    "low": "#3f6212",
    "info": "#374151",
}


def render_html(
    engagement: str, assets: list[Asset], findings: list[Finding], alerts: list[Alert]
) -> str:
    """Render a self-contained (inline-CSS) HTML report of the engagement."""
    ranked = rank_findings(findings)
    breakdown = severity_breakdown(findings)
    generated = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    parts: list[str] = [
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
        f"<title>Security report — {html.escape(engagement)}</title>",
        "<style>body{font-family:system-ui,sans-serif;max-width:60rem;margin:2rem auto;"
        "padding:0 1rem;color:#111}h1{margin-bottom:0}.meta{color:#666}"
        ".sev{display:inline-block;padding:.1rem .5rem;border-radius:.3rem;color:#fff;"
        "font-size:.8rem}.card{border:1px solid #ddd;border-radius:.5rem;padding:1rem;"
        "margin:.75rem 0}table{border-collapse:collapse}td,th{border:1px solid #ddd;"
        "padding:.3rem .6rem;text-align:left}</style></head><body>",
        f"<h1>Security report — {html.escape(engagement)}</h1>",
        f"<p class='meta'>Generated {generated} by Olympus Vulcan · "
        f"{len(assets)} assets · {len(findings)} findings · {len(alerts)} alerts</p>",
        "<h2>Severity breakdown</h2><table><tr>"
        + "".join(f"<th>{level}</th>" for level in _SEVERITY_COLORS)
        + "</tr><tr>"
        + "".join(f"<td>{breakdown[level]}</td>" for level in _SEVERITY_COLORS)
        + "</tr></table>",
        "<h2>Findings (ranked)</h2>",
    ]
    if not ranked:
        parts.append("<p>No findings.</p>")
    for finding in ranked:
        color = _SEVERITY_COLORS[finding.severity.value]
        parts.append(
            f"<div class='card'><span class='sev' style='background:{color}'>"
            f"{finding.severity.value.upper()}</span> "
            f"<strong>{html.escape(finding.title)}</strong>"
            f"<p class='meta'>{html.escape(finding.source.value)} · {html.escape(finding.asset_id)}"
            + (f" · CVSS {finding.cvss}" if finding.cvss is not None else "")
            + "</p>"
            + (f"<p>{html.escape(finding.description)}</p>" if finding.description else "")
            + (
                f"<p><strong>Remediation:</strong> {html.escape(finding.remediation)}</p>"
                if finding.remediation
                else ""
            )
            + "</div>"
        )
    parts.append("</body></html>")
    return "".join(parts)


def export_report(report: dict[str, object], path: Path) -> None:
    """Write the JSON report to ``path``."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")


def export_text(content: str, path: Path) -> None:
    """Write ``content`` (Markdown or HTML) to ``path``."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def export_markdown(markdown: str, path: Path) -> None:
    """Write the Markdown report to ``path``."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(markdown, encoding="utf-8")
