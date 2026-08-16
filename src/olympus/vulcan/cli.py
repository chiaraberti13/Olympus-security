"""Command-line interface for the Vulcan aggregation & report engine."""

from __future__ import annotations

import json
from pathlib import Path

import typer

from olympus.core.enums import Severity
from olympus.core.output import OutputFormat, render
from olympus.vulcan.aggregate import (
    AggregationError,
    dedupe_findings,
    filter_min_severity,
    load_alerts,
    load_assets,
    load_findings,
    rank_findings,
)
from olympus.vulcan.report import (
    build_report,
    export_report,
    export_text,
    render_html,
    render_markdown,
)

app = typer.Typer(
    help="Vulcan — Findings aggregation & report engine.",
    no_args_is_help=True,
)


@app.command()
def report(
    engagement: str = typer.Option(..., "--engagement", help="Engagement name for the report."),
    assets: list[Path] = typer.Option(
        [], "--assets", help="core.Asset JSON file(s) to include (repeatable)."
    ),
    findings: list[Path] = typer.Option(
        [], "--findings", help="core.Finding JSON file(s) to include (repeatable)."
    ),
    alerts: list[Path] = typer.Option(
        [], "--alerts", help="core.Alert JSON file(s) to include (repeatable)."
    ),
    output: Path = typer.Option(
        Path("examples/output/vulcan-report.json"), "--output", help="JSON report output path."
    ),
    markdown: Path | None = typer.Option(
        None, "--markdown", help="If set, also write a Markdown report to this path."
    ),
    html_output: Path | None = typer.Option(
        None, "--html", help="If set, also write a self-contained HTML report to this path."
    ),
    min_severity: Severity | None = typer.Option(
        None, "--min-severity", help="Only include findings at or above this severity."
    ),
) -> None:
    """Aggregate, dedupe and rank module outputs into one consolidated report."""
    try:
        asset_list = load_assets(list(assets))
        finding_list = dedupe_findings(load_findings(list(findings)))
        alert_list = load_alerts(list(alerts))
    except AggregationError as exc:
        typer.echo(f"vulcan: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    if min_severity is not None:
        finding_list = filter_min_severity(finding_list, min_severity)

    report_json = build_report(engagement, asset_list, finding_list, alert_list)
    export_report(report_json, output)
    typer.echo(json.dumps(report_json["summary"], indent=2, sort_keys=True))
    typer.echo(f"vulcan: wrote report to {output}", err=True)

    if markdown is not None:
        export_text(render_markdown(engagement, asset_list, finding_list, alert_list), markdown)
        typer.echo(f"vulcan: wrote Markdown report to {markdown}", err=True)
    if html_output is not None:
        export_text(render_html(engagement, asset_list, finding_list, alert_list), html_output)
        typer.echo(f"vulcan: wrote HTML report to {html_output}", err=True)


@app.command()
def rank(
    findings: list[Path] = typer.Option(
        ..., "--findings", help="core.Finding JSON file(s) to rank (repeatable)."
    ),
    output_format: OutputFormat = typer.Option(
        OutputFormat.TABLE, "--format", help="Render as a table (human) or json (machine)."
    ),
) -> None:
    """Load findings, deduplicate and print them ranked by severity."""
    try:
        ranked = rank_findings(dedupe_findings(load_findings(list(findings))))
    except AggregationError as exc:
        typer.echo(f"vulcan: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    columns = ["severity", "title", "source", "asset_id"]
    records: list[dict[str, object]] = [
        {
            "severity": f.severity.value,
            "title": f.title,
            "source": f.source.value,
            "asset_id": f.asset_id,
        }
        for f in ranked
    ]
    typer.echo(render(records, columns, output_format, title="Findings (ranked)"))
