"""Command-line presentation for bounded Vulcan application workflows."""

from __future__ import annotations

import json
from pathlib import Path

import typer

from olympus.core.enums import Severity
from olympus.core.execution import CancellationRequested, ExecutionPolicyError
from olympus.core.output import OutputFormat, render
from olympus.core.paths import output_path
from olympus.vulcan.aggregate import (
    DEFAULT_MAX_FILES,
    DEFAULT_MAX_INPUT_BYTES,
    DEFAULT_MAX_ITEMS_PER_FILE,
    DEFAULT_MAX_TOTAL_ITEMS,
    AggregationError,
)
from olympus.vulcan.application import (
    DEFAULT_MAX_OUTPUT_BYTES,
    DEFAULT_MAX_TOTAL_INPUT_BYTES,
    VulcanApplicationService,
    VulcanRankRequest,
    VulcanReportRequest,
)
from olympus.vulcan.report import export_report, export_text

DEFAULT_REPORT_OUTPUT = output_path("vulcan-report.json")

app = typer.Typer(
    help="Vulcan — Findings aggregation & report engine.",
    no_args_is_help=True,
)
_APPLICATION_ERRORS = (
    AggregationError,
    CancellationRequested,
    ExecutionPolicyError,
    OSError,
    TimeoutError,
    ValueError,
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
        DEFAULT_REPORT_OUTPUT, "--output", help="JSON report output path."
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
    max_files: int = typer.Option(DEFAULT_MAX_FILES, "--max-files"),
    max_input_bytes: int = typer.Option(DEFAULT_MAX_INPUT_BYTES, "--max-input-bytes"),
    max_total_input_bytes: int = typer.Option(
        DEFAULT_MAX_TOTAL_INPUT_BYTES, "--max-total-input-bytes"
    ),
    max_items_per_file: int = typer.Option(
        DEFAULT_MAX_ITEMS_PER_FILE, "--max-items-per-file"
    ),
    max_total_items: int = typer.Option(DEFAULT_MAX_TOTAL_ITEMS, "--max-total-items"),
    max_output_bytes: int = typer.Option(DEFAULT_MAX_OUTPUT_BYTES, "--max-output-bytes"),
    deadline: float = typer.Option(120.0, "--deadline"),
) -> None:
    """Aggregate strict inputs into consistent JSON, Markdown and HTML views."""
    outputs = tuple(path for path in (output, markdown, html_output) if path is not None)
    try:
        outcome = VulcanApplicationService().report(
            VulcanReportRequest(
                engagement=engagement,
                asset_paths=tuple(assets),
                finding_paths=tuple(findings),
                alert_paths=tuple(alerts),
                excluded_paths=outputs,
                min_severity=min_severity,
                render_markdown=markdown is not None,
                render_html=html_output is not None,
                max_files=max_files,
                max_input_bytes=max_input_bytes,
                max_total_input_bytes=max_total_input_bytes,
                max_items_per_file=max_items_per_file,
                max_total_items=max_total_items,
                max_output_bytes=max_output_bytes,
                deadline_seconds=deadline,
            )
        )
        export_report(outcome.report, output)
        if markdown is not None and outcome.markdown is not None:
            export_text(outcome.markdown, markdown)
        if html_output is not None and outcome.html is not None:
            export_text(outcome.html, html_output)
    except _APPLICATION_ERRORS as exc:
        typer.echo(f"vulcan: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    typer.echo(json.dumps(outcome.report.summary.model_dump(mode="json"), indent=2, sort_keys=True))
    typer.echo(f"vulcan: wrote report to {output}", err=True)
    if markdown is not None:
        typer.echo(f"vulcan: wrote Markdown report to {markdown}", err=True)
    if html_output is not None:
        typer.echo(f"vulcan: wrote HTML report to {html_output}", err=True)


@app.command()
def rank(
    findings: list[Path] = typer.Option(
        ..., "--findings", help="core.Finding JSON file(s) to rank (repeatable)."
    ),
    output_format: OutputFormat = typer.Option(
        OutputFormat.TABLE, "--format", help="Render as a table (human) or json (machine)."
    ),
    max_files: int = typer.Option(DEFAULT_MAX_FILES, "--max-files"),
    max_input_bytes: int = typer.Option(DEFAULT_MAX_INPUT_BYTES, "--max-input-bytes"),
    max_total_input_bytes: int = typer.Option(
        DEFAULT_MAX_TOTAL_INPUT_BYTES, "--max-total-input-bytes"
    ),
    max_items_per_file: int = typer.Option(
        DEFAULT_MAX_ITEMS_PER_FILE, "--max-items-per-file"
    ),
    max_total_items: int = typer.Option(DEFAULT_MAX_TOTAL_ITEMS, "--max-total-items"),
    deadline: float = typer.Option(60.0, "--deadline"),
) -> None:
    """Load strict findings and print exact-ID-deduplicated severity ranking."""
    try:
        ranked = VulcanApplicationService().rank(
            VulcanRankRequest(
                finding_paths=tuple(findings),
                max_files=max_files,
                max_input_bytes=max_input_bytes,
                max_total_input_bytes=max_total_input_bytes,
                max_items_per_file=max_items_per_file,
                max_total_items=max_total_items,
                deadline_seconds=deadline,
            )
        )
    except _APPLICATION_ERRORS as exc:
        typer.echo(f"vulcan: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    columns = ["severity", "title", "source", "asset_id", "finding_id"]
    records: list[dict[str, object]] = [
        {
            "severity": finding.severity.value,
            "title": finding.title,
            "source": finding.source.value,
            "asset_id": finding.asset_id,
            "finding_id": finding.finding_id,
        }
        for finding in ranked
    ]
    typer.echo(render(records, columns, output_format, title="Findings (ranked)"))
