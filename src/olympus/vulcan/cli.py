"""Command-line interface for the Vulcan module."""

from __future__ import annotations

from pathlib import Path

import typer

from olympus.vulcan.aggregate import aggregate
from olympus.vulcan.pentest_report import render_report
from olympus.vulcan.report_export import export_vulcan_report
from olympus.vulcan.risk import rank_findings

app = typer.Typer(
    help="Vulcan — Findings aggregation & report engine.",
    no_args_is_help=True,
)

DEMO_ENGAGEMENT = "olympus-demo-corp-2026"
# The other modules' own real demo output: same asset ids, same finding
# objects, that traveled across the whole platform -- this is the payoff
# of the shared core.* data contract every module writes to.
DEMO_SOURCE_PATHS: tuple[Path, ...] = (
    Path("examples/output/argus-assets.json"),
    Path("examples/output/helios-findings.json"),
    Path("examples/output/artemis-findings.json"),
    Path("examples/output/apollo-alerts.json"),
    Path("examples/output/proteus-report.json"),
)
DEMO_MARKDOWN_OUTPUT_PATH = Path("examples/output/vulcan-report.md")
DEMO_JSON_OUTPUT_PATH = Path("examples/output/vulcan-report.json")


@app.command()
def demo() -> None:
    """Aggregate every other module's real demo output into one pentest report.

    Reads the actual JSON files produced by ``argus demo``, ``helios
    demo``, ``artemis demo``, ``apollo demo`` and ``proteus demo``, and
    turns them into one deduplicated, risk-ranked pentest report. Run the
    other modules' demos first if a source file is missing (a warning is
    printed and that source is skipped, the rest of the demo still runs).
    """
    typer.echo(f"vulcan: demo — aggregating {len(DEMO_SOURCE_PATHS)} module export(s)")

    existing_paths = [path for path in DEMO_SOURCE_PATHS if path.exists()]
    missing_paths = [path for path in DEMO_SOURCE_PATHS if path not in existing_paths]
    if missing_paths:
        typer.echo(
            f"vulcan: warning: {len(missing_paths)} source file(s) not found, skipping: "
            f"{[str(path) for path in missing_paths]}",
            err=True,
        )

    data = aggregate(existing_paths)
    ranked_findings = rank_findings(data.findings)
    typer.echo(
        f"vulcan: aggregated {len(data.assets)} asset(s), {len(ranked_findings)} finding(s), "
        f"{len(data.alerts)} alert(s)"
    )

    markdown = render_report(DEMO_ENGAGEMENT, data.assets, ranked_findings, data.alerts)
    DEMO_MARKDOWN_OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    DEMO_MARKDOWN_OUTPUT_PATH.write_text(markdown, encoding="utf-8")
    typer.echo(f"vulcan: wrote Markdown report to {DEMO_MARKDOWN_OUTPUT_PATH}")

    export_vulcan_report(
        DEMO_ENGAGEMENT, data.assets, ranked_findings, data.alerts, DEMO_JSON_OUTPUT_PATH
    )
    typer.echo(f"vulcan: wrote JSON report to {DEMO_JSON_OUTPUT_PATH}")
