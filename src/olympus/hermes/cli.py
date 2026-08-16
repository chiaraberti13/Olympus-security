"""Command-line interface for the Hermes secret scanner."""

from __future__ import annotations

import subprocess
from pathlib import Path

import typer

from olympus.hermes.sarif import write_sarif
from olympus.hermes.scanner import (
    apply_baseline,
    load_baseline,
    scan_git_history,
    scan_path,
    write_baseline,
)

app = typer.Typer(help="Hermes — secret and configuration scanner.", no_args_is_help=True)
DEFAULT_OUTPUT = Path("examples/output/hermes-results.sarif")


@app.command()
def scan(
    paths: list[Path] = typer.Argument(...),
    output: Path = typer.Option(DEFAULT_OUTPUT, "--output"),
    entropy_threshold: float = typer.Option(4.5, "--entropy-threshold", min=0.0, max=8.0),
    history: bool = typer.Option(False, "--history"),
    baseline: Path | None = typer.Option(
        None, "--baseline", help="JSON baseline of accepted fingerprints to ignore."
    ),
    write_baseline_path: Path | None = typer.Option(
        None, "--write-baseline", help="Write current findings' fingerprints as a baseline."
    ),
) -> None:
    """Scan a path and optionally its Git history, emitting masked SARIF."""
    try:
        findings = [
            finding
            for path in paths
            for finding in scan_path(path, entropy_threshold)
        ]
        if history:
            findings.extend(scan_git_history(paths[0], entropy_threshold))
        if baseline is not None:
            findings = apply_baseline(findings, load_baseline(baseline))
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        typer.echo(f"hermes: scan error: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    if write_baseline_path is not None:
        write_baseline(findings, write_baseline_path)
        typer.echo(
            f"hermes: wrote baseline ({len(findings)} fingerprint(s)) to {write_baseline_path}"
        )

    write_sarif(findings, output)
    typer.echo(f"hermes: {len(findings)} potential secret(s); SARIF: {output}")
    if findings:
        raise typer.Exit(code=1)
