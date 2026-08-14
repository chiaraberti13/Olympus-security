"""Command-line interface for the Hermes secret scanner."""

from __future__ import annotations

import subprocess
from pathlib import Path

import typer

from olympus.hermes.sarif import write_sarif
from olympus.hermes.scanner import scan_git_history, scan_path

app = typer.Typer(help="Hermes — secret and configuration scanner.", no_args_is_help=True)
DEFAULT_OUTPUT = Path("examples/output/hermes-results.sarif")


@app.command()
def scan(
    paths: list[Path] = typer.Argument(...),
    output: Path = typer.Option(DEFAULT_OUTPUT, "--output"),
    entropy_threshold: float = typer.Option(4.5, "--entropy-threshold", min=0.0, max=8.0),
    history: bool = typer.Option(False, "--history"),
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
    except (OSError, subprocess.SubprocessError) as exc:
        typer.echo(f"hermes: scan error: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    write_sarif(findings, output)
    typer.echo(f"hermes: {len(findings)} potential secret(s); SARIF: {output}")
    if findings:
        raise typer.Exit(code=1)


@app.command()
def demo() -> None:
    """Scan the synthetic Olympus Demo Corp fixture without real credentials."""
    fixture = Path("examples/input/hermes-demo.txt")
    findings = scan_path(fixture)
    write_sarif(findings, DEFAULT_OUTPUT)
    typer.echo(f"hermes: demo detected {len(findings)} synthetic secret(s); values masked")
