"""Command-line interface for the Vulcan module."""

from __future__ import annotations

import typer

app = typer.Typer(
    help="Vulcan — Findings aggregation & report engine.",
    no_args_is_help=True,
)


@app.command()
def demo() -> None:
    """Run a self-contained demo on the synthetic 'Olympus Demo Corp' dataset."""
    # NOTE: scaffold only. The development loop implements this command.
    typer.echo("vulcan: demo not implemented yet (scaffold).")
