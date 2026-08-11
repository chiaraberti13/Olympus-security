"""Command-line interface for the Hermes module."""

from __future__ import annotations

import typer

app = typer.Typer(
    help="Hermes — Secret & config scanner (DevSecOps).",
    no_args_is_help=True,
)


@app.command()
def demo() -> None:
    """Run a self-contained demo on the synthetic 'Olympus Demo Corp' dataset."""
    # NOTE: scaffold only. The development loop implements this command.
    typer.echo("hermes: demo not implemented yet (scaffold).")
