"""Unified Olympus command-line entry point.

Every module is exposed as a sub-command, so the whole platform is driven
through a single binary: ``olympus <tool> <command>`` (e.g. ``olympus argus
demo``). ``olympus core`` groups data-contract utilities.
"""

from __future__ import annotations

import json

import typer

from olympus import __version__
from olympus.apollo.cli import app as apollo_app
from olympus.argus.cli import app as argus_app
from olympus.artemis.cli import app as artemis_app
from olympus.core.models import Asset, Finding
from olympus.helios.cli import app as helios_app
from olympus.hermes.cli import app as hermes_app
from olympus.minerva.cli import app as minerva_app
from olympus.proteus.cli import app as proteus_app
from olympus.vulcan.cli import app as vulcan_app

app = typer.Typer(
    help="Olympus — offensive-security platform (Red + Blue).",
    no_args_is_help=True,
)

core_app = typer.Typer(help="Core data-contract utilities.", no_args_is_help=True)


@core_app.command("export-schemas")
def export_schemas() -> None:
    """Print the JSON Schema of the core models to stdout."""
    schemas = {
        "olympus.asset": Asset.model_json_schema(),
        "olympus.finding": Finding.model_json_schema(),
    }
    typer.echo(json.dumps(schemas, indent=2, sort_keys=True))


app.add_typer(core_app, name="core")
app.add_typer(argus_app, name="argus")
app.add_typer(helios_app, name="helios")
app.add_typer(artemis_app, name="artemis")
app.add_typer(proteus_app, name="proteus")
app.add_typer(hermes_app, name="hermes")
app.add_typer(apollo_app, name="apollo")
app.add_typer(minerva_app, name="minerva")
app.add_typer(vulcan_app, name="vulcan")


@app.command()
def version() -> None:
    """Print the Olympus version."""
    typer.echo(__version__)


def main() -> None:  # pragma: no cover
    """Console-script entry point."""
    app()


if __name__ == "__main__":  # pragma: no cover
    main()
