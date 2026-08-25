"""Unified Olympus command-line entry point.

Every module is exposed as a sub-command, so the whole platform is driven
through a single binary: ``olympus <tool> <command>`` (e.g. ``olympus argus
scan``). ``olympus core`` groups data-contract utilities.
"""

from __future__ import annotations

import json
from pathlib import Path

import typer

from olympus import __version__
from olympus.apollo.cli import app as apollo_app
from olympus.argus.cli import app as argus_app
from olympus.artemis.cli import app as artemis_app
from olympus.athena.cli import app as athena_app
from olympus.athena.domain.contracts import AssessmentPlan, AssessmentResult
from olympus.core.models import (
    Alert,
    Asset,
    Event,
    Evidence,
    Finding,
    Incident,
    Observation,
    ScanJob,
    SecurityReport,
)
from olympus.helios.cli import app as helios_app
from olympus.hermes.cli import app as hermes_app
from olympus.integrations.cli import (
    aegis_app,
    register_argus_native,
    register_doctor,
    register_vap_shim,
)
from olympus.minerva.cli import app as minerva_app
from olympus.proteus.cli import app as proteus_app
from olympus.vulcan.cli import app as vulcan_app

app = typer.Typer(
    help="Olympus — offensive-security platform (Red + Blue).",
    no_args_is_help=True,
)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(__version__)
        raise typer.Exit()


@app.callback()
def _main(
    version: bool = typer.Option(
        False,
        "--version",
        "-V",
        callback=_version_callback,
        is_eager=True,
        help="Show the Olympus version and exit.",
    ),
) -> None:
    """Olympus — a single binary driving every Red and Blue module."""


core_app = typer.Typer(help="Core data-contract utilities.", no_args_is_help=True)


@core_app.command("export-schemas")
def export_schemas(
    output_dir: Path | None = typer.Argument(
        None,
        help="Optional directory to write schemas.json into; prints to stdout when omitted.",
    ),
) -> None:
    """Print the JSON Schema of the core models, or write it to a directory."""
    schemas = {
        "olympus.athena.plan": AssessmentPlan.model_json_schema(),
        "olympus.athena.result": AssessmentResult.model_json_schema(),
        "olympus.asset": Asset.model_json_schema(),
        "olympus.finding": Finding.model_json_schema(),
        "olympus.event": Event.model_json_schema(),
        "olympus.evidence": Evidence.model_json_schema(),
        "olympus.alert": Alert.model_json_schema(),
        "olympus.incident": Incident.model_json_schema(),
        "olympus.observation": Observation.model_json_schema(),
        "olympus.scan-job": ScanJob.model_json_schema(),
        "olympus.security-report": SecurityReport.model_json_schema(),
    }
    payload = json.dumps(schemas, indent=2, sort_keys=True)
    if output_dir is None:
        typer.echo(payload)
        return
    output_dir.mkdir(parents=True, exist_ok=True)
    destination = output_dir / "schemas.json"
    destination.write_text(payload, encoding="utf-8")
    typer.echo(f"olympus: wrote core schemas to {destination}", err=True)


app.add_typer(core_app, name="core")
app.add_typer(argus_app, name="argus")
app.add_typer(athena_app, name="athena")
app.add_typer(helios_app, name="helios")
app.add_typer(artemis_app, name="artemis")
app.add_typer(proteus_app, name="proteus")
app.add_typer(hermes_app, name="hermes")
app.add_typer(apollo_app, name="apollo")
app.add_typer(minerva_app, name="minerva")
app.add_typer(vulcan_app, name="vulcan")
# Complete vendored upstream tools, wired in as first-class subcommands.
register_argus_native(app)
app.add_typer(aegis_app, name="aegis")
register_vap_shim(app)  # deprecated 'olympus vap' -> forwards to 'olympus aegis'
register_doctor(app)  # 'olympus doctor'


@app.command()
def version() -> None:
    """Print the Olympus version."""
    typer.echo(__version__)


def main() -> None:  # pragma: no cover
    """Console-script entry point."""
    app()


if __name__ == "__main__":  # pragma: no cover
    main()
