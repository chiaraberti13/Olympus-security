"""First-class Olympus CLI surface for the complete vendored upstream tools.

These commands run the full, unmodified upstream tools that live under
``vendor/``:

* ``olympus argus-native`` runs the complete standalone ARGUS CLI (all of its
  original subcommands and its interactive menu), forwarding every argument
  verbatim.
* ``olympus vap`` drives the complete Vulnerability Assessment Platform — its
  FastAPI web app, database migrations, and full 24-scanner catalogue.

Heavy upstream dependencies are imported lazily, only when a command actually
runs, and missing dependencies or external scanner binaries fail gracefully
with actionable installation guidance rather than being treated as absent
features.
"""

from __future__ import annotations

import json
import subprocess
import sys

import typer

from olympus.integrations.vendored import ARGUS_DIR, VAP_DIR, ensure_on_path, tool_path


# --------------------------------------------------------------------------- #
# ARGUS (complete standalone CLI, run verbatim)
# --------------------------------------------------------------------------- #
def run_argus_native(args: list[str]) -> int:
    """Forward ``args`` to the complete vendored ARGUS CLI, returning its exit code."""
    ensure_on_path(ARGUS_DIR)
    try:
        from argus.cli import main as argus_main  # type: ignore[import-not-found]
    except ModuleNotFoundError as exc:
        typer.echo(
            "olympus: ARGUS runtime dependencies are not installed "
            f"({exc.name}). Install them with:  pip install -e \".[argus]\"",
            err=True,
        )
        return 2
    return int(argus_main(args))


def register_argus_native(parent: typer.Typer) -> None:
    """Register ``argus-native`` on ``parent`` as a raw-passthrough command.

    It captures every following token (subcommand, flags, values) and forwards
    them unchanged to the complete vendored ARGUS CLI, e.g.
    ``olympus argus-native ip 8.8.8.8`` or ``olympus argus-native --help``.
    """

    @parent.command(
        "argus-native",
        context_settings={
            "allow_extra_args": True,
            "ignore_unknown_options": True,
            "help_option_names": [],
        },
        help="Run the complete vendored ARGUS CLI (all original subcommands, passthrough).",
    )
    def _argus_native(ctx: typer.Context) -> None:
        raise typer.Exit(code=run_argus_native(list(ctx.args)))


# --------------------------------------------------------------------------- #
# Vulnerability Assessment Platform (complete app)
# --------------------------------------------------------------------------- #
vap_app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Drive the complete vendored Vulnerability Assessment Platform.",
)


def _scanner_names() -> list[str]:
    """Return the names of every vendored VAP scanner (dependency-free)."""
    scanners = tool_path(VAP_DIR) / "scanners"
    return sorted(
        path.stem.removesuffix("_scanner")
        for path in scanners.glob("*_scanner.py")
    )


@vap_app.command("serve")
def vap_serve(
    host: str = typer.Option("127.0.0.1", "--host", help="Bind address for the web app."),
    port: int = typer.Option(8000, "--port", help="Port for the web app."),
) -> None:
    """Serve the complete VAP FastAPI application (Ctrl-C to stop)."""
    path = tool_path(VAP_DIR)
    env = {**_os_environ(), "VAP_HOST": host, "VAP_PORT": str(port)}
    typer.echo(f"olympus: starting VAP web app on http://{host}:{port} (from {path})", err=True)
    try:
        completed = subprocess.run(
            [sys.executable, "app.py"], cwd=str(path), env=env, check=False
        )
    except KeyboardInterrupt:  # pragma: no cover - interactive
        raise typer.Exit(code=0) from None
    raise typer.Exit(code=completed.returncode)


@vap_app.command("migrate")
def vap_migrate() -> None:
    """Run the VAP database migrations (alembic upgrade head)."""
    path = tool_path(VAP_DIR)
    completed = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=str(path),
        env=_os_environ(),
        check=False,
    )
    raise typer.Exit(code=completed.returncode)


@vap_app.command("scanners")
def vap_scanners() -> None:
    """List the complete VAP scanner catalogue (all 24 integrations)."""
    names = _scanner_names()
    typer.echo(json.dumps({"count": len(names), "scanners": names}, indent=2, sort_keys=True))


@vap_app.command("info")
def vap_info() -> None:
    """Show where the vendored VAP lives and whether its stack is importable."""
    import importlib.util

    path = tool_path(VAP_DIR)
    ensure_on_path(VAP_DIR)
    importable = importlib.util.find_spec("fastapi") is not None
    payload = {
        "path": str(path),
        "scanners": len(_scanner_names()),
        "web_stack_importable": importable,
        "install_hint": 'pip install -e ".[vap]"  (or vendor installer.sh / docker-compose.yml)',
        "docker_compose": str(path / "docker-compose.yml"),
    }
    typer.echo(json.dumps(payload, indent=2, sort_keys=True))


def _os_environ() -> dict[str, str]:
    import os

    return dict(os.environ)
