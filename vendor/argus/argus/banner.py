"""ASCII banner and program metadata."""
from __future__ import annotations

from . import __version__, ui

BANNER = r"""
     _    ____   ____ _   _ ____
    / \  |  _ \ / ___| | | / ___|
   / _ \ | |_) | |  _| | | \___ \
  / ___ \|  _ <| |_| | |_| |___) |
 /_/   \_\_| \_\\____|\___/|____/
"""

TAGLINE = "The all-seeing OSINT & reconnaissance toolkit"


def show() -> None:
    if ui._RICH:  # colored gradient-ish banner
        ui.echo(f"[bold cyan]{BANNER}[/bold cyan]")
        ui.echo(f"        [bold white]{TAGLINE}[/bold white]")
        ui.echo(f"        [grey62]v{__version__} · authorized / educational use only[/grey62]\n")
    else:
        print(ui.C.CYAN + BANNER + ui.C.RESET)
        print(f"        {TAGLINE}")
        print(f"        v{__version__} - authorized / educational use only\n")
