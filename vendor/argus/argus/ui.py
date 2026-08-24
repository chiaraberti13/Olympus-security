"""Terminal UI helpers.

Uses `rich` when available for colored tables, panels and progress bars, and
falls back to plain (still-usable) ANSI/plain text output when it is not, so the
tool works even on a bare Python install.
"""
from __future__ import annotations

import sys
from typing import Iterable, Sequence

try:  # pragma: no cover - exercised implicitly
    from rich import box
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table

    _RICH = True
    _console = Console()
except Exception:  # pragma: no cover
    _RICH = False
    _console = None


# ANSI fallback colors
class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GREY = "\033[90m"


def supports_color() -> bool:
    return sys.stdout.isatty()


def _plain(text: str) -> str:
    """Strip rich markup for the plain fallback."""
    import re

    return re.sub(r"\[/?[a-zA-Z0-9_# ]+\]", "", text)


def echo(text: str = "") -> None:
    if _RICH:
        _console.print(text)
    else:
        print(_plain(text))


def rule(title: str = "") -> None:
    if _RICH:
        _console.rule(title)
    else:
        line = "-" * 60
        print(f"\n{line}\n{title}\n{line}" if title else line)


def success(text: str) -> None:
    if _RICH:
        _console.print(f"[bold green]✔[/bold green] {text}")
    else:
        print(f"{C.GREEN}[+]{C.RESET} {_plain(text)}")


def warn(text: str) -> None:
    if _RICH:
        _console.print(f"[bold yellow]![/bold yellow] {text}")
    else:
        print(f"{C.YELLOW}[!]{C.RESET} {_plain(text)}")


def error(text: str) -> None:
    if _RICH:
        _console.print(f"[bold red]✖[/bold red] {text}")
    else:
        print(f"{C.RED}[x]{C.RESET} {_plain(text)}", file=sys.stderr)


def info(text: str) -> None:
    if _RICH:
        _console.print(f"[cyan]»[/cyan] {text}")
    else:
        print(f"{C.CYAN}[*]{C.RESET} {_plain(text)}")


def panel(body: str, title: str = "") -> None:
    if _RICH:
        _console.print(Panel(body, title=title, border_style="cyan", box=box.ROUNDED))
    else:
        rule(title)
        print(_plain(body))
        rule()


def kv_table(rows: Sequence[tuple[str, str]], title: str = "") -> None:
    """Render key/value rows as a two-column table."""
    if _RICH:
        table = Table(title=title or None, box=box.SIMPLE_HEAVY, show_header=False, expand=False)
        table.add_column("Field", style="bold cyan", no_wrap=True)
        table.add_column("Value", style="white")
        for k, v in rows:
            table.add_row(str(k), str(v))
        _console.print(table)
    else:
        if title:
            rule(title)
        width = max((len(k) for k, _ in rows), default=0)
        for k, v in rows:
            print(f"  {C.CYAN}{k.ljust(width)}{C.RESET} : {v}")


def results_table(headers: Sequence[str], rows: Iterable[Sequence[str]], title: str = "") -> None:
    if _RICH:
        table = Table(title=title or None, box=box.ROUNDED, header_style="bold magenta")
        for h in headers:
            table.add_column(str(h))
        for row in rows:
            table.add_row(*[str(c) for c in row])
        _console.print(table)
    else:
        if title:
            rule(title)
        print("  " + " | ".join(headers))
        print("  " + "-" * 50)
        for row in rows:
            print("  " + " | ".join(str(c) for c in row))


def prompt(text: str) -> str:
    if _RICH:
        return _console.input(f"[bold cyan]{text}[/bold cyan] ")
    return input(f"{C.CYAN}{_plain(text)}{C.RESET} ")


def progress_iter(iterable, description: str, total: int | None = None):
    """Yield from `iterable` while showing a progress bar (rich) or dots."""
    if _RICH:
        from rich.progress import (
            BarColumn,
            Progress,
            SpinnerColumn,
            TextColumn,
            TimeElapsedColumn,
        )

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("{task.completed}/{task.total}"),
            TimeElapsedColumn(),
            console=_console,
            transient=True,
        ) as progress:
            task = progress.add_task(description, total=total)
            for item in iterable:
                yield item
                progress.advance(task)
    else:
        count = 0
        for item in iterable:
            yield item
            count += 1
            if count % 5 == 0:
                sys.stdout.write(".")
                sys.stdout.flush()
        print()


def clear() -> None:
    import os

    os.system("cls" if os.name == "nt" else "clear")
