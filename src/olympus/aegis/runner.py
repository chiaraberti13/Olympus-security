"""Bounded, shell-free subprocess execution for AEGIS scanner adapters.

All external scanners run through :func:`run_command`, which uses a fixed
argument vector (never a shell string), enforces a timeout, and kills the whole
process group on timeout so long-running scanners cannot leak. It returns the
captured exit status, stdout, and stderr.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import signal
import subprocess
from dataclasses import dataclass


class CommandTimeout(RuntimeError):
    """Raised when a scanner exceeds its timeout and is terminated."""


class CommandError(RuntimeError):
    """Raised when a scanner process cannot be started at all."""


@dataclass(frozen=True)
class CommandOutput:
    """The captured result of a completed subprocess."""

    exit_code: int
    stdout: str
    stderr: str


def which(binary: str) -> str | None:
    """Return the resolved path of ``binary`` on PATH, or ``None``."""
    return shutil.which(binary)


def run_command(argv: list[str], *, timeout: int, cwd: str | None = None) -> CommandOutput:
    """Run ``argv`` with no shell, a timeout, and process-group termination.

    ``argv[0]`` must be an existing executable (resolved by the caller). Raises
    :class:`CommandTimeout` if the timeout is exceeded, :class:`CommandError` if
    the process cannot be started.
    """
    if not argv:
        raise CommandError("empty command")
    resolved = which(argv[0]) or argv[0]
    start_new_session = os.name == "posix"
    try:
        process = subprocess.Popen(  # noqa: S603 - fixed argv, no shell
            [resolved, *argv[1:]],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=cwd,
            start_new_session=start_new_session,
        )
    except (OSError, ValueError) as exc:
        raise CommandError(f"could not start {argv[0]}: {exc}") from exc

    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        _terminate(process, start_new_session)
        raise CommandTimeout(f"{argv[0]} exceeded {timeout}s and was terminated") from exc
    return CommandOutput(exit_code=process.returncode, stdout=stdout or "", stderr=stderr or "")


def _terminate(process: subprocess.Popen[str], start_new_session: bool) -> None:
    """Kill the process (and its group on POSIX), then reap it."""
    try:
        if start_new_session:
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        else:  # pragma: no cover - non-POSIX
            process.kill()
    except (ProcessLookupError, PermissionError, OSError):  # pragma: no cover
        process.kill()
    with contextlib.suppress(subprocess.TimeoutExpired):  # pragma: no cover
        process.communicate(timeout=10)
