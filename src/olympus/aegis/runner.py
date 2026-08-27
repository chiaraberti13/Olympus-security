"""Bounded, cancellable, shell-free subprocess execution for AEGIS adapters."""

from __future__ import annotations

import contextlib
import os
import shutil
import signal
import subprocess
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from olympus.core.execution import Cancellation, CancellationRequested, NeverCancelled


class CommandTimeout(RuntimeError):
    """Raised when a scanner exceeds its timeout and is terminated."""


class CommandError(RuntimeError):
    """Raised when a scanner process cannot be started or exits unsuccessfully."""


class CommandOutputLimit(CommandError):
    """Raised when combined stdout/stderr exceeds its byte budget."""


@dataclass(frozen=True)
class CommandOutput:
    """The bounded captured result of a completed subprocess."""

    exit_code: int
    stdout: str
    stderr: str


def which(binary: str) -> str | None:
    """Return the resolved path of ``binary`` on PATH, or ``None``."""
    return shutil.which(binary)


def run_command(
    argv: list[str],
    *,
    timeout: float,
    cwd: str | Path | None = None,
    max_output_bytes: int = 5_000_000,
    cancellation: Cancellation | None = None,
    environment: Mapping[str, str] | None = None,
) -> CommandOutput:
    """Run a fixed argv with bounded pipes, a minimal environment and cancellation."""
    if not argv or not argv[0] or any("\x00" in argument for argument in argv):
        raise CommandError("command arguments must be non-empty and contain no NUL")
    if not 0.05 <= timeout <= 3_600:
        raise CommandError("command timeout must be between 0.05 and 3600 seconds")
    if not 1 <= max_output_bytes <= 100_000_000:
        raise CommandError("max_output_bytes must be between 1 and 100000000")
    working_directory: str | None = None
    if cwd is not None:
        path = Path(cwd)
        if path.is_symlink() or not path.is_dir():
            raise CommandError(f"command cwd must be a non-symlink directory: {path}")
        working_directory = str(path)
    resolved = which(argv[0])
    if resolved is None:
        raise CommandError(f"executable not found: {argv[0]}")
    token = cancellation or NeverCancelled()
    if token.is_cancelled():
        raise CancellationRequested("operation cancelled")
    start_new_session = os.name == "posix"
    try:
        process = subprocess.Popen(  # noqa: S603 - resolved executable, fixed argument vector
            [resolved, *argv[1:]],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=working_directory,
            env=_subprocess_environment(environment),
            start_new_session=start_new_session,
        )
    except (OSError, ValueError) as exc:
        raise CommandError(f"could not start {argv[0]}: {exc}") from exc
    stdout_pipe, stderr_pipe = process.stdout, process.stderr
    if stdout_pipe is None or stderr_pipe is None:
        _terminate(process, start_new_session)
        raise CommandError("scanner process pipes were not created")

    stdout = bytearray()
    stderr = bytearray()
    total = [0]
    lock = threading.Lock()
    exceeded = threading.Event()
    readers = [
        threading.Thread(
            target=_read_pipe,
            args=(stdout_pipe, stdout, max_output_bytes, total, lock, exceeded),
            daemon=True,
        ),
        threading.Thread(
            target=_read_pipe,
            args=(stderr_pipe, stderr, max_output_bytes, total, lock, exceeded),
            daemon=True,
        ),
    ]
    for reader in readers:
        reader.start()
    deadline = time.monotonic() + timeout
    try:
        while process.poll() is None:
            if token.is_cancelled():
                raise CancellationRequested("operation cancelled")
            if exceeded.is_set():
                raise CommandOutputLimit(
                    f"{argv[0]} output exceeds the {max_output_bytes} byte limit"
                )
            if time.monotonic() >= deadline:
                raise CommandTimeout(f"{argv[0]} exceeded {timeout:g}s and was terminated")
            time.sleep(0.02)
    except BaseException:
        _terminate(process, start_new_session)
        raise
    finally:
        for reader in readers:
            reader.join(timeout=1.0)
    if token.is_cancelled():
        raise CancellationRequested("operation cancelled")
    if exceeded.is_set():
        raise CommandOutputLimit(f"{argv[0]} output exceeds the {max_output_bytes} byte limit")
    return CommandOutput(
        exit_code=int(process.returncode),
        stdout=stdout.decode("utf-8", errors="replace"),
        stderr=stderr.decode("utf-8", errors="replace"),
    )


def _read_pipe(
    pipe: BinaryIO,
    destination: bytearray,
    maximum: int,
    total: list[int],
    lock: threading.Lock,
    exceeded: threading.Event,
) -> None:
    try:
        while not exceeded.is_set():
            chunk = pipe.read(65_536)
            if not chunk:
                return
            with lock:
                remaining = maximum - total[0]
                if remaining <= 0:
                    exceeded.set()
                    return
                destination.extend(chunk[:remaining])
                total[0] += min(len(chunk), remaining)
                if len(chunk) > remaining:
                    exceeded.set()
                    return
    finally:
        pipe.close()


def _subprocess_environment(extra: Mapping[str, str] | None) -> dict[str, str]:
    allowed = ("PATH", "LANG", "LC_ALL", "TZ", "SSL_CERT_FILE", "SSL_CERT_DIR", "TMPDIR")
    environment = {key: os.environ[key] for key in allowed if key in os.environ}
    environment.setdefault("PATH", os.defpath)
    environment.setdefault("LANG", "C.UTF-8")
    environment["NO_COLOR"] = "1"
    if extra is not None:
        for key, value in extra.items():
            if not key or "=" in key or "\x00" in key or "\x00" in value:
                raise CommandError("subprocess environment contains an invalid key/value")
            environment[key] = value
    return environment


def _terminate(process: subprocess.Popen[bytes], start_new_session: bool) -> None:
    """Kill the process group where available, then reap it."""
    try:
        if start_new_session:
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        else:  # pragma: no cover - non-POSIX
            process.kill()
    except (ProcessLookupError, PermissionError, OSError):  # pragma: no cover
        with contextlib.suppress(OSError):
            process.kill()
    with contextlib.suppress(subprocess.TimeoutExpired):
        process.wait(timeout=10)
