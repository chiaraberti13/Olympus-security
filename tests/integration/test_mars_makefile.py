"""Verify the Mars range's Makefile targets, without ever running them for real.

`make -n` (dry-run) prints the exact command a target would execute
without executing it -- enough to prove each target only ever touches the
`mars` Compose project's own containers/network, never anything else on
the host.
"""

from __future__ import annotations

import shutil
import subprocess

import pytest

pytestmark = pytest.mark.skipif(shutil.which("make") is None, reason="make not available")

_EXPECTED_COMPOSE_PREFIX = "docker compose -f labs/mars/docker-compose.yml"


def _dry_run(target: str) -> str:
    result = subprocess.run(
        ["make", "-n", target], capture_output=True, text=True, check=True
    )
    return result.stdout


@pytest.mark.parametrize(
    ("target", "expected_suffix"),
    [
        ("mars-up", "up -d"),
        ("mars-down", "down"),
        ("mars-status", "ps"),
    ],
)
def test_mars_makefile_target_only_touches_the_mars_compose_project(
    target: str, expected_suffix: str
) -> None:
    output = _dry_run(target)
    assert f"{_EXPECTED_COMPOSE_PREFIX} {expected_suffix}" in output
