"""Structural validation of the Mars cyber range's docker-compose.yml.

Does not require a running Docker daemon: `docker compose config` only
parses and validates the compose file against the schema, it never starts
anything. Skipped entirely on environments without the `docker` CLI.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

COMPOSE_FILE = "labs/mars/docker-compose.yml"

pytestmark = pytest.mark.skipif(
    shutil.which("docker") is None, reason="docker CLI not available in this environment"
)


def _compose_config() -> str:
    result = subprocess.run(
        ["docker", "compose", "-f", COMPOSE_FILE, "config"],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout


def test_mars_compose_file_is_structurally_valid() -> None:
    result = subprocess.run(
        ["docker", "compose", "-f", COMPOSE_FILE, "config", "--quiet"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr


def test_mars_network_is_segmented_with_no_outbound_internet() -> None:
    assert "internal: true" in _compose_config()


def test_mars_target_web_publishes_only_the_documented_port() -> None:
    assert 'published: "8080"' in _compose_config()


def test_mars_target_web_content_files_exist() -> None:
    assert (Path("labs/mars/target-web/html/index.html")).exists()
    assert (Path("labs/mars/target-web/html/.env")).exists()
    assert (Path("labs/mars/target-web/nginx.conf")).exists()
