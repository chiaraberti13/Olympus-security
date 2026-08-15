"""CLI-level tests for `olympus argus accounts` and `accounts-demo`."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from olympus.argus import cli as argus_cli
from olympus.cli import app
from olympus.core.http import HttpResponse

runner = CliRunner()


class _FakeClient:
    """Offline HttpClient double: first configured host is 'present', rest 404."""

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> HttpResponse:
        if "github.com" in url:
            return HttpResponse(status_code=200, headers={}, body="<html>profile</html>")
        return HttpResponse(status_code=404, headers={}, body="not found")


def _scope(tmp_path: Path) -> Path:
    path = tmp_path / "scope.json"
    path.write_text(
        json.dumps({"engagement": "t", "allowed_handles": ["olympus_demo"]}), encoding="utf-8"
    )
    return path


def _sites(tmp_path: Path) -> Path:
    path = tmp_path / "sites.json"
    path.write_text(
        json.dumps(
            [
                {"name": "GitHub", "url_template": "https://github.com/{username}"},
                {"name": "GitLab", "url_template": "https://gitlab.com/{username}"},
            ]
        ),
        encoding="utf-8",
    )
    return path


def test_accounts_real_with_fake_client(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(argus_cli, "UrllibHttpClient", _FakeClient)
    result = runner.invoke(
        app,
        [
            "argus", "accounts", "--username", "olympus_demo",
            "--scope", str(_scope(tmp_path)), "--sites", str(_sites(tmp_path)),
        ],
    )
    assert result.exit_code == 0, result.output
    # output combines the JSON bundle followed by a stderr summary line; slice the JSON.
    json_text = result.output[: result.output.rfind("}") + 1]
    payload = json.loads(json_text)
    assert len(payload["assets"]) == 1
    assert payload["assets"][0]["metadata"]["site"] == "GitHub"


def test_accounts_out_of_scope_blocks(tmp_path: Path) -> None:
    log = tmp_path / "blocked.log"
    result = runner.invoke(
        app,
        [
            "argus", "accounts", "--username", "intruder",
            "--scope", str(_scope(tmp_path)), "--log", str(log),
            "--sites", str(_sites(tmp_path)),
        ],
    )
    assert result.exit_code == 3
    assert log.exists()


def test_accounts_metadata_requires_authorization(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "argus", "accounts", "--username", "olympus_demo",
            "--scope", str(_scope(tmp_path)), "--sites", str(_sites(tmp_path)), "--metadata",
        ],
    )
    assert result.exit_code == 4
    assert "AUTHORIZED USE ONLY" in result.output


def test_accounts_bad_registry(tmp_path: Path) -> None:
    bad = tmp_path / "sites.json"
    bad.write_text("{not a list", encoding="utf-8")
    result = runner.invoke(
        app,
        [
            "argus", "accounts", "--username", "olympus_demo",
            "--scope", str(_scope(tmp_path)), "--sites", str(bad),
        ],
    )
    assert result.exit_code == 2
