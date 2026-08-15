"""CLI-level tests for `olympus argus phone` and `phone-demo`."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from olympus.argus import cli as argus_cli
from olympus.cli import app
from olympus.core.http import HttpResponse

runner = CliRunner()

DEMO_NUMBER = "+16505550123"


class _FakeClient:
    """Offline HttpClient double: routes by URL substring to canned JSON."""

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> HttpResponse:
        if "apilayer.net" in url:
            body = json.dumps({"carrier": "Demo Mobile", "line_type": "mobile"})
        elif "hudsonrock" in url:
            body = json.dumps({"stealers": [{"stealer_family": "Redline"}]})
        else:  # messaging
            body = json.dumps({"exists": True, "has_photo": True})
        return HttpResponse(status_code=200, headers={}, body=body)


def _scope_file(tmp_path: Path) -> Path:
    path = tmp_path / "phone-scope.json"
    path.write_text(
        json.dumps({"engagement": "t", "allowed_prefixes": ["+1650555"]}), encoding="utf-8"
    )
    return path


def test_phone_offline_in_scope(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["argus", "phone", "--number", DEMO_NUMBER, "--scope", str(_scope_file(tmp_path))],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["asset"]["asset_type"] == "phone"
    assert payload["report"]["e164"] == DEMO_NUMBER


def test_phone_out_of_scope_blocks_and_logs(tmp_path: Path) -> None:
    log = tmp_path / "blocked.log"
    result = runner.invoke(
        app,
        [
            "argus", "phone", "--number", "+14155550123",
            "--scope", str(_scope_file(tmp_path)), "--log", str(log),
        ],
    )
    assert result.exit_code == 3
    assert "out of scope" in result.output
    assert log.exists()


def test_phone_parse_error(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["argus", "phone", "--number", "not-a-number", "--scope", str(_scope_file(tmp_path))],
    )
    assert result.exit_code == 2


def test_phone_real_lookup_refused_without_authorization(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "argus", "phone", "--number", DEMO_NUMBER,
            "--scope", str(_scope_file(tmp_path)), "--breach",
        ],
    )
    assert result.exit_code == 4
    assert "AUTHORIZED USE ONLY" in result.output


def test_phone_enrich_without_key_warns(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("OLYMPUS_NUMVERIFY_KEY", raising=False)
    monkeypatch.delenv("OLYMPUS_RAPIDAPI_KEY", raising=False)
    result = runner.invoke(
        app,
        [
            "argus", "phone", "--number", DEMO_NUMBER,
            "--scope", str(_scope_file(tmp_path)),
            "--enrich", "--messaging", "--i-am-authorized",
        ],
    )
    assert result.exit_code == 0
    assert "OLYMPUS_NUMVERIFY_KEY" in result.output
    assert "OLYMPUS_RAPIDAPI_KEY" in result.output


def test_phone_full_enrichment_with_fakes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("OLYMPUS_NUMVERIFY_KEY", "k")
    monkeypatch.setenv("OLYMPUS_RAPIDAPI_KEY", "k")
    monkeypatch.setattr(argus_cli, "UrllibHttpClient", _FakeClient)
    result = runner.invoke(
        app,
        [
            "argus", "phone", "--number", DEMO_NUMBER,
            "--scope", str(_scope_file(tmp_path)),
            "--enrich", "--breach", "--messaging", "--i-am-authorized",
        ],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    titles = {f["title"] for f in payload["findings"]}
    assert "Number appears in known data breaches" in titles
    assert any("Registered on messaging platform" in t for t in titles)


def test_phone_demo_writes_isolated_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out = tmp_path / "intel.json"
    monkeypatch.setattr(argus_cli, "DEMO_PHONE_OUTPUT_PATH", out)
    result = runner.invoke(app, ["argus", "phone-demo"])
    assert result.exit_code == 0, result.output
    assert out.exists()
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["asset"]["asset_type"] == "phone"
    # demo doubles inject a breach + messaging finding
    assert len(payload["findings"]) == 2
