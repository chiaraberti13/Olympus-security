"""Unit tests for Proteus authorized phishing simulation (training only)."""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from olympus.cli import app
from olympus.proteus.campaign import (
    Campaign,
    build_campaign,
    campaign_report,
    render_email,
    render_training_page,
    tracking_link,
)
from olympus.proteus.scope import ProteusOutOfScopeError, ProteusScope, enforce_scope

runner = CliRunner()


def _scope(tmp_path: Path) -> Path:
    path = tmp_path / "scope.json"
    path.write_text(
        json.dumps({"engagement": "e", "allowed_domains": ["example.com"]}), encoding="utf-8"
    )
    return path


def _build(tmp_path: Path, emails: list[str]) -> Campaign:
    return build_campaign(
        "eng", emails, _scope(tmp_path), tmp_path / "log",
        subject="Confirm", sender="it@example.com", landing_url="https://train.example/p",
    )


def test_scope_covers_by_domain() -> None:
    scope = ProteusScope(engagement="e", allowed_domains=("example.com",))
    assert scope.covers("alice@example.com") is True
    assert scope.covers("alice@evil.test") is False
    assert scope.covers("not-an-email") is False


def test_enforce_blocks_and_logs(tmp_path: Path) -> None:
    log = tmp_path / "log"
    with pytest.raises(ProteusOutOfScopeError):
        enforce_scope("x@evil.test", _scope(tmp_path), log)
    assert "blocked_out_of_scope" in log.read_text(encoding="utf-8")


def test_build_campaign_mints_unique_tokens(tmp_path: Path) -> None:
    campaign = _build(tmp_path, ["a@example.com", "b@example.com"])
    tokens = {t.token for t in campaign.targets}
    assert len(tokens) == 2  # unique per target
    assert all(t.token for t in campaign.targets)


def test_build_campaign_rejects_out_of_scope(tmp_path: Path) -> None:
    with pytest.raises(ProteusOutOfScopeError):
        _build(tmp_path, ["a@evil.test"])


def test_lure_email_contains_tracking_link(tmp_path: Path) -> None:
    campaign = _build(tmp_path, ["a@example.com"])
    target = campaign.targets[0]
    body = render_email(campaign, target)
    assert tracking_link(campaign, target) in body
    assert target.token in body


def test_training_page_never_captures_credentials() -> None:
    page = render_training_page("Acme Corp").lower()
    # The core safety guarantee: no credential capture, ever.
    assert "<input" not in page
    assert "password" not in page
    assert "<form" not in page
    assert "phishing simulation" in page
    assert "acme corp" in page


def test_campaign_report_click_rate(tmp_path: Path) -> None:
    campaign = _build(tmp_path, ["a@example.com", "b@example.com"])
    clicked = {campaign.targets[0].token}
    summary = campaign_report(campaign, clicked)
    assert summary["targets"] == 2
    assert summary["clicked"] == 1
    assert summary["click_rate_percent"] == 50.0


def test_cli_campaign_page_email_report(tmp_path: Path) -> None:
    targets = tmp_path / "targets.txt"
    targets.write_text("alice@example.com\nmallory@evil.test\n", encoding="utf-8")
    campaign_out = tmp_path / "campaign.json"
    result = runner.invoke(
        app,
        [
            "proteus", "campaign", "--engagement", "eng", "--targets", str(targets),
            "--landing-url", "https://train.example/p", "--scope", str(_scope(tmp_path)),
            "--log", str(tmp_path / "log"), "--i-am-authorized", "--output", str(campaign_out),
        ],
    )
    assert result.exit_code == 0, result.output
    campaign = json.loads(campaign_out.read_text(encoding="utf-8"))
    assert len(campaign["targets"]) == 1  # only in-scope alice
    token = campaign["targets"][0]["token"]

    page_out = tmp_path / "page.html"
    assert runner.invoke(
        app, ["proteus", "page", "--engagement", "eng", "--output", str(page_out)]
    ).exit_code == 0

    email_result = runner.invoke(
        app, ["proteus", "email", "--campaign", str(campaign_out), "--token", token]
    )
    assert email_result.exit_code == 0
    assert token in email_result.output

    report_result = runner.invoke(
        app, ["proteus", "report", "--campaign", str(campaign_out), "--clicked", token]
    )
    assert report_result.exit_code == 0
    assert json.loads(report_result.output)["clicked"] == 1


def test_cli_campaign_requires_authorization(tmp_path: Path) -> None:
    targets = tmp_path / "t.txt"
    targets.write_text("alice@example.com\n", encoding="utf-8")
    result = runner.invoke(
        app,
        ["proteus", "campaign", "--engagement", "e", "--targets", str(targets),
         "--landing-url", "https://x/p", "--scope", str(_scope(tmp_path))],
    )
    assert result.exit_code == 4
    assert "AUTHORIZED USE ONLY" in result.output
