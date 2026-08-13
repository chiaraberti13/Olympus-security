"""Unit tests for Proteus's simulated phishing campaign generation."""

from __future__ import annotations

import pytest

from olympus.proteus.campaign import Recipient, simulate_campaign


def _recipients(count: int) -> list[Recipient]:
    return [Recipient(email=f"user{i}@olympusdemocorp.example") for i in range(count)]


def test_simulate_campaign_returns_one_result_per_recipient() -> None:
    results = simulate_campaign(_recipients(5), seed=42)
    assert len(results) == 5
    assert [r.recipient.email for r in results] == [rec.email for rec in _recipients(5)]


def test_simulate_campaign_is_deterministic_with_a_seed() -> None:
    first = simulate_campaign(_recipients(20), click_rate=0.4, seed=7)
    second = simulate_campaign(_recipients(20), click_rate=0.4, seed=7)
    assert [r.clicked for r in first] == [r.clicked for r in second]


def test_simulate_campaign_click_rate_zero_means_nobody_clicks() -> None:
    results = simulate_campaign(_recipients(50), click_rate=0.0, seed=1)
    assert all(not r.clicked for r in results)


def test_simulate_campaign_click_rate_one_means_everybody_clicks() -> None:
    results = simulate_campaign(_recipients(50), click_rate=1.0, seed=1)
    assert all(r.clicked for r in results)


def test_simulate_campaign_rejects_invalid_click_rate() -> None:
    with pytest.raises(ValueError, match="click_rate"):
        simulate_campaign(_recipients(1), click_rate=1.5)
    with pytest.raises(ValueError, match="click_rate"):
        simulate_campaign(_recipients(1), click_rate=-0.1)


def test_simulate_campaign_empty_recipients_yields_empty_results() -> None:
    assert simulate_campaign([], seed=1) == []
