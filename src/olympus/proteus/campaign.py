"""Simulated phishing campaign generation.

Proteus never sends a real email and never collects a real credential: a
"campaign" is a purely local simulation over a list of synthetic
recipients, producing a per-recipient simulated outcome (clicked / not
clicked) from a seedable random model — useful for demonstrating a
security-awareness exercise without any of the actual risk (or legal
exposure) of a real phishing send.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from datetime import UTC, datetime


@dataclass(frozen=True)
class Recipient:
    """A synthetic training-campaign recipient. Never a real email is sent to this."""

    email: str
    display_name: str = ""


@dataclass(frozen=True)
class CampaignResult:
    """The simulated outcome for one recipient in a campaign."""

    recipient: Recipient
    clicked: bool
    simulated_at: datetime


def simulate_campaign(
    recipients: list[Recipient],
    *,
    click_rate: float = 0.3,
    seed: int | None = None,
) -> list[CampaignResult]:
    """Simulate a click outcome per recipient. Never sends or receives anything real.

    ``click_rate`` is the probability [0, 1] a recipient "clicks" the
    simulated link. ``seed`` makes the simulation reproducible (used by
    tests and the demo); omit it for a fresh random outcome each run.
    """
    if not 0.0 <= click_rate <= 1.0:
        raise ValueError("click_rate must be between 0.0 and 1.0")

    rng = random.Random(seed)  # noqa: S311 (local simulation, not security-sensitive)
    simulated_at = datetime.now(UTC)
    return [
        CampaignResult(
            recipient=recipient, clicked=rng.random() < click_rate, simulated_at=simulated_at
        )
        for recipient in recipients
    ]
