"""Authorized phishing-simulation campaigns — training only, never real capture.

Proteus builds a security-awareness simulation: it assigns each in-scope
recipient a unique tracking token, renders a simulated lure email pointing at
a training URL, and renders the page a "clicker" lands on. That page is a
**training/awareness** page by construction — it contains no credential form
and captures nothing. Proteus never collects real credentials; the whole
point is measuring click-through and delivering just-in-time training.
"""

from __future__ import annotations

import html
import json
import secrets
from dataclasses import dataclass, field
from pathlib import Path

from olympus.proteus.scope import enforce_scope


@dataclass(frozen=True)
class Target:
    """One recipient in a campaign, with its unique tracking token."""

    email: str
    token: str


@dataclass(frozen=True)
class Campaign:
    """An authorized simulation: engagement metadata + the in-scope targets."""

    engagement: str
    subject: str
    sender: str
    landing_url: str
    targets: list[Target] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serializable view of the campaign."""
        return {
            "engagement": self.engagement,
            "subject": self.subject,
            "sender": self.sender,
            "landing_url": self.landing_url,
            "targets": [{"email": t.email, "token": t.token} for t in self.targets],
        }


def build_campaign(
    engagement: str,
    emails: list[str],
    scope_path: Path,
    log_path: Path,
    *,
    subject: str,
    sender: str,
    landing_url: str,
) -> Campaign:
    """Build a campaign from in-scope emails, minting a unique token per target.

    Out-of-scope addresses raise :class:`ProteusOutOfScopeError` (blocked and
    logged) — callers decide whether to skip or abort.
    """
    targets: list[Target] = []
    for email in emails:
        enforce_scope(email, scope_path, log_path)
        targets.append(Target(email=email, token=secrets.token_urlsafe(16)))
    return Campaign(
        engagement=engagement,
        subject=subject,
        sender=sender,
        landing_url=landing_url,
        targets=targets,
    )


def tracking_link(campaign: Campaign, target: Target) -> str:
    """Return the per-target training link embedded in the lure email."""
    separator = "&" if "?" in campaign.landing_url else "?"
    return f"{campaign.landing_url}{separator}t={target.token}"


def render_email(campaign: Campaign, target: Target) -> str:
    """Render the simulated lure email body (plain text) for one target."""
    return (
        f"From: {campaign.sender}\n"
        f"To: {target.email}\n"
        f"Subject: {campaign.subject}\n\n"
        "We noticed unusual activity on your account and need you to review it.\n"
        f"Please confirm your details here: {tracking_link(campaign, target)}\n\n"
        "If you do not act, access may be suspended.\n"
    )


def render_training_page(engagement: str) -> str:
    """Render the awareness page a clicker lands on.

    By construction this page has NO input fields and captures nothing: it
    tells the recipient they clicked a simulated phishing link and gives
    concrete guidance. This is the only thing a "victim" ever sees.
    """
    safe = html.escape(engagement)
    return (
        "<!doctype html>\n"
        '<html lang="en"><head><meta charset="utf-8">'
        "<title>Security awareness — simulated phishing</title></head>\n"
        '<body style="font-family:sans-serif;max-width:40rem;margin:3rem auto">\n'
        "<h1>This was a phishing simulation</h1>\n"
        f"<p>You clicked a link in an <strong>authorized security-awareness test</strong> "
        f"for <em>{safe}</em>. No information was collected and no account was affected.</p>\n"
        "<h2>How to spot the next one</h2>\n"
        "<ul>\n"
        "<li>Check the sender address and hover links before clicking.</li>\n"
        "<li>Be wary of urgency (\"act now or lose access\").</li>\n"
        "<li>Never enter credentials from an email link — navigate to the site yourself.</li>\n"
        "<li>Report suspicious messages to your security team.</li>\n"
        "</ul>\n"
        "<p>Thank you for helping keep the organization safe.</p>\n"
        "</body></html>\n"
    )


def campaign_report(campaign: Campaign, clicked_tokens: set[str]) -> dict[str, object]:
    """Summarize click-through for a campaign (training metric, never secrets)."""
    valid = {t.token for t in campaign.targets}
    clicked = valid & clicked_tokens
    total = len(campaign.targets)
    rate = round(100 * len(clicked) / total, 1) if total else 0.0
    return {
        "engagement": campaign.engagement,
        "targets": total,
        "clicked": len(clicked),
        "click_rate_percent": rate,
        "clicked_emails": sorted(t.email for t in campaign.targets if t.token in clicked),
    }


def export_campaign(campaign: Campaign, path: Path) -> None:
    """Write the campaign (targets + tokens) as JSON to ``path``."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(campaign.to_dict(), indent=2, sort_keys=True), encoding="utf-8")


def load_campaign(path: Path) -> Campaign:
    """Load a previously exported campaign JSON file."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    targets = [Target(email=str(t["email"]), token=str(t["token"])) for t in raw["targets"]]
    return Campaign(
        engagement=str(raw["engagement"]),
        subject=str(raw["subject"]),
        sender=str(raw["sender"]),
        landing_url=str(raw["landing_url"]),
        targets=targets,
    )
