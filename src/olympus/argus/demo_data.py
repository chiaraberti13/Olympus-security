"""Offline, deterministic doubles for the Argus OSINT demos.

These synthetic values never touch the network: the phone number is a
reserved fictional NANP number (555-0123), so the ``phone-demo`` command
runs the real production code path against static data.
"""

from __future__ import annotations

from olympus.argus.enrichment import MessagingPresence, PhoneEnrichment

# A reserved, fictional NANP number (555-0123) — valid in shape, never a real
# subscriber — so the phone-OSINT demo is deterministic and touches no one.
DEMO_PHONE_NUMBER = "+16505550123"


class DemoPhoneEnrichmentClient:
    """Offline PhoneEnrichmentClient double: canned carrier + breach exposure."""

    def enrich(self, e164: str) -> PhoneEnrichment:
        """Return deterministic synthetic enrichment for the demo number."""
        return PhoneEnrichment(
            carrier="Olympus Demo Mobile",
            line_type="mobile",
            breach_count=2,
            breach_sources=("DemoStealer/Redline", "DemoStealer/Raccoon"),
        )


class DemoMessagingPresenceClient:
    """Offline MessagingPresenceClient double: canned WhatsApp-style presence."""

    def lookup(self, e164: str) -> MessagingPresence:
        """Return deterministic synthetic messaging presence for the demo number."""
        return MessagingPresence(
            platform="whatsapp",
            registered=True,
            has_public_photo=True,
            is_business=False,
        )
