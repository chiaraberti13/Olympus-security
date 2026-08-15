"""Offline, deterministic doubles for the Argus OSINT demos.

These synthetic values never touch the network: the phone number is a
reserved fictional NANP number (555-0123), so the ``phone-demo`` command
runs the real production code path against static data.
"""

from __future__ import annotations

from typing import ClassVar

from olympus.argus.accounts import SiteSpec
from olympus.argus.enrichment import MessagingPresence, PhoneEnrichment
from olympus.core.http import HttpResponse

# A reserved, fictional NANP number (555-0123) — valid in shape, never a real
# subscriber — so the phone-OSINT demo is deterministic and touches no one.
DEMO_PHONE_NUMBER = "+16505550123"

# Synthetic handle enumerated against synthetic .example sites for the demo.
DEMO_ACCOUNT_HANDLE = "olympus_demo"


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


def demo_site_specs() -> list[SiteSpec]:
    """Synthetic, offline site registry for the account-enumeration demo."""
    return [
        SiteSpec(
            name="DemoHub",
            url_template="https://demohub.example/{username}",
            metadata_patterns={"bio": r"<bio>([^<]*)</bio>"},
        ),
        SiteSpec(
            name="DemoForum",
            url_template="https://forum.example/u/{username}",
            metadata_patterns={"followers": r"followers:(\d+)"},
        ),
        SiteSpec(name="DemoGram", url_template="https://demogram.example/{username}"),
    ]


class DemoAccountHttpClient:
    """Offline HttpClient double serving canned profile pages for the demo handle."""

    _PAGES: ClassVar[dict[str, tuple[int, str]]] = {
        "demohub.example": (200, "<html><bio>Olympus demo account, synthetic.</bio></html>"),
        "forum.example": (200, "<html>profile followers:42</html>"),
        "demogram.example": (404, "<html>Not Found</html>"),
    }

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> HttpResponse:
        """Return a canned response based on the host in ``url``."""
        for host, (status, body) in self._PAGES.items():
            if host in url:
                return HttpResponse(status_code=status, headers={}, body=body)
        return HttpResponse(status_code=404, headers={}, body="")
