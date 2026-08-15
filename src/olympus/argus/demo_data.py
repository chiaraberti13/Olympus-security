"""Synthetic, fully offline "Olympus Demo Corp" dataset used by `argus demo`.

Every value here lives in an IANA-reserved documentation range (RFC 5737 /
RFC 3849 for addresses, the ``.example`` TLD for the domain itself, RFC
2606), so nothing in this module ever touches a real host. The resolver and
CT client below satisfy the same protocols as their production
counterparts, so the demo command runs the exact same recon/CT/assets/diff
pipeline as `argus scan`, just fed from static data instead of the network.
"""

from __future__ import annotations

from typing import Any, ClassVar

from olympus.argus.enrichment import MessagingPresence, PhoneEnrichment

DEMO_DOMAIN = "olympusdemocorp.example"

# A reserved, fictional NANP number (555-0123) — valid in shape, never a real
# subscriber — so the phone-OSINT demo is deterministic and touches no one.
DEMO_PHONE_NUMBER = "+16505550123"


class DemoResolver:
    """Offline DnsResolver double serving the synthetic demo DNS zone."""

    _RECORDS: ClassVar[dict[tuple[str, str], list[str]]] = {
        (DEMO_DOMAIN, "A"): ["203.0.113.10"],
        (DEMO_DOMAIN, "AAAA"): ["2001:db8::10"],
        (DEMO_DOMAIN, "MX"): ["10 mail.olympusdemocorp.example"],
        (DEMO_DOMAIN, "TXT"): ["v=spf1 include:_spf.olympusdemocorp.example ~all"],
        (f"_dmarc.{DEMO_DOMAIN}", "TXT"): [
            "v=DMARC1; p=reject; rua=mailto:dmarc@olympusdemocorp.example"
        ],
    }

    def resolve(self, name: str, record_type: str) -> list[str]:
        """Return the canned answer for ``name``/``record_type``, or ``[]``."""
        return list(self._RECORDS.get((name.lower(), record_type), []))


class DemoCtClient:
    """Offline CertificateTransparencyClient double serving canned CT log entries."""

    _ENTRIES: ClassVar[list[dict[str, Any]]] = [
        {"name_value": f"{DEMO_DOMAIN}\nwww.{DEMO_DOMAIN}", "issuer_name": "Demo CA"},
        {"name_value": f"mail.{DEMO_DOMAIN}", "issuer_name": "Demo CA"},
        {"name_value": f"vpn.{DEMO_DOMAIN}", "issuer_name": "Demo CA"},
    ]

    def query(self, domain: str) -> list[dict[str, Any]]:
        """Return every canned CT entry (domain is ignored, dataset is single-tenant)."""
        return list(self._ENTRIES)


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
