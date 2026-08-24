"""Phone number intelligence using the `phonenumbers` library.

Features:
  * Robust parsing with a clear error for un-parseable input.
  * Returns validity, line type (mobile/fixed/VoIP…), carrier, region,
    timezones and multiple canonical formats as structured data.
"""
from __future__ import annotations

from typing import Optional

import phonenumbers
from phonenumbers import carrier, geocoder, timezone
from phonenumbers.phonenumberutil import PhoneNumberType, number_type

from ..utils import normalize_phone

_TYPE_NAMES = {
    PhoneNumberType.MOBILE: "mobile",
    PhoneNumberType.FIXED_LINE: "fixed line",
    PhoneNumberType.FIXED_LINE_OR_MOBILE: "fixed line or mobile",
    PhoneNumberType.TOLL_FREE: "toll free",
    PhoneNumberType.PREMIUM_RATE: "premium rate",
    PhoneNumberType.SHARED_COST: "shared cost",
    PhoneNumberType.VOIP: "VoIP",
    PhoneNumberType.PERSONAL_NUMBER: "personal number",
    PhoneNumberType.PAGER: "pager",
    PhoneNumberType.UAN: "UAN",
    PhoneNumberType.VOICEMAIL: "voicemail",
    PhoneNumberType.UNKNOWN: "unknown",
}


def lookup(number: str, default_region: Optional[str] = None, lang: str = "en") -> dict:
    """Parse and enrich a phone number.

    ``number`` should be in international format (``+<country><number>``). If it
    is not, ``default_region`` (an ISO country code like ``"US"``) can help the
    parser interpret a national number.
    """
    raw = number.strip()
    normalized = normalize_phone(raw) if default_region is None else raw

    try:
        parsed = phonenumbers.parse(normalized, default_region)
    except phonenumbers.NumberParseException as exc:
        return {"error": f"could not parse number: {exc}", "input": raw}

    is_valid = phonenumbers.is_valid_number(parsed)
    is_possible = phonenumbers.is_possible_number(parsed)

    ntype = number_type(parsed)

    result = {
        "input": raw,
        "valid": is_valid,
        "possible": is_possible,
        "country_code": parsed.country_code,
        "national_number": parsed.national_number,
        "line_type": _TYPE_NAMES.get(ntype, "unknown"),
        "region": geocoder.description_for_number(parsed, lang) or None,
        "carrier": carrier.name_for_number(parsed, lang) or None,
        "timezones": list(timezone.time_zones_for_number(parsed)) or None,
        "format_e164": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164),
        "format_international": phonenumbers.format_number(
            parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL
        ),
        "format_national": phonenumbers.format_number(
            parsed, phonenumbers.PhoneNumberFormat.NATIONAL
        ),
        "format_rfc3966": phonenumbers.format_number(
            parsed, phonenumbers.PhoneNumberFormat.RFC3966
        ),
    }
    if not is_valid:
        result["warning"] = "Number is not valid; enriched fields may be empty or approximate."
    return result
