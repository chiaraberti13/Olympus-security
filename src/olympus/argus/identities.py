"""Username and email permutation generation for Argus.

A recurring OSINT primitive — popularised by tools such as *username* enumerators
and the classic *email-permutator* — is turning a real person's name into the
candidate handles and addresses they are likely to use, so those candidates can
then be checked against public sites (Argus ``accounts``) or validated
(Argus ``email``).

This module is that primitive, done the Olympus way: pure, **offline** and
deterministic. It never touches the network; it only derives an ordered,
de-duplicated set of plausible usernames and emails from the supplied name
parts. Because the output is candidate identities about a real person, the CLI
gates it behind an explicit authorization flag — generating a target's likely
handles is privacy-sensitive OSINT.
"""

from __future__ import annotations

import json
import re
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path

from olympus.core.enums import AssetType, Source
from olympus.core.models import Asset

#: Separators inserted between name parts to widen the candidate set.
_SEPARATORS: tuple[str, ...] = ("", ".", "_", "-")

#: Conservative domain shape used when a domain is supplied for email candidates.
_DOMAIN_RE = re.compile(r"^[^@\s]+\.[^@\s]+$")


class IdentityGenerationError(ValueError):
    """Raised when the supplied name parts or domain are unusable."""


def _slug(value: str) -> str:
    """Fold accents and reduce ``value`` to lower-case ``[a-z0-9]`` only."""
    decomposed = unicodedata.normalize("NFKD", value)
    ascii_only = decomposed.encode("ascii", "ignore").decode("ascii")
    return re.sub(r"[^a-z0-9]", "", ascii_only.lower())


def _ordered_unique(values: list[str]) -> list[str]:
    """Return ``values`` with duplicates removed, preserving first-seen order."""
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            result.append(value)
    return result


@dataclass(frozen=True)
class IdentityInput:
    """Normalized name parts used to derive candidate identities."""

    first: str
    last: str
    middle: str | None = None
    nickname: str | None = None
    year: str | None = None
    domain: str | None = None

    def __post_init__(self) -> None:
        if not _slug(self.first) or not _slug(self.last):
            raise IdentityGenerationError("both 'first' and 'last' name parts are required")
        if self.domain is not None and not _DOMAIN_RE.match(self.domain.strip().lower()):
            raise IdentityGenerationError(f"not a valid domain: {self.domain!r}")


def generate_usernames(identity: IdentityInput) -> list[str]:
    """Derive an ordered, de-duplicated set of candidate usernames.

    The generator combines first/last (and, when given, middle and nickname)
    with a fixed family of separators, initial abbreviations and an optional
    year suffix. Output order is stable so the result is fully reproducible.
    """
    first = _slug(identity.first)
    last = _slug(identity.last)
    middle = _slug(identity.middle) if identity.middle else ""
    nickname = _slug(identity.nickname) if identity.nickname else ""
    fi, li = first[0], last[0]
    mi = middle[0] if middle else ""

    candidates: list[str] = [first, last]
    if nickname:
        candidates.append(nickname)

    for sep in _SEPARATORS:
        candidates.append(f"{first}{sep}{last}")
        candidates.append(f"{last}{sep}{first}")
        candidates.append(f"{fi}{sep}{last}")
        candidates.append(f"{first}{sep}{li}")
        if nickname:
            candidates.append(f"{nickname}{sep}{last}")
        if mi:
            candidates.append(f"{first}{sep}{mi}{sep}{last}")

    # Initials and initial-based handles.
    candidates.append(f"{fi}{li}")
    candidates.append(f"{fi}{mi}{li}" if mi else f"{fi}{li}")

    # Year-suffixed variants of the strongest base handles.
    if identity.year:
        year = _slug(identity.year)
        if year:
            for base in (first, f"{first}{last}", f"{first}.{last}", f"{fi}{last}", nickname):
                if base:
                    candidates.append(f"{base}{year}")

    return _ordered_unique(candidates)


def generate_emails(identity: IdentityInput, usernames: list[str] | None = None) -> list[str]:
    """Derive candidate email addresses ``<username>@<domain>``.

    Requires ``identity.domain``. When ``usernames`` is omitted it is generated
    from ``identity`` first, keeping emails and handles consistent.
    """
    if identity.domain is None:
        raise IdentityGenerationError("a domain is required to generate email candidates")
    domain = identity.domain.strip().lower()
    handles = usernames if usernames is not None else generate_usernames(identity)
    return [f"{handle}@{domain}" for handle in handles]


@dataclass(frozen=True)
class IdentityProfile:
    """Bundle of generated candidate identities for one person."""

    identity: IdentityInput
    usernames: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serializable view of the profile."""
        return {
            "input": {
                "first": self.identity.first,
                "last": self.identity.last,
                "middle": self.identity.middle,
                "nickname": self.identity.nickname,
                "year": self.identity.year,
                "domain": self.identity.domain,
            },
            "usernames": list(self.usernames),
            "emails": list(self.emails),
        }


def build_identity_profile(identity: IdentityInput) -> IdentityProfile:
    """Generate usernames and (when a domain is present) emails for ``identity``."""
    usernames = generate_usernames(identity)
    emails = generate_emails(identity, usernames) if identity.domain else []
    return IdentityProfile(identity=identity, usernames=usernames, emails=emails)


def build_identity_asset(profile: IdentityProfile) -> Asset:
    """Convert an identity profile into a ``core.Asset`` for downstream tools."""
    label = f"{profile.identity.first} {profile.identity.last}".strip()
    metadata: dict[str, str] = {
        "usernames": str(len(profile.usernames)),
        "emails": str(len(profile.emails)),
    }
    if profile.identity.domain:
        metadata["domain"] = profile.identity.domain.strip().lower()
    return Asset(
        asset_type=AssetType.ACCOUNT,
        hostname=label,
        source=Source.ARGUS,
        tags=["argus", "identities", "permutation"],
        metadata=metadata,
    )


@dataclass(frozen=True)
class IdentityIntel:
    """Export-ready bundle: the profile plus its shared-contract asset."""

    profile: IdentityProfile
    asset: Asset

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serializable view of the whole bundle."""
        return {
            "profile": self.profile.to_dict(),
            "asset": json.loads(self.asset.model_dump_json()),
        }


def export_identity_intel(intel: IdentityIntel, path: Path) -> None:
    """Write the identity-intel bundle (profile + asset) as JSON to ``path``."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(intel.to_dict(), indent=2, sort_keys=True), encoding="utf-8")


def export_identity_list(profile: IdentityProfile, path: Path, *, emails: bool = False) -> None:
    """Write one candidate per line (usernames, or emails when ``emails`` is set)."""
    values = profile.emails if emails else profile.usernames
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(values) + ("\n" if values else ""), encoding="utf-8")
