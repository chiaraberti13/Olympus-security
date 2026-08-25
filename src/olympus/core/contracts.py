"""Version negotiation helpers for persisted Olympus contracts.

Olympus documents use Semantic Versioning. Consumers accept their exact schema
name and the same major/minor version they implement; patch releases remain
wire-compatible. A major or newer-minor document requires an explicit adapter
instead of being guessed into an older model.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

CURRENT_CONTRACT_VERSION = "1.0.0"
_SEMVER = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")


class ContractCompatibilityError(ValueError):
    """Raised when a persisted document is not compatible with a consumer."""


@dataclass(frozen=True, order=True)
class ContractVersion:
    """Parsed, comparable Semantic Versioning core triplet."""

    major: int
    minor: int
    patch: int

    @classmethod
    def parse(cls, value: object) -> ContractVersion:
        """Parse a strict ``MAJOR.MINOR.PATCH`` string without coercion."""
        if not isinstance(value, str) or (match := _SEMVER.fullmatch(value)) is None:
            raise ContractCompatibilityError(
                f"schema_version must be semantic version MAJOR.MINOR.PATCH, got {value!r}"
            )
        return cls(*(int(part) for part in match.groups()))


def validate_contract_header(
    document: object,
    *,
    schema_name: str,
    supported_version: str = CURRENT_CONTRACT_VERSION,
) -> dict[str, Any]:
    """Validate a document's identity/version and return its typed mapping.

    Same-major, same-or-older-minor documents are compatible. Patch differences
    are accepted. Callers still validate the full payload with the strict model,
    so compatible headers cannot bypass structural validation.
    """
    if not isinstance(document, dict):
        raise ContractCompatibilityError("contract document must be a JSON object")
    actual_name = document.get("schema_name")
    if actual_name != schema_name:
        raise ContractCompatibilityError(
            f"expected schema_name {schema_name!r}, got {actual_name!r}"
        )
    actual = ContractVersion.parse(document.get("schema_version"))
    supported = ContractVersion.parse(supported_version)
    if actual.major != supported.major or actual.minor > supported.minor:
        raise ContractCompatibilityError(
            f"unsupported {schema_name} version {actual.major}.{actual.minor}.{actual.patch}; "
            f"consumer supports {supported_version}"
        )
    return document
