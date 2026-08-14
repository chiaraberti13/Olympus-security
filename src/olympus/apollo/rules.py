"""Strict detection rule loading and evaluation."""

from __future__ import annotations

import json
import re
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, field_validator

from olympus.core.enums import Severity
from olympus.core.models import Event


class DetectionRule(BaseModel):
    """A minimal portable detection rule expressed as YAML-compatible JSON."""

    model_config = ConfigDict(extra="forbid")

    rule_id: str = Field(pattern=r"^APL-[A-Z0-9-]+$")
    title: str = Field(min_length=1)
    event_type: str = Field(min_length=1)
    conditions: dict[str, str] = Field(default_factory=dict)
    severity: Severity = Severity.MEDIUM
    mitre_attack: list[str] = Field(default_factory=list)

    @field_validator("mitre_attack")
    @classmethod
    def validate_mitre(cls, techniques: list[str]) -> list[str]:
        """Validate ATT&CK technique identifiers without external lookups."""
        if any(re.fullmatch(r"T\d{4}(?:\.\d{3})?", item) is None for item in techniques):
            raise ValueError("MITRE ATT&CK IDs must match T#### or T####.###")
        return techniques


def load_rule(path: Path) -> DetectionRule:
    """Load a JSON document, a safe interoperable subset of YAML 1.2."""
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("rule document must be a mapping")
    return DetectionRule.model_validate(payload)


def matches(rule: DetectionRule, event: Event) -> bool:
    """Evaluate exact, deterministic event attribute conditions."""
    return event.event_type == rule.event_type and all(
        event.attributes.get(key) == value for key, value in rule.conditions.items()
    )
