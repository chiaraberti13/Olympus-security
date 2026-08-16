"""Strict detection rule loading and evaluation."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

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


def _plain_scalar(value: str, line_number: int) -> str:
    """Parse a deliberately small, non-executable YAML plain scalar."""
    scalar = value.strip()
    if not scalar or scalar.startswith(("!", "&", "*", "|", ">", "{", "[")):
        raise ValueError(f"unsupported YAML scalar on line {line_number}")
    if " #" in scalar:
        scalar = scalar.split(" #", 1)[0].rstrip()
    if len(scalar) >= 2 and scalar[0] == scalar[-1] and scalar[0] in {'"', "'"}:
        scalar = scalar[1:-1]
    return scalar


def _parse_yaml(text: str) -> dict[str, Any]:
    """Parse the strict mapping/list subset used by portable Apollo rules."""
    payload: dict[str, Any] = {}
    section: str | None = None
    for line_number, raw_line in enumerate(text.splitlines(), 1):
        if "\t" in raw_line:
            raise ValueError(f"tabs are not allowed in YAML on line {line_number}")
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        indentation = len(raw_line) - len(raw_line.lstrip(" "))
        content = raw_line.strip()
        if indentation == 0:
            if ":" not in content:
                raise ValueError(f"expected key/value pair on line {line_number}")
            key, raw_value = content.split(":", 1)
            key = key.strip()
            if key in payload:
                raise ValueError(f"duplicate YAML key {key!r} on line {line_number}")
            if raw_value.strip():
                payload[key] = _plain_scalar(raw_value, line_number)
                section = None
            elif key == "conditions":
                payload[key] = {}
                section = key
            elif key == "mitre_attack":
                payload[key] = []
                section = key
            else:
                raise ValueError(f"unsupported nested YAML key {key!r}")
            continue
        if indentation != 2 or section is None:
            raise ValueError(f"invalid YAML indentation on line {line_number}")
        if section == "mitre_attack" and content.startswith("- "):
            payload[section].append(_plain_scalar(content[2:], line_number))
        elif section == "conditions" and ":" in content:
            key, raw_value = content.split(":", 1)
            if key.strip() in payload[section]:
                raise ValueError(f"duplicate condition on line {line_number}")
            payload[section][key.strip()] = _plain_scalar(raw_value, line_number)
        else:
            raise ValueError(f"invalid YAML collection item on line {line_number}")
    return payload


def load_rule(path: Path) -> DetectionRule:
    """Safely load a strict Apollo YAML rule without constructors, tags or anchors."""
    text = path.read_text(encoding="utf-8")
    payload = json.loads(text) if text.lstrip().startswith("{") else _parse_yaml(text)
    if not isinstance(payload, dict):
        raise ValueError("rule document must be a mapping")
    return DetectionRule.model_validate(payload)


def load_rules(directory: Path) -> list[DetectionRule]:
    """Load every ``*.yml``/``*.yaml`` rule in ``directory``, sorted by path."""
    paths = sorted(
        path for pattern in ("*.yml", "*.yaml") for path in directory.glob(pattern)
    )
    rules = [load_rule(path) for path in paths]
    seen: set[str] = set()
    for rule in rules:
        if rule.rule_id in seen:
            raise ValueError(f"duplicate rule_id in {directory}: {rule.rule_id}")
        seen.add(rule.rule_id)
    return rules


def matches(rule: DetectionRule, event: Event) -> bool:
    """Evaluate exact, deterministic event attribute conditions."""
    return event.event_type == rule.event_type and all(
        event.attributes.get(key) == value for key, value in rule.conditions.items()
    )
