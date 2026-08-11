"""Regex-based secret detection using known vendor prefixes/formats.

Each :class:`SecretRule` pairs a stable id with a compiled regex that
targets a specific, well-known credential shape (AWS, GitHub, Slack, JWT,
PEM private keys). A fixed prefix or structure keeps both detection and
false-positive control tractable without entropy analysis (see
:mod:`olympus.hermes.entropy` for the generic, prefix-less case).
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class SecretRule:
    """A named, compiled regex targeting one known secret format."""

    rule_id: str
    name: str
    pattern: re.Pattern[str]
    description: str


@dataclass(frozen=True)
class RuleMatch:
    """One regex rule hit at a specific line/column of scanned text."""

    rule_id: str
    rule_name: str
    matched_text: str
    line: int
    column: int


def _rule(rule_id: str, name: str, pattern: str, description: str) -> SecretRule:
    return SecretRule(
        rule_id=rule_id, name=name, pattern=re.compile(pattern), description=description
    )


BUILTIN_RULES: tuple[SecretRule, ...] = (
    _rule(
        "HERMES-AWS-ACCESS-KEY-ID",
        "AWS Access Key ID",
        r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
        "AWS IAM long-term or temporary access key id",
    ),
    _rule(
        "HERMES-GITHUB-TOKEN",
        "GitHub Token",
        r"\bgh[oprsu]_[A-Za-z0-9]{36}\b",
        "GitHub OAuth/PAT/app/refresh token",
    ),
    _rule(
        "HERMES-GITHUB-FINE-GRAINED-PAT",
        "GitHub Fine-Grained Personal Access Token",
        r"\bgithub_pat_[A-Za-z0-9_]{22,255}\b",
        "GitHub fine-grained personal access token",
    ),
    _rule(
        "HERMES-SLACK-TOKEN",
        "Slack Token",
        r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b",
        "Slack bot/user/app/refresh token",
    ),
    _rule(
        "HERMES-JWT",
        "JSON Web Token",
        r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b",
        "JSON Web Token (header.payload.signature)",
    ),
    _rule(
        "HERMES-PRIVATE-KEY",
        "Private Key Block",
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----",
        "PEM-encoded private key block header",
    ),
)


def scan_text(text: str, rules: tuple[SecretRule, ...] = BUILTIN_RULES) -> list[RuleMatch]:
    """Scan ``text`` line by line against every rule in ``rules``."""
    matches: list[RuleMatch] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        for rule in rules:
            for found in rule.pattern.finditer(line):
                matches.append(
                    RuleMatch(
                        rule_id=rule.rule_id,
                        rule_name=rule.name,
                        matched_text=found.group(0),
                        line=line_number,
                        column=found.start() + 1,
                    )
                )
    return matches
