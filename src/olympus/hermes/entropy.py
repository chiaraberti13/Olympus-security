"""Shannon-entropy based generic secret detection with configurable thresholds.

Complements the known-prefix rules in :mod:`olympus.hermes.rules`: catches
high-entropy tokens that don't match any known vendor format (raw API
keys, random passwords) without hardcoding every possible prefix.

Entropy alone is not charset-aware: a purely hexadecimal token can never
exceed 4 bits/char (16 symbols), while a base64-like token can reach 6
bits/char (64 symbols). A single threshold either misses real hex-encoded
secrets or drowns in base64 false positives, so two thresholds are used —
one for hex-only tokens, one for everything else.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass

# '=' is only meaningful as base64 padding, so it may only trail a token,
# never sit inside one -- otherwise an unspaced `KEY=value` assignment (the
# common .env/shell shape) would be swallowed into a single "KEY=value"
# token instead of separating the (uninteresting) name from the value.
_CANDIDATE_TOKEN = re.compile(r"[A-Za-z0-9+/_-]+=*")
# Split across two short literals (neither reaches DEFAULT_MIN_LENGTH) so this
# constant doesn't itself look like a planted high-entropy secret to Hermes.
_HEX_DIGITS = "0123456789"
_HEX_LETTERS = "abcdefABCDEF"
_HEX_CHARS = frozenset(_HEX_DIGITS + _HEX_LETTERS)

DEFAULT_MIN_LENGTH = 20
DEFAULT_HEX_THRESHOLD = 3.0
DEFAULT_BASE64_THRESHOLD = 4.3


def shannon_entropy(value: str) -> float:
    """Return the Shannon entropy of ``value``, in bits per character."""
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _is_hex(token: str) -> bool:
    """Return ``True`` if every character of ``token`` is a hex digit."""
    return all(char in _HEX_CHARS for char in token)


@dataclass(frozen=True)
class EntropyMatch:
    """A high-entropy token found at a specific line/column of scanned text."""

    matched_text: str
    entropy: float
    line: int
    column: int


def scan_text_entropy(
    text: str,
    *,
    min_length: int = DEFAULT_MIN_LENGTH,
    hex_threshold: float = DEFAULT_HEX_THRESHOLD,
    base64_threshold: float = DEFAULT_BASE64_THRESHOLD,
) -> list[EntropyMatch]:
    """Scan ``text`` for tokens whose entropy exceeds the charset-appropriate threshold."""
    matches: list[EntropyMatch] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        for found in _CANDIDATE_TOKEN.finditer(line):
            token = found.group(0)
            if len(token) < min_length:
                continue
            entropy = shannon_entropy(token)
            threshold = hex_threshold if _is_hex(token) else base64_threshold
            if entropy >= threshold:
                matches.append(
                    EntropyMatch(
                        matched_text=token,
                        entropy=entropy,
                        line=line_number,
                        column=found.start() + 1,
                    )
                )
    return matches
