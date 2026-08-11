"""Unit tests for Hermes's Shannon-entropy generic secret detection engine."""

from __future__ import annotations

import math

from olympus.hermes.entropy import scan_text_entropy, shannon_entropy


def test_shannon_entropy_of_empty_string_is_zero() -> None:
    assert shannon_entropy("") == 0.0


def test_shannon_entropy_of_repeated_character_is_zero() -> None:
    assert shannon_entropy("a" * 40) == 0.0


def test_shannon_entropy_of_uniform_alphabet_matches_theory() -> None:
    # 4 distinct, equally frequent symbols -> exactly 2 bits/char.
    assert math.isclose(shannon_entropy("abcd" * 10), 2.0, abs_tol=1e-9)


def test_detects_high_entropy_base64_like_secret() -> None:
    secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # AWS docs example secret access key
    matches = scan_text_entropy(f'aws_secret_access_key = "{secret}"')
    assert any(m.matched_text == secret for m in matches)


def test_detects_high_entropy_hex_token_with_hex_threshold() -> None:
    token = "a3f9c1e7b2d84f6091ac7e3b5d2f9081"  # 32 lowercase hex chars
    matches = scan_text_entropy(f"session_key = {token}")
    assert any(m.matched_text == token for m in matches)


def test_hex_token_would_be_missed_by_a_single_high_threshold() -> None:
    # Demonstrates *why* hex gets its own (lower) threshold: its own
    # entropy never reaches the base64 threshold, since a 16-symbol
    # alphabet caps out at 4 bits/char.
    token = "a3f9c1e7b2d84f6091ac7e3b5d2f9081"
    assert shannon_entropy(token) < 4.3


def test_ignores_repeated_low_entropy_token() -> None:
    matches = scan_text_entropy("padding = " + "a" * 40)
    assert matches == []


def test_ignores_short_high_entropy_token_below_min_length() -> None:
    matches = scan_text_entropy("x = aB3$kZ9!", min_length=20)
    assert matches == []


def test_ignores_plain_english_identifier() -> None:
    text = "this_is_a_normal_variable_name_not_a_secret = compute_total(order)"
    assert scan_text_entropy(text) == []


def test_threshold_is_configurable() -> None:
    token = "a3f9c1e7b2d84f6091ac7e3b5d2f9081"
    text = f"key = {token}"
    assert scan_text_entropy(text, hex_threshold=10.0) == []
    assert scan_text_entropy(text, hex_threshold=0.0)


def test_match_reports_correct_line_and_column() -> None:
    secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # AWS docs example secret access key
    text = f"line one\nsecret = {secret}"
    matches = scan_text_entropy(text)
    match = next(m for m in matches if m.matched_text == secret)
    assert match.line == 2
    assert match.column == text.splitlines()[1].index(secret) + 1
