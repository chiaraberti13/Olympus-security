"""Unit tests for Hermes's known-prefix regex secret detection engine."""

from __future__ import annotations

from olympus.hermes.rules import scan_text


def test_detects_aws_access_key_id() -> None:
    matches = scan_text('aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"')
    assert any(m.rule_id == "HERMES-AWS-ACCESS-KEY-ID" for m in matches)


def test_detects_aws_temporary_access_key_id() -> None:
    matches = scan_text("ASIAABCDEFGHIJKLMNOP")
    assert any(m.rule_id == "HERMES-AWS-ACCESS-KEY-ID" for m in matches)


def test_rejects_key_looking_string_without_prefix() -> None:
    # Same length/shape as an AWS key id but wrong prefix -> must not fire.
    matches = scan_text("XXXXIOSFODNN7EXAMPLEY")
    assert not any(m.rule_id == "HERMES-AWS-ACCESS-KEY-ID" for m in matches)


def test_detects_github_token() -> None:
    token = "ghp_" + "a" * 36
    matches = scan_text(f"GITHUB_TOKEN={token}")
    assert any(m.rule_id == "HERMES-GITHUB-TOKEN" and m.matched_text == token for m in matches)


def test_rejects_github_token_too_short() -> None:
    matches = scan_text("ghp_tooshort")
    assert not any(m.rule_id == "HERMES-GITHUB-TOKEN" for m in matches)


def test_detects_github_fine_grained_pat() -> None:
    token = "github_pat_" + "a" * 30
    matches = scan_text(token)
    assert any(m.rule_id == "HERMES-GITHUB-FINE-GRAINED-PAT" for m in matches)


def test_detects_slack_token() -> None:
    matches = scan_text("SLACK_BOT_TOKEN=xoxb-123456789012-abcdefghijklmnop")
    assert any(m.rule_id == "HERMES-SLACK-TOKEN" for m in matches)


def test_detects_jwt() -> None:
    jwt = (
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"
        ".dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    )
    matches = scan_text(f"Authorization: Bearer {jwt}")
    assert any(m.rule_id == "HERMES-JWT" and m.matched_text == jwt for m in matches)


def test_rejects_plain_base64_that_is_not_jwt_shaped() -> None:
    matches = scan_text("data = 'TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQ='")
    assert not any(m.rule_id == "HERMES-JWT" for m in matches)


def test_detects_private_key_block() -> None:
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIIBOwIBAAJBAK...\n-----END RSA PRIVATE KEY-----"
    matches = scan_text(text)
    assert any(m.rule_id == "HERMES-PRIVATE-KEY" for m in matches)


def test_clean_source_code_has_no_matches() -> None:
    clean_code = (
        "def add(a: int, b: int) -> int:\n"
        "    return a + b\n"
        "\n"
        "API_URL = 'https://api.olympusdemocorp.example/v1'\n"
    )
    assert scan_text(clean_code) == []


def test_match_reports_correct_line_and_column() -> None:
    text = "line one\nline two AKIAIOSFODNN7EXAMPLE trailing"
    matches = scan_text(text)
    match = next(m for m in matches if m.rule_id == "HERMES-AWS-ACCESS-KEY-ID")
    assert match.line == 2
    assert match.column == text.splitlines()[1].index("AKIA") + 1
