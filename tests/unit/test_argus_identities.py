"""Unit and CLI tests for Argus identity (username/email) permutation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from olympus.argus.identities import (
    IdentityGenerationError,
    IdentityInput,
    IdentityIntel,
    build_identity_asset,
    build_identity_profile,
    export_identity_intel,
    export_identity_list,
    generate_emails,
    generate_usernames,
)
from olympus.cli import app
from olympus.core.enums import AssetType

runner = CliRunner()


def test_identity_input_requires_first_and_last() -> None:
    with pytest.raises(IdentityGenerationError):
        IdentityInput(first="", last="Doe")
    with pytest.raises(IdentityGenerationError):
        IdentityInput(first="John", last="!!!")


def test_identity_input_rejects_bad_domain() -> None:
    with pytest.raises(IdentityGenerationError):
        IdentityInput(first="John", last="Doe", domain="notadomain")


def test_generate_usernames_is_deterministic_and_deduped() -> None:
    identity = IdentityInput(first="John", last="Doe")
    first = generate_usernames(identity)
    second = generate_usernames(identity)
    assert first == second
    assert len(first) == len(set(first))
    assert "johndoe" in first
    assert "jdoe" in first
    assert "john.doe" in first


def test_generate_usernames_folds_accents() -> None:
    identity = IdentityInput(first="José", last="Díaz")
    handles = generate_usernames(identity)
    assert "jose" in handles
    assert "josediaz" in handles
    assert all(handle.isascii() for handle in handles)


def test_generate_usernames_uses_nickname_middle_and_year() -> None:
    identity = IdentityInput(first="John", last="Doe", middle="Q", nickname="jdawg", year="1990")
    handles = generate_usernames(identity)
    assert "jdawg" in handles
    assert "johndoe1990" in handles
    assert any(h.startswith("john") and "q" in h for h in handles)


def test_generate_emails_requires_domain() -> None:
    identity = IdentityInput(first="John", last="Doe")
    with pytest.raises(IdentityGenerationError):
        generate_emails(identity)


def test_generate_emails_pairs_with_domain() -> None:
    identity = IdentityInput(first="John", last="Doe", domain="example.com")
    emails = generate_emails(identity)
    assert "johndoe@example.com" in emails
    assert all(email.endswith("@example.com") for email in emails)


def test_build_identity_profile_without_domain_has_no_emails() -> None:
    profile = build_identity_profile(IdentityInput(first="John", last="Doe"))
    assert profile.usernames
    assert profile.emails == []


def test_build_identity_asset_metadata() -> None:
    profile = build_identity_profile(IdentityInput(first="John", last="Doe", domain="example.com"))
    asset = build_identity_asset(profile)
    assert asset.asset_type is AssetType.ACCOUNT
    assert asset.hostname == "John Doe"
    assert asset.metadata["domain"] == "example.com"
    assert int(asset.metadata["emails"]) == len(profile.emails)


def test_export_identity_intel_and_lists(tmp_path: Path) -> None:
    profile = build_identity_profile(IdentityInput(first="John", last="Doe", domain="example.com"))
    intel = IdentityIntel(profile=profile, asset=build_identity_asset(profile))
    bundle = tmp_path / "sub" / "id.json"
    export_identity_intel(intel, bundle)
    assert json.loads(bundle.read_text())["profile"]["input"]["last"] == "Doe"

    users = tmp_path / "users.txt"
    export_identity_list(profile, users, emails=False)
    assert "johndoe" in users.read_text().splitlines()

    emails = tmp_path / "emails.txt"
    export_identity_list(profile, emails, emails=True)
    assert "johndoe@example.com" in emails.read_text().splitlines()


def test_cli_identities_requires_authorization() -> None:
    result = runner.invoke(app, ["argus", "identities", "--first", "John", "--last", "Doe"])
    assert result.exit_code == 4
    assert "AUTHORIZED USE ONLY" in result.output


def test_cli_identities_ok() -> None:
    result = runner.invoke(
        app,
        [
            "argus",
            "identities",
            "--first",
            "John",
            "--last",
            "Doe",
            "--domain",
            "example.com",
            "--i-am-authorized",
        ],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert "johndoe" in payload["profile"]["usernames"]
    assert "johndoe@example.com" in payload["profile"]["emails"]


def test_cli_identities_invalid_domain() -> None:
    result = runner.invoke(
        app,
        [
            "argus",
            "identities",
            "--first",
            "John",
            "--last",
            "Doe",
            "--domain",
            "notadomain",
            "--i-am-authorized",
        ],
    )
    assert result.exit_code == 2


def test_cli_identities_exports(tmp_path: Path) -> None:
    out = tmp_path / "id.json"
    users = tmp_path / "users.txt"
    emails = tmp_path / "emails.txt"
    result = runner.invoke(
        app,
        [
            "argus",
            "identities",
            "--first",
            "John",
            "--last",
            "Doe",
            "--domain",
            "example.com",
            "--i-am-authorized",
            "--output",
            str(out),
            "--usernames-out",
            str(users),
            "--emails-out",
            str(emails),
        ],
    )
    assert result.exit_code == 0, result.output
    assert out.exists() and users.exists() and emails.exists()
