"""Unit tests for Hermes git-history scanning, against a real fixture repo."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from olympus.hermes.git_history import GitHistoryError, scan_git_history


def _git(repo_path: Path, *args: str) -> None:
    subprocess.run(
        [
            "git",
            "-c",
            "user.email=test@olympus.local",
            "-c",
            "user.name=Olympus Test",
            "-c",
            "commit.gpgsign=false",
            *args,
        ],
        cwd=repo_path,
        check=True,
        capture_output=True,
        text=True,
    )


def _init_fixture_repo(base_path: Path) -> Path:
    """Build a small repo where a secret is added, then removed in a later commit."""
    repo = base_path / "fixture-repo"
    repo.mkdir()
    _git(repo, "init", "-q")

    config = repo / "config.py"
    config.write_text('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
    _git(repo, "add", "config.py")
    _git(repo, "commit", "-q", "-m", "add config with a leaked key")

    config.write_text('AWS_KEY = os.environ["AWS_KEY"]\n')
    _git(repo, "add", "config.py")
    _git(repo, "commit", "-q", "-m", "rotate key, load from env instead")

    readme = repo / "README.md"
    readme.write_text("# Olympus Demo Corp fixture repo\n")
    _git(repo, "add", "README.md")
    _git(repo, "commit", "-q", "-m", "add readme")

    return repo


def test_scan_git_history_finds_secret_committed_in_the_past(tmp_path: Path) -> None:
    repo = _init_fixture_repo(tmp_path)

    findings = scan_git_history(repo)

    all_matches = [m.matched_text for finding in findings for m in finding.rule_matches]
    assert "AKIAIOSFODNN7EXAMPLE" in all_matches


def test_scan_git_history_flags_both_add_and_removal_commits(tmp_path: Path) -> None:
    # The secret is visible in both the commit that introduced it ("+" line)
    # and the one that removed it ("-" line still shows the old value) --
    # exactly why history scanning matters even after a "rotation" commit.
    repo = _init_fixture_repo(tmp_path)

    findings = scan_git_history(repo)

    assert len(findings) == 2
    for finding in findings:
        assert any(m.matched_text == "AKIAIOSFODNN7EXAMPLE" for m in finding.rule_matches)


def test_scan_git_history_clean_repo_has_no_findings(tmp_path: Path) -> None:
    repo = tmp_path / "clean-repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    (repo / "README.md").write_text("# Nothing secret here\n")
    _git(repo, "add", "README.md")
    _git(repo, "commit", "-q", "-m", "init")

    assert scan_git_history(repo) == []


def test_scan_non_repo_raises_git_history_error(tmp_path: Path) -> None:
    not_a_repo = tmp_path / "not-a-repo"
    not_a_repo.mkdir()

    with pytest.raises(GitHistoryError, match="git log failed"):
        scan_git_history(not_a_repo)
