"""CLI-level tests for `olympus hermes scan` and `olympus hermes git-history`."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from typer.testing import CliRunner

from olympus.cli import app

runner = CliRunner()


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


# --- scan -------------------------------------------------------------------


def test_scan_file_with_secret_exits_nonzero_and_masks_output(tmp_path: Path) -> None:
    leaked = tmp_path / "leaked.env"
    leaked.write_text("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n")

    result = runner.invoke(app, ["hermes", "scan", str(leaked)])

    assert result.exit_code == 1
    assert "HERMES-AWS-ACCESS-KEY-ID" in result.stdout
    assert "AKIAIOSFODNN7EXAMPLE" not in result.stdout
    assert "AKIA" in result.stdout  # masked, but edges are kept


def test_scan_clean_file_exits_zero(tmp_path: Path) -> None:
    clean = tmp_path / "clean.env"
    clean.write_text("API_URL=https://api.olympusdemocorp.example/v1\n")

    result = runner.invoke(app, ["hermes", "scan", str(clean)])

    assert result.exit_code == 0
    assert "no secrets found" in result.stdout


def test_scan_directory_recurses_into_files(tmp_path: Path) -> None:
    nested = tmp_path / "nested"
    nested.mkdir()
    (nested / "leaked.env").write_text("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n")
    (tmp_path / "clean.env").write_text("LOG_LEVEL=info\n")

    result = runner.invoke(app, ["hermes", "scan", str(tmp_path)])

    assert result.exit_code == 1
    assert "leaked.env" in result.stdout


def test_scan_writes_sarif_report(tmp_path: Path) -> None:
    leaked = tmp_path / "leaked.env"
    leaked.write_text("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n")
    sarif_path = tmp_path / "report.sarif.json"

    result = runner.invoke(
        app, ["hermes", "scan", str(leaked), "--sarif-output", str(sarif_path)]
    )

    assert result.exit_code == 1
    report = json.loads(sarif_path.read_text(encoding="utf-8"))
    assert report["version"] == "2.1.0"
    assert "AKIAIOSFODNN7EXAMPLE" not in sarif_path.read_text(encoding="utf-8")


# --- git-history --------------------------------------------------------------


def _fixture_repo_with_leaked_secret(base_path: Path) -> Path:
    repo = base_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    config = repo / "config.py"
    config.write_text('AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"\n')
    _git(repo, "add", "config.py")
    _git(repo, "commit", "-q", "-m", "add leaked key")
    return repo


def test_git_history_detects_secret_and_exits_nonzero(tmp_path: Path) -> None:
    repo = _fixture_repo_with_leaked_secret(tmp_path)

    result = runner.invoke(app, ["hermes", "git-history", "--repo", str(repo)])

    assert result.exit_code == 1
    assert "HERMES-AWS-ACCESS-KEY-ID" in result.stdout
    assert "AKIAIOSFODNN7EXAMPLE" not in result.stdout


def test_git_history_clean_repo_exits_zero(tmp_path: Path) -> None:
    repo = tmp_path / "clean-repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    (repo / "README.md").write_text("# clean\n")
    _git(repo, "add", "README.md")
    _git(repo, "commit", "-q", "-m", "init")

    result = runner.invoke(app, ["hermes", "git-history", "--repo", str(repo)])

    assert result.exit_code == 0
    assert "no secrets found" in result.stdout


def test_git_history_non_repo_errors(tmp_path: Path) -> None:
    not_a_repo = tmp_path / "not-a-repo"
    not_a_repo.mkdir()

    result = runner.invoke(app, ["hermes", "git-history", "--repo", str(not_a_repo)])

    assert result.exit_code == 2
    assert "git history error" in result.output


def test_git_history_writes_sarif_report(tmp_path: Path) -> None:
    repo = _fixture_repo_with_leaked_secret(tmp_path)
    sarif_path = tmp_path / "history.sarif.json"

    result = runner.invoke(
        app,
        ["hermes", "git-history", "--repo", str(repo), "--sarif-output", str(sarif_path)],
    )

    assert result.exit_code == 1
    report = json.loads(sarif_path.read_text(encoding="utf-8"))
    assert report["version"] == "2.1.0"
    assert report["runs"][0]["results"]
