"""Command-line interface for the Hermes module."""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path

import typer

from olympus.hermes.entropy import scan_text_entropy
from olympus.hermes.git_history import GitHistoryError, scan_git_history
from olympus.hermes.rules import scan_text
from olympus.hermes.sarif import Finding, build_sarif_report, mask_secret

app = typer.Typer(
    help="Hermes — Secret & config scanner (DevSecOps).",
    no_args_is_help=True,
)

ENTROPY_RULE_ID = "HERMES-HIGH-ENTROPY"
DEMO_SAMPLES_PATH = Path("examples/input/hermes-samples")
DEMO_SARIF_OUTPUT_PATH = Path("examples/output/hermes-report.sarif.json")


def _findings_for_text(text: str, file_path: str) -> list[Finding]:
    """Run both the regex and entropy engines over ``text``, as Findings."""
    findings = [
        Finding(
            rule_id=match.rule_id,
            rule_name=match.rule_name,
            message=f"{match.rule_name} detected",
            file_path=file_path,
            line=match.line,
            column=match.column,
            matched_text=match.matched_text,
        )
        for match in scan_text(text)
    ]
    findings.extend(
        Finding(
            rule_id=ENTROPY_RULE_ID,
            rule_name="High-Entropy String",
            message=f"High-entropy string detected (entropy={match.entropy:.2f} bits/char)",
            file_path=file_path,
            line=match.line,
            column=match.column,
            matched_text=match.matched_text,
        )
        for match in scan_text_entropy(text)
    )
    return findings


def _iter_files(paths: list[Path]) -> list[Path]:
    """Expand a mix of files/directories into a sorted, deduplicated file list."""
    files: set[Path] = set()
    for path in paths:
        if path.is_dir():
            files.update(candidate for candidate in path.rglob("*") if candidate.is_file())
        elif path.is_file():
            files.add(path)
    return sorted(files)


def _report_findings(findings: list[Finding]) -> None:
    for finding in findings:
        typer.echo(
            f"{finding.file_path}:{finding.line}:{finding.column} "
            f"[{finding.rule_id}] {mask_secret(finding.matched_text)}"
        )


def _write_sarif(findings: list[Finding], output: Path, *, tool_name: str) -> None:
    report = build_sarif_report(findings, tool_name=tool_name)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")


@app.command()
def scan(
    paths: list[Path] = typer.Argument(..., help="Files or directories to scan for secrets."),
    sarif_output: Path | None = typer.Option(
        None, "--sarif-output", help="If set, write a SARIF 2.1.0 report to this path."
    ),
) -> None:
    """Scan files for known-prefix and high-entropy secrets.

    Exits with code 1 if any secret is found — suitable as a pre-commit hook
    (``pass_filenames: true`` feeds staged files as ``paths``).
    """
    findings: list[Finding] = []
    for file_path in _iter_files(paths):
        text = file_path.read_text(encoding="utf-8", errors="replace")
        findings.extend(_findings_for_text(text, str(file_path)))

    _report_findings(findings)
    if sarif_output is not None:
        _write_sarif(findings, sarif_output, tool_name="hermes")

    if findings:
        typer.echo(f"hermes: {len(findings)} finding(s) — blocking.", err=True)
        raise typer.Exit(code=1)
    typer.echo("hermes: no secrets found.")


@app.command("git-history")
def git_history(
    repo: Path = typer.Option(Path(), "--repo", help="Path to the git repository to scan."),
    sarif_output: Path | None = typer.Option(
        None, "--sarif-output", help="If set, write a SARIF 2.1.0 report to this path."
    ),
) -> None:
    """Scan every commit reachable from any ref for secrets, not just the working tree."""
    try:
        history_findings = scan_git_history(repo)
    except GitHistoryError as exc:
        typer.echo(f"hermes: git history error: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    findings: list[Finding] = []
    for item in history_findings:
        commit_ref = f"git:{item.commit[:12]}"
        for rule_match in item.rule_matches:
            findings.append(
                Finding(
                    rule_id=rule_match.rule_id,
                    rule_name=rule_match.rule_name,
                    message=f"{rule_match.rule_name} detected in commit {item.commit[:12]}",
                    file_path=commit_ref,
                    line=rule_match.line,
                    column=rule_match.column,
                    matched_text=rule_match.matched_text,
                )
            )
        for entropy_match in item.entropy_matches:
            findings.append(
                Finding(
                    rule_id=ENTROPY_RULE_ID,
                    rule_name="High-Entropy String",
                    message=f"High-entropy string in commit {item.commit[:12]}",
                    file_path=commit_ref,
                    line=entropy_match.line,
                    column=entropy_match.column,
                    matched_text=entropy_match.matched_text,
                )
            )

    _report_findings(findings)
    if sarif_output is not None:
        _write_sarif(findings, sarif_output, tool_name="hermes-git-history")

    if findings:
        typer.echo(f"hermes: {len(findings)} finding(s) in history — blocking.", err=True)
        raise typer.Exit(code=1)
    typer.echo("hermes: no secrets found in history.")


def _git(repo_path: Path, *args: str) -> None:
    subprocess.run(
        [
            "git",
            "-c",
            "user.email=demo@olympusdemocorp.example",
            "-c",
            "user.name=Olympus Demo Corp",
            "-c",
            "commit.gpgsign=false",
            *args,
        ],
        cwd=repo_path,
        check=True,
        capture_output=True,
        text=True,
    )


def _build_demo_git_repo(repo_path: Path, planted_secret: str) -> None:
    """Build a throwaway repo where ``planted_secret`` is committed, then rotated out."""
    _git(repo_path, "init", "-q")
    config = repo_path / "config.py"
    config.write_text(f'AWS_ACCESS_KEY_ID = "{planted_secret}"\n')
    _git(repo_path, "add", "config.py")
    _git(repo_path, "commit", "-q", "-m", "add config with a leaked demo key")

    config.write_text('AWS_ACCESS_KEY_ID = os.environ["AWS_ACCESS_KEY_ID"]\n')
    _git(repo_path, "add", "config.py")
    _git(repo_path, "commit", "-q", "-m", "rotate key, load from environment instead")


@app.command()
def demo() -> None:
    """Run the full Hermes pipeline on synthetic 'Olympus Demo Corp' samples.

    Scans the committed sample files under ``examples/input/hermes-samples``
    (real files, real findings, real SARIF output) and then demonstrates
    git-history scanning against a throwaway repo built on the fly, so the
    demo never depends on the network and never touches this project's own
    git history.
    """
    typer.echo(f"hermes: demo — scanning synthetic sample files in {DEMO_SAMPLES_PATH}")

    findings: list[Finding] = []
    aws_key_matches: list[str] = []
    for file_path in _iter_files([DEMO_SAMPLES_PATH]):
        text = file_path.read_text(encoding="utf-8", errors="replace")
        findings.extend(_findings_for_text(text, str(file_path)))
        aws_key_matches.extend(
            match.matched_text
            for match in scan_text(text)
            if match.rule_id == "HERMES-AWS-ACCESS-KEY-ID"
        )

    _report_findings(findings)
    _write_sarif(findings, DEMO_SARIF_OUTPUT_PATH, tool_name="hermes-demo")
    typer.echo(
        f"hermes: wrote SARIF report ({len(findings)} finding(s)) to {DEMO_SARIF_OUTPUT_PATH}"
    )

    typer.echo("hermes: demo — scanning a throwaway repo's git history")
    # Reuse a key already planted in the sample files above instead of a
    # second hardcoded literal, so no fake secret lives directly in source.
    fallback_secret = "AKIA" + "0" * 16  # built, not a literal: avoids self-triggering the scan
    planted_secret = aws_key_matches[0] if aws_key_matches else fallback_secret
    try:
        with tempfile.TemporaryDirectory() as tmp_dir:
            repo_path = Path(tmp_dir) / "demo-repo"
            repo_path.mkdir()
            _build_demo_git_repo(repo_path, planted_secret)
            history_findings = scan_git_history(repo_path)
    except (GitHistoryError, OSError, subprocess.CalledProcessError) as exc:
        # The history demo is illustrative, not the point of the command:
        # a missing/broken git must not fail the whole (otherwise valid) demo.
        typer.echo(f"hermes: warning: git history demo skipped: {exc}", err=True)
    else:
        occurrences = sum(
            len(item.rule_matches) + len(item.entropy_matches) for item in history_findings
        )
        typer.echo(
            f"hermes: found {occurrences} historical secret occurrence(s) across "
            f"{len(history_findings)} commit(s) — the key stays visible in history "
            "even after being rotated out"
        )
