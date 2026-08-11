"""Git history scanning: find secrets committed in the past, not just on disk.

A secret that was committed and later removed is still reachable through
git history unless the repository is rewritten. This module runs the
regex and entropy engines (see :mod:`olympus.hermes.rules` and
:mod:`olympus.hermes.entropy`) over every commit's diff, not just the
current working tree.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from olympus.hermes.entropy import (
    DEFAULT_BASE64_THRESHOLD,
    DEFAULT_HEX_THRESHOLD,
    DEFAULT_MIN_LENGTH,
    EntropyMatch,
    scan_text_entropy,
)
from olympus.hermes.rules import BUILTIN_RULES, RuleMatch, SecretRule, scan_text

_COMMIT_HEADER = re.compile(r"^commit ([0-9a-f]{40})", re.MULTILINE)


class GitHistoryError(RuntimeError):
    """Raised when ``git log`` cannot be run or fails (not a repo, git missing...)."""


@dataclass(frozen=True)
class HistoryFinding:
    """Secret-scan hits found in a single commit's diff."""

    commit: str
    rule_matches: list[RuleMatch]
    entropy_matches: list[EntropyMatch]


def _run_git_log(repo_path: Path) -> str:
    """Return the full patch log (``git log -p --all``) of ``repo_path``."""
    try:
        result = subprocess.run(
            ["git", "log", "-p", "--all", "--no-color"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=True,
        )
    except FileNotFoundError as exc:
        raise GitHistoryError("git executable not found") from exc
    except subprocess.CalledProcessError as exc:
        raise GitHistoryError(f"git log failed for {repo_path}: {exc.stderr}") from exc
    return result.stdout


def _split_by_commit(log_output: str) -> list[tuple[str, str]]:
    """Split ``git log -p`` output into ``(commit_hash, diff_text)`` chunks."""
    headers = list(_COMMIT_HEADER.finditer(log_output))
    chunks: list[tuple[str, str]] = []
    for index, header in enumerate(headers):
        start = header.end()
        end = headers[index + 1].start() if index + 1 < len(headers) else len(log_output)
        chunks.append((header.group(1), log_output[start:end]))
    return chunks


def scan_git_history(
    repo_path: Path,
    *,
    rules: tuple[SecretRule, ...] = BUILTIN_RULES,
    min_length: int = DEFAULT_MIN_LENGTH,
    hex_threshold: float = DEFAULT_HEX_THRESHOLD,
    base64_threshold: float = DEFAULT_BASE64_THRESHOLD,
) -> list[HistoryFinding]:
    """Scan every commit reachable from any ref in ``repo_path`` for secrets."""
    log_output = _run_git_log(repo_path)

    findings: list[HistoryFinding] = []
    for commit_hash, diff_text in _split_by_commit(log_output):
        rule_matches = scan_text(diff_text, rules)
        entropy_matches = scan_text_entropy(
            diff_text,
            min_length=min_length,
            hex_threshold=hex_threshold,
            base64_threshold=base64_threshold,
        )
        if rule_matches or entropy_matches:
            findings.append(
                HistoryFinding(
                    commit=commit_hash,
                    rule_matches=rule_matches,
                    entropy_matches=entropy_matches,
                )
            )
    return findings
