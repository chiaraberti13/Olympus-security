"""Secret detection engines for files and Git history."""

from __future__ import annotations

import hashlib
import math
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

PATTERNS = {
    "aws-access-key": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    "github-token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
}
TOKEN = re.compile(r"\b[A-Za-z0-9+/=_-]{20,}\b")


@dataclass(frozen=True)
class SecretFinding:
    """A masked potential secret location."""

    rule: str
    path: str
    line: int
    masked: str
    fingerprint: str


def _mask(value: str) -> str:
    return f"{value[:4]}…{value[-4:]}" if len(value) > 8 else "********"


def _entropy(value: str) -> float:
    frequencies = {character: value.count(character) for character in set(value)}
    return -sum(
        (count / len(value)) * math.log2(count / len(value))
        for count in frequencies.values()
    )


def scan_text(text: str, path: str, entropy_threshold: float = 4.5) -> list[SecretFinding]:
    """Scan text using known prefixes followed by configurable entropy detection."""
    findings: list[SecretFinding] = []
    seen: set[tuple[int, str]] = set()
    for line_number, line in enumerate(text.splitlines(), 1):
        matches = [
            (rule, match.group())
            for rule, pattern in PATTERNS.items()
            for match in pattern.finditer(line)
        ]
        matches.extend(
            ("high-entropy", match.group())
            for match in TOKEN.finditer(line)
            if _entropy(match.group()) >= entropy_threshold
        )
        for rule, value in matches:
            key = (line_number, value)
            if key in seen:
                continue
            seen.add(key)
            fingerprint = hashlib.sha256(f"{path}:{line_number}:{value}".encode()).hexdigest()
            findings.append(SecretFinding(rule, path, line_number, _mask(value), fingerprint))
    return findings


def scan_path(path: Path, entropy_threshold: float = 4.5) -> list[SecretFinding]:
    """Scan one file or a directory without following symlinks or binary files."""
    files = (
        [path]
        if path.is_file()
        else sorted(item for item in path.rglob("*") if item.is_file() and not item.is_symlink())
    )
    findings: list[SecretFinding] = []
    for file in files:
        try:
            text = file.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        findings.extend(scan_text(text, str(file), entropy_threshold))
    return findings


def scan_git_history(repository: Path, entropy_threshold: float = 4.5) -> list[SecretFinding]:
    """Scan committed patches without checking out or modifying repository state."""
    git = shutil.which("git")
    if git is None:
        raise OSError("git executable not found")
    result = subprocess.run(  # noqa: S603 - executable and arguments are controlled
        [git, "log", "--all", "--format=commit:%H", "-p", "--no-ext-diff"],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return scan_text(result.stdout, "git-history", entropy_threshold)
