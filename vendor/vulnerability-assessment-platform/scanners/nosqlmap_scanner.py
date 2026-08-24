"""NoSQLMap scanner wrapper."""
from __future__ import annotations

from dataclasses import dataclass
import re
import shutil
import subprocess
from typing import Any, Dict, List

from config import settings

_SEVERITY_HIGH_PATTERNS = (
    "vulnerable",
    "successfully injected",
    "authentication bypass",
    "dumped",
)
_SEVERITY_MEDIUM_PATTERNS = (
    "potential",
    "possible",
    "injection point",
    "suspicious",
)


@dataclass
class NosqlmapScanner:
    enable_live_scans: bool = False

    def run(self, target: str) -> Dict[str, Any]:
        if not self.enable_live_scans:
            return {
                "tool": "nosqlmap",
                "status": "simulated",
                "findings": [
                    {
                        "tool": "nosqlmap",
                        "title": "Possibile superficie NoSQL injection",
                        "severity": "high",
                        "description": "NoSQLMap suggerisce possibili vettori d'injection lato datastore NoSQL.",
                        "recommendation": "Applicare query parametrizzate e validazione rigorosa input.",
                        "found_by": "NoSQLMap – Active Testing",
                    }
                ],
            }

        if not shutil.which("nosqlmap"):
            return {
                "tool": "nosqlmap",
                "status": "skipped",
                "message": "Tool NoSQLMap non installato.",
                "findings": [],
            }

        command = ["nosqlmap", "-u", target]
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=settings.scan_timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return {
                "tool": "nosqlmap",
                "status": "timeout",
                "message": "Timeout durante l'esecuzione di NoSQLMap.",
                "findings": [],
            }

        findings = self._extract_findings(completed.stdout)
        return {
            "tool": "nosqlmap",
            "status": "executed" if completed.returncode == 0 else "completed_with_warnings",
            "findings": findings[: settings.max_findings],
        }

    def _extract_findings(self, output: str) -> List[Dict[str, Any]]:
        normalized_output = (output or "").strip()
        if not normalized_output:
            return []

        text = normalized_output.lower()
        datastore_hits = self._extract_datastores(text)
        if not datastore_hits and "inject" not in text and "vulnerable" not in text:
            return []

        severity = self._infer_severity(text)
        datastores = ", ".join(datastore_hits) if datastore_hits else "NoSQL datastore non specificato"
        return [
            {
                "tool": "nosqlmap",
                "title": "Potenziale NoSQL Injection rilevata",
                "severity": severity,
                "description": (
                    "NoSQLMap ha identificato indicatori coerenti con tentativi di NoSQL injection "
                    f"su: {datastores}."
                ),
                "evidence": normalized_output[:1000],
                "recommendation": (
                    "Usare query parametrizzate/sicure, validare schema e tipi input lato server, "
                    "abilitare rate limiting e monitoraggio degli accessi anomali."
                ),
                "found_by": "NoSQLMap – Active Testing",
                "affected_datastores": datastore_hits,
                "tags": ["nosql", "injection", *[db.lower() for db in datastore_hits]],
            }
        ]

    def _extract_datastores(self, text: str) -> List[str]:
        mapping = {
            "MongoDB": r"\bmongodb\b|\bmongo\b",
            "CouchDB": r"\bcouchdb\b|\bcouch\b",
            "Redis": r"\bredis\b",
        }
        return [name for name, pattern in mapping.items() if re.search(pattern, text)]

    def _infer_severity(self, text: str) -> str:
        if any(pattern in text for pattern in _SEVERITY_HIGH_PATTERNS):
            return "high"
        if any(pattern in text for pattern in _SEVERITY_MEDIUM_PATTERNS):
            return "medium"
        return "low"
