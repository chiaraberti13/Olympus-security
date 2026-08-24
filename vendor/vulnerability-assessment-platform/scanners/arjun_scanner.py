"""Arjun scanner wrapper."""
from __future__ import annotations

from dataclasses import dataclass
import json
import shutil
import subprocess
from tempfile import NamedTemporaryFile
from typing import Any, Dict, List
from urllib.parse import urlparse

from config import settings


@dataclass
class ArjunScanner:
    enable_live_scans: bool = False

    def run(self, target: str) -> Dict[str, Any]:
        if not self.enable_live_scans:
            return {
                "tool": "arjun",
                "status": "simulated",
                "findings": [
                    {
                        "tool": "arjun",
                        "title": "Parametri HTTP nascosti rilevati",
                        "severity": "medium",
                        "description": "Arjun ha identificato parametri non documentati sull'endpoint target.",
                        "recommendation": "Validare e filtrare rigorosamente tutti i parametri in input.",
                        "found_by": "Arjun – Active Testing",
                    }
                ],
            }

        if not shutil.which("arjun"):
            return {
                "tool": "arjun",
                "status": "skipped",
                "message": "Tool arjun non installato.",
                "findings": [],
            }

        with NamedTemporaryFile(mode="w+", suffix=".json") as output_file:
            command = ["arjun", "-u", target, "--json", "-o", output_file.name]
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
                    "tool": "arjun",
                    "status": "timeout",
                    "message": "Timeout durante l'esecuzione di Arjun.",
                    "findings": [],
                }

            payload = self._load_json_output(output_file.name)
            findings = self._extract_findings(payload, target)
            return {
                "tool": "arjun",
                "status": "executed" if completed.returncode == 0 else "completed_with_warnings",
                "findings": findings[: settings.max_findings],
            }

    def _load_json_output(self, output_path: str) -> Any:
        try:
            with open(output_path, "r", encoding="utf-8") as handle:
                raw = handle.read().strip()
        except OSError:
            return {}
        if not raw:
            return {}
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {}

    def _extract_findings(self, payload: Any, target: str) -> List[Dict[str, Any]]:
        params = self._extract_params(payload, target)
        clean_params = [str(p) for p in params if isinstance(p, str) and p.strip()]
        if not clean_params:
            return []
        return [
            {
                "tool": "arjun",
                "title": "Parametri HTTP non documentati identificati",
                "severity": "medium",
                "description": (
                    "Arjun ha rilevato parametri potenzialmente sensibili che aumentano la superficie di attacco."
                ),
                "parameters": clean_params,
                "endpoint": target,
                "method": "GET",
                "recommendation": "Applicare allowlist dei parametri e validazione server-side.",
                "found_by": "Arjun – Active Testing",
                "tags": ["parameter-discovery", "input-validation"],
            }
        ]

    def _extract_params(self, payload: Any, target: str) -> List[Any]:
        if isinstance(payload, dict):
            target_candidates = self._build_target_candidates(target)
            for candidate in target_candidates:
                if isinstance(payload.get(candidate), list):
                    return payload[candidate]
            if isinstance(payload.get("params"), list):
                return payload["params"]

        if isinstance(payload, list):
            collected_params: List[Any] = []
            for entry in payload:
                if isinstance(entry, dict) and isinstance(entry.get("params"), list):
                    collected_params.extend(entry["params"])
            return collected_params

        return []

    def _build_target_candidates(self, target: str) -> List[str]:
        parsed = urlparse(target if "://" in target else f"http://{target}")
        candidates = [target]

        if parsed.scheme and parsed.netloc:
            normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path or ''}"
            candidates.extend([normalized, normalized.rstrip("/")])
            if not parsed.path:
                candidates.append(f"{parsed.scheme}://{parsed.netloc}/")
            candidates.append(parsed.netloc)
        elif parsed.path:
            candidates.append(parsed.path.rstrip("/"))

        unique_candidates: List[str] = []
        for candidate in candidates:
            cleaned = candidate.strip()
            if cleaned and cleaned not in unique_candidates:
                unique_candidates.append(cleaned)
        return unique_candidates
