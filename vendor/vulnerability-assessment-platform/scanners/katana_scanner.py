"""Katana scanner wrapper."""
from __future__ import annotations

from dataclasses import dataclass
import json
import shutil
import subprocess
from typing import Any, Dict, List

from config import settings


@dataclass
class KatanaScanner:
    enable_live_scans: bool = False

    def run(self, target: str) -> Dict[str, Any]:
        if not self.enable_live_scans:
            return {
                "tool": "katana",
                "status": "simulated",
                "findings": [
                    {
                        "tool": "katana",
                        "title": "Endpoint discovery completata",
                        "severity": "info",
                        "description": "Katana ha identificato endpoint aggiuntivi da includere nella superficie d'attacco.",
                        "recommendation": "Verificare autorizzazioni e hardening sugli endpoint scoperti.",
                        "found_by": "Katana – Active Testing",
                    }
                ],
                "urls_spidered": 3,
            }

        if not shutil.which("katana"):
            return {
                "tool": "katana",
                "status": "skipped",
                "message": "Tool katana non installato.",
                "findings": [],
            }

        command = ["katana", "-u", target, "-json"]
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
                "tool": "katana",
                "status": "timeout",
                "message": "Timeout durante l'esecuzione di Katana.",
                "findings": [],
            }

        payload = self._parse_json_lines(completed.stdout)
        findings = self._extract_findings(payload)
        unique_spidered_urls = {
            endpoint
            for row in payload
            if isinstance(row, dict)
            for endpoint in [str((row.get("request") or {}).get("endpoint") or "").strip()]
            if endpoint
        }

        return {
            "tool": "katana",
            "status": "executed" if completed.returncode == 0 else "completed_with_warnings",
            "findings": findings[: settings.max_findings],
            "urls_spidered": len(unique_spidered_urls),
        }

    def _parse_json_lines(self, raw: str) -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                parsed = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(parsed, dict):
                rows.append(parsed)
        return rows

    def _extract_findings(self, payload: Any) -> List[Dict[str, Any]]:
        if not isinstance(payload, list):
            return []
        endpoints: List[str] = []
        for row in payload:
            if not isinstance(row, dict):
                continue
            request = row.get("request") if isinstance(row.get("request"), dict) else {}
            endpoint = str(request.get("endpoint") or "").strip()
            if endpoint:
                endpoints.append(endpoint)

        unique_endpoints = sorted(set(endpoints))
        if not unique_endpoints:
            return []

        return [
            {
                "tool": "katana",
                "title": "Nuovi endpoint individuati dal crawler",
                "severity": "info",
                "description": f"Katana ha scoperto {len(unique_endpoints)} endpoint unici.",
                "evidence": ", ".join(unique_endpoints[:10]),
                "recommendation": "Includere gli endpoint nel threat modeling e nei test di sicurezza.",
                "found_by": "Katana – Active Testing",
                "tags": ["crawler", "attack-surface"],
            }
        ]
