"""theHarvester scanner wrapper."""
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
class TheHarvesterScanner:
    enable_live_scans: bool = False

    def run(self, target: str) -> Dict[str, Any]:
        if not self.enable_live_scans:
            return {
                "tool": "theharvester",
                "status": "simulated",
                "findings": [
                    {
                        "tool": "theharvester",
                        "title": "Asset OSINT pubblici rilevati",
                        "severity": "low",
                        "description": (
                            "theHarvester ha individuato email e subdomain esposti da fonti pubbliche."
                        ),
                        "recommendation": "Ridurre esposizione dati sensibili nei registri pubblici.",
                        "found_by": "theHarvester – Passive Detection",
                    }
                ],
            }

        if not shutil.which("theHarvester"):
            return {
                "tool": "theharvester",
                "status": "skipped",
                "message": "Tool theHarvester non installato.",
                "findings": [],
            }

        domain = self._extract_domain(target)
        if not domain:
            return {
                "tool": "theharvester",
                "status": "error",
                "message": "Impossibile estrarre il dominio dal target per theHarvester.",
                "findings": [],
            }

        with NamedTemporaryFile(mode="w+", suffix=".json") as output_file:
            command = ["theHarvester", "-d", domain, "-b", "all", "-f", output_file.name]
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
                    "tool": "theharvester",
                    "status": "timeout",
                    "message": "Timeout durante l'esecuzione di theHarvester.",
                    "findings": [],
                }

            payload = self._load_json_output(output_file.name)
            findings = self._extract_findings(payload)
            return {
                "tool": "theharvester",
                "status": "executed" if completed.returncode == 0 else "completed_with_warnings",
                "findings": findings[: settings.max_findings],
            }

    def _extract_domain(self, target: str) -> str:
        parsed = urlparse(target if "://" in target else f"https://{target}")
        return (parsed.hostname or "").strip()

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

    def _extract_findings(self, payload: Any) -> List[Dict[str, Any]]:
        if not isinstance(payload, dict):
            return []
        emails = payload.get("emails") if isinstance(payload.get("emails"), list) else []
        hosts = payload.get("hosts") if isinstance(payload.get("hosts"), list) else []
        ips = payload.get("ips") if isinstance(payload.get("ips"), list) else []
        if not (emails or hosts or ips):
            return []

        return [
            {
                "tool": "theharvester",
                "title": "Dati OSINT esposti",
                "severity": "low",
                "description": (
                    f"Rilevati {len(emails)} email, {len(hosts)} host/subdomain e {len(ips)} IP da fonti pubbliche."
                ),
                "evidence": ", ".join([*emails[:5], *hosts[:5], *ips[:5]]),
                "recommendation": "Ridurre footprint OSINT e monitorare leak di asset digitali.",
                "found_by": "theHarvester – Passive Detection",
                "tags": ["osint", "asset-discovery"],
            }
        ]
