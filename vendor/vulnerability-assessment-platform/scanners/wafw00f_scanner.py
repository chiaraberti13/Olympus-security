"""wafw00f scanner wrapper."""
from __future__ import annotations

from dataclasses import dataclass
import json
import shutil
import subprocess
from tempfile import NamedTemporaryFile
from typing import Any, Dict, List

from config import settings


@dataclass
class Wafw00fScanner:
    enable_live_scans: bool = False
    _BYPASS_HINTS_MAP = {
        "cloudflare": [
            "Verificare endpoint origin esposti direttamente su IP o host alternativi.",
            "Applicare mTLS e ACL lato origin per impedire accessi diretti.",
        ],
        "sucuri": [
            "Confermare che DNS e CDN non espongano l'origin senza protezioni.",
            "Abilitare rate limiting e bot protection con policy conservative.",
        ],
        "akamai": [
            "Validare regole custom su path critici e API sensibili.",
            "Monitorare anomalie su header di forwarding e bypass cache.",
        ],
        "f5 big-ip asm": [
            "Rivedere signature tuning e staging mode per ridurre false negative.",
            "Bloccare payload noti OWASP Top 10 con policy enforce.",
        ],
        "aws waf": [
            "Applicare managed rules + regole custom per endpoint business-critical.",
            "Integrare logging su CloudWatch/SIEM con alert su pattern anomali.",
        ],
    }

    def run(self, target: str) -> Dict[str, Any]:
        if not self.enable_live_scans:
            return {
                "tool": "wafw00f",
                "status": "simulated",
                "findings": [
                    {
                        "tool": "wafw00f",
                        "title": "WAF rilevato in front-end",
                        "severity": "info",
                        "description": "wafw00f ha identificato un Web Application Firewall davanti al target.",
                        "recommendation": (
                            "Verificare la configurazione del WAF, regole custom e modalità di blocco."
                        ),
                        "found_by": "wafw00f – Passive Detection",
                    }
                ],
            }

        if not shutil.which("wafw00f"):
            return {
                "tool": "wafw00f",
                "status": "skipped",
                "message": "Tool wafw00f non installato.",
                "findings": [],
            }

        with NamedTemporaryFile(mode="w+", suffix=".json") as output_file:
            command = ["wafw00f", target, "-f", "json", "-o", output_file.name]
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
                    "tool": "wafw00f",
                    "status": "timeout",
                    "message": "Timeout durante l'esecuzione di wafw00f.",
                    "findings": [],
                }

            payload = self._load_json_output(output_file.name)
            findings = self._extract_findings(payload)
            return {
                "tool": "wafw00f",
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

    def _extract_findings(self, payload: Any) -> List[Dict[str, Any]]:
        if not isinstance(payload, dict):
            return []
        detections = payload.get("detected_wafs")
        if not isinstance(detections, list):
            detections = []
        findings: List[Dict[str, Any]] = []
        for waf_name in detections:
            if not isinstance(waf_name, str) or not waf_name.strip():
                continue
            bypass_hints = self._build_bypass_hints(waf_name)
            findings.append(
                {
                    "tool": "wafw00f",
                    "title": f"WAF rilevato: {waf_name}",
                    "severity": "info",
                    "description": f"Fingerprint del WAF identificato: {waf_name}.",
                    "recommendation": "Convalidare le regole di protezione e monitorare possibili bypass.",
                    "found_by": "wafw00f – Passive Detection",
                    "tags": ["waf", "fingerprinting"],
                    "bypass_hints": bypass_hints,
                }
            )
        return findings

    def _build_bypass_hints(self, waf_name: str) -> List[str]:
        normalized_name = waf_name.lower().strip()
        matched_hints: List[str] = []
        for fingerprint, hints in self._BYPASS_HINTS_MAP.items():
            if fingerprint in normalized_name:
                matched_hints.extend(hints)
        if matched_hints:
            return matched_hints
        return [
            "Eseguire test di evasione controllati su payload encoding/obfuscation.",
            "Verificare che l'origin non sia raggiungibile bypassando il layer WAF.",
        ]
