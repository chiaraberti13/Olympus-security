"""DalFox scanner wrapper."""
from __future__ import annotations

from dataclasses import dataclass
import json
import shutil
import subprocess
from tempfile import NamedTemporaryFile
from typing import Any, Dict, List, Set, Tuple

from config import settings


@dataclass
class DalfoxScanner:
    enable_live_scans: bool = False

    def run(self, target: str) -> Dict[str, Any]:
        if not self.enable_live_scans:
            return {
                "tool": "dalfox",
                "status": "simulated",
                "findings": [
                    {
                        "tool": "dalfox",
                        "title": "Possibile vulnerabilità XSS identificata",
                        "severity": "high",
                        "description": "DalFox ha rilevato vettori XSS potenzialmente sfruttabili.",
                        "recommendation": "Applicare escaping contestuale e Content Security Policy robusta.",
                        "found_by": "DalFox – Active Testing",
                    }
                ],
            }

        if not shutil.which("dalfox"):
            return {
                "tool": "dalfox",
                "status": "skipped",
                "message": "Tool DalFox non installato.",
                "findings": [],
            }

        with NamedTemporaryFile(mode="w+", suffix=".json") as output_file:
            command = [
                "dalfox",
                "url",
                target,
                "--format",
                "json",
                "--output",
                output_file.name,
                "--silence",
            ]
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
                    "tool": "dalfox",
                    "status": "timeout",
                    "message": "Timeout durante l'esecuzione di DalFox.",
                    "findings": [],
                }

            payload = self._load_json_output(output_file.name)
            findings = self._extract_findings(payload)
            return {
                "tool": "dalfox",
                "status": "executed" if completed.returncode == 0 else "completed_with_warnings",
                "findings": findings[: settings.max_findings],
            }

    def _load_json_output(self, output_path: str) -> Any:
        try:
            with open(output_path, "r", encoding="utf-8") as handle:
                raw = handle.read().strip()
        except OSError:
            return []
        if not raw:
            return []
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return []

    def _extract_findings(self, payload: Any) -> List[Dict[str, Any]]:
        if isinstance(payload, dict):
            payload = [payload]
        if not isinstance(payload, list):
            return []

        findings: List[Dict[str, Any]] = []
        seen_findings: Set[Tuple[str, str, str]] = set()
        for row in payload:
            if not isinstance(row, dict):
                continue
            evidence = str(row.get("evidence") or row.get("payload") or "").strip()
            if not evidence:
                continue
            param = str(row.get("param") or row.get("parameter") or "").strip()
            method = str(row.get("method") or "GET").strip().upper()
            finding_type = str(row.get("type") or row.get("vtype") or "").strip().lower()
            severity = self._map_severity(finding_type)
            title = self._build_title(finding_type, param)
            fingerprint = (param, method, evidence)
            if fingerprint in seen_findings:
                continue
            seen_findings.add(fingerprint)
            findings.append(
                {
                    "tool": "dalfox",
                    "title": title,
                    "severity": severity,
                    "description": "DalFox ha identificato un vettore XSS su input non sanitizzato.",
                    "evidence": evidence,
                    "method": method,
                    "parameters": [param] if param else [],
                    "recommendation": "Validare input, applicare escaping output e CSP strict.",
                    "found_by": "DalFox – Active Testing",
                    "tags": ["xss", "injection", finding_type or "generic-xss"],
                }
            )
        return findings

    def _map_severity(self, finding_type: str) -> str:
        if "dom" in finding_type:
            return "medium"
        if "verified" in finding_type or "stored" in finding_type:
            return "high"
        return "high"

    def _build_title(self, finding_type: str, param: str) -> str:
        if "dom" in finding_type:
            label = "DOM-based XSS"
        elif "stored" in finding_type:
            label = "Stored XSS"
        else:
            label = "Reflected XSS"
        if param:
            return f"{label} rilevato sul parametro '{param}'"
        return f"{label} rilevato"
