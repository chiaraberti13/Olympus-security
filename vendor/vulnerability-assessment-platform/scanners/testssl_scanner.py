"""testssl.sh scanner wrapper."""
from __future__ import annotations

from dataclasses import dataclass
import json
import shutil
import subprocess
from tempfile import NamedTemporaryFile
from typing import Any, ClassVar, Dict, List

from config import settings


@dataclass
class TestsslScanner:
    __test__ = False
    enable_live_scans: bool = False
    _ID_RULES: ClassVar[Dict[str, Dict[str, str]]] = {
        "ssl": {
            "title": "Protocollo SSL obsoleto abilitato",
            "severity": "high",
            "recommendation": "Disabilitare SSLv2/SSLv3 e mantenere solo TLS moderni (>= TLS 1.2).",
        },
        "tlsv1": {
            "title": "Protocollo TLS legacy abilitato",
            "severity": "medium",
            "recommendation": "Disabilitare TLS 1.0/1.1 e forzare TLS 1.2/1.3.",
        },
        "cipher": {
            "title": "Cipher suite debole rilevata",
            "severity": "high",
            "recommendation": "Rimuovere cipher deboli (EXPORT, DES/3DES, RC4, NULL, aNULL).",
        },
        "cert_expired": {
            "title": "Certificato TLS scaduto",
            "severity": "high",
            "recommendation": "Rinnovare immediatamente il certificato con una CA affidabile.",
        },
        "cert_selfsigned": {
            "title": "Certificato self-signed in uso",
            "severity": "medium",
            "recommendation": "Sostituire con certificato firmato da una CA attendibile.",
        },
        "hsts": {
            "title": "HSTS assente o non sicuro",
            "severity": "medium",
            "recommendation": "Abilitare HSTS con max-age adeguato e includeSubDomains/preload se applicabile.",
        },
    }

    def run(self, target: str) -> Dict[str, Any]:
        if not self.enable_live_scans:
            return {
                "tool": "testssl",
                "status": "simulated",
                "findings": [
                    {
                        "tool": "testssl",
                        "title": "Configurazione TLS da verificare",
                        "severity": "medium",
                        "description": (
                            "testssl.sh ha rilevato impostazioni TLS potenzialmente deboli sul target."
                        ),
                        "recommendation": "Disabilitare protocolli obsoleti e abilitare cipher suite robuste.",
                        "found_by": "testssl.sh – Active Testing",
                    }
                ],
            }

        binary = shutil.which("testssl.sh") or shutil.which("testssl")
        if not binary:
            return {
                "tool": "testssl",
                "status": "skipped",
                "message": "Tool testssl.sh non installato.",
                "findings": [],
            }

        with NamedTemporaryFile(mode="w+", suffix=".json") as output_file:
            command = [binary, "--jsonfile", output_file.name, target]
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
                    "tool": "testssl",
                    "status": "timeout",
                    "message": "Timeout durante l'esecuzione di testssl.sh.",
                    "findings": [],
                }

            payload = self._load_json_output(output_file.name)
            findings = self._extract_findings(payload)
            return {
                "tool": "testssl",
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
        if not isinstance(payload, list):
            return []
        findings: List[Dict[str, Any]] = []
        for row in payload:
            if not isinstance(row, dict):
                continue
            severity = str(row.get("severity", "")).lower()
            if severity not in {"critical", "high", "medium", "low"}:
                continue
            finding_text = str(row.get("finding") or "Misconfiguration TLS rilevata")
            finding_id = str(row.get("id") or "")
            rule = self._match_rule(finding_id, finding_text)
            mapped_severity = rule.get("severity", severity)
            findings.append(
                {
                    "tool": "testssl",
                    "title": rule.get("title", f"TLS issue: {finding_id or 'generic'}"),
                    "severity": "high" if mapped_severity == "critical" else mapped_severity,
                    "description": finding_text,
                    "recommendation": rule.get(
                        "recommendation", "Applicare hardening TLS secondo OWASP TLS Cheat Sheet."
                    ),
                    "found_by": "testssl.sh – Active Testing",
                    "tags": ["tls", "ssl", "crypto"],
                }
            )
        return findings

    def _match_rule(self, finding_id: str, finding_text: str) -> Dict[str, str]:
        normalized_id = finding_id.lower()
        normalized_text = finding_text.lower()
        for pattern, rule in self._ID_RULES.items():
            if pattern in normalized_id or pattern in normalized_text:
                return rule
        return {}
