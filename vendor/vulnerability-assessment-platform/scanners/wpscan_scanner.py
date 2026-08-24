"""WPScan scanner wrapper."""
from __future__ import annotations

from dataclasses import dataclass
import json
import shutil
import subprocess
from tempfile import NamedTemporaryFile
from typing import Any, Dict, List

from config import settings


@dataclass
class WpscanScanner:
    enable_live_scans: bool = False

    def run(self, target: str) -> Dict[str, Any]:
        if not self.enable_live_scans:
            return {
                "tool": "wpscan",
                "status": "simulated",
                "findings": [
                    {
                        "tool": "wpscan",
                        "title": "WordPress 6.4.3 con plugin vulnerabile rilevato",
                        "severity": "high",
                        "description": (
                            "WPScan ha identificato WordPress 6.4.3 con il plugin "
                            "Contact Form 7 in versione vulnerabile."
                        ),
                        "impact": "Possibile compromissione dell'applicazione tramite exploit noti.",
                        "recommendation": (
                            "Aggiornare core WordPress, plugin e temi. "
                            "Limitare enumeration utenti e proteggere endpoint sensibili."
                        ),
                        "cve": ["CVE-2024-0001"],
                        "references": ["https://wpscan.com/wordpresses/"],
                        "found_by": "WPScan – Active Testing",
                    }
                ],
            }

        if not shutil.which("wpscan"):
            return {
                "tool": "wpscan",
                "status": "skipped",
                "message": "Tool wpscan non installato.",
                "findings": [],
            }

        with NamedTemporaryFile(mode="w+", suffix=".json") as output_file:
            command = [
                "wpscan",
                "--url",
                target,
                "--format",
                "json",
                "--output",
                output_file.name,
            ]
            if settings.wpscan_api_token:
                command.extend(["--api-token", settings.wpscan_api_token])
            if settings.wpscan_enumerate:
                command.extend(["--enumerate", settings.wpscan_enumerate])

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
                    "tool": "wpscan",
                    "status": "timeout",
                    "message": "Timeout durante l'esecuzione di WPScan.",
                    "findings": [],
                }

            payload = self._load_json_output(output_file.name)
            if payload is None:
                message = completed.stderr.strip() or "Impossibile interpretare l'output JSON di WPScan."
                return {
                    "tool": "wpscan",
                    "status": "error",
                    "message": message,
                    "findings": [],
                }

            findings = self._extract_findings(payload)
            return {
                "tool": "wpscan",
                "status": "executed" if completed.returncode == 0 else "completed_with_warnings",
                "target": target,
                "findings": findings[: settings.max_findings],
            }

    def _load_json_output(self, output_path: str) -> Dict[str, Any] | None:
        try:
            with open(output_path, "r", encoding="utf-8") as handle:
                raw = handle.read().strip()
        except OSError:
            return None

        if not raw:
            return None

        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return None

    def _extract_findings(self, payload: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []

        version = payload.get("version") if isinstance(payload.get("version"), dict) else {}
        version_number = version.get("number")
        if version_number:
            findings.append(
                {
                    "tool": "wpscan",
                    "title": f"WordPress {version_number} rilevato",
                    "severity": "info",
                    "description": f"Versione WordPress rilevata: {version_number}.",
                    "recommendation": "Verificare che la versione sia supportata e aggiornata.",
                    "found_by": "WPScan – Passive Detection",
                }
            )

        findings.extend(self._extract_component_findings(payload.get("plugins"), component="plugin"))
        findings.extend(self._extract_component_findings(payload.get("themes"), component="theme"))
        findings.extend(self._extract_core_vulnerability_findings(version))
        findings.extend(self._extract_interesting_findings(payload.get("interesting_findings")))
        findings.extend(self._extract_users_findings(payload.get("users")))

        return findings

    def _extract_core_vulnerability_findings(self, version: Dict[str, Any]) -> List[Dict[str, Any]]:
        if not isinstance(version, dict):
            return []

        vulnerabilities = version.get("vulnerabilities")
        if not isinstance(vulnerabilities, list) or not vulnerabilities:
            return []

        findings: List[Dict[str, Any]] = []
        version_number = str(version.get("number") or "non disponibile")
        for vuln in vulnerabilities:
            if not isinstance(vuln, dict):
                continue
            title = vuln.get("title") or "Vulnerabilità del core WordPress rilevata"
            references = vuln.get("references") if isinstance(vuln.get("references"), dict) else {}
            url_refs = references.get("url") if isinstance(references.get("url"), list) else []
            cves = vuln.get("cve") if isinstance(vuln.get("cve"), list) else []
            findings.append(
                {
                    "tool": "wpscan",
                    "title": "Core WordPress vulnerabile",
                    "severity": "high",
                    "description": f"{title}. Versione rilevata: {version_number}.",
                    "recommendation": "Aggiornare immediatamente WordPress core all'ultima versione stabile.",
                    "affected_component": "core:wordpress",
                    "cve": cves,
                    "references": url_refs,
                    "found_by": "WPScan – Active Testing",
                }
            )
        return findings

    def _extract_component_findings(self, components: Any, component: str) -> List[Dict[str, Any]]:
        if not isinstance(components, dict):
            return []

        findings: List[Dict[str, Any]] = []
        for name, details in components.items():
            if not isinstance(details, dict):
                continue
            version = ""
            version_data = details.get("version")
            if isinstance(version_data, dict):
                version = str(version_data.get("number") or "")

            vulnerabilities = details.get("vulnerabilities")
            if not isinstance(vulnerabilities, list) or not vulnerabilities:
                continue

            for vuln in vulnerabilities:
                if not isinstance(vuln, dict):
                    continue
                title = vuln.get("title") or f"{component.title()} vulnerabile rilevato"
                references = vuln.get("references") if isinstance(vuln.get("references"), dict) else {}
                url_refs = references.get("url") if isinstance(references.get("url"), list) else []
                cves = vuln.get("cve") if isinstance(vuln.get("cve"), list) else []

                findings.append(
                    {
                        "tool": "wpscan",
                        "title": f"{component.title()} vulnerabile: {name}",
                        "severity": "high",
                        "description": f"{title}. Versione rilevata: {version or 'non disponibile'}.",
                        "recommendation": f"Aggiornare o rimuovere il {component} {name}.",
                        "affected_component": f"{component}:{name}",
                        "cve": cves,
                        "references": url_refs,
                        "found_by": "WPScan – Active Testing",
                    }
                )

        return findings

    def _extract_interesting_findings(self, interesting_findings: Any) -> List[Dict[str, Any]]:
        if not isinstance(interesting_findings, list):
            return []

        findings: List[Dict[str, Any]] = []
        for finding in interesting_findings:
            if not isinstance(finding, dict):
                continue
            title = finding.get("to_s") or finding.get("type") or "Finding WordPress interessante"
            url = finding.get("url") or ""
            confidence = str(finding.get("confidence") or "unknown")
            findings.append(
                {
                    "tool": "wpscan",
                    "title": title,
                    "severity": "medium",
                    "description": f"WPScan ha rilevato un elemento interessante ({confidence}).",
                    "evidence_url": url,
                    "recommendation": "Verificare manualmente l'esposizione e applicare hardening.",
                    "found_by": "WPScan – Passive Detection",
                }
            )
        return findings

    def _extract_users_findings(self, users: Any) -> List[Dict[str, Any]]:
        if not isinstance(users, dict) or not users:
            return []

        usernames = [name for name in users.keys() if isinstance(name, str) and name.strip()]
        if not usernames:
            return []

        return [
            {
                "tool": "wpscan",
                "title": "User enumeration abilitata",
                "severity": "medium",
                "description": "WPScan ha enumerato utenti WordPress pubblicamente esposti.",
                "evidence": ", ".join(sorted(usernames)[:10]),
                "recommendation": "Disabilitare o limitare la user enumeration su endpoint pubblici.",
                "found_by": "WPScan – Passive Detection",
            }
        ]
