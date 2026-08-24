"""OpenVAS / Greenbone (GVM) API scanner wrapper (optional).

Adapter opzionale verso un'installazione Greenbone/GVM esistente: legge i
risultati di vulnerabilità da un endpoint HTTP configurato e li normalizza nei
findings della piattaforma (con CVE/CVSS che confluiscono nell'enrichment).
Segue lo stesso contratto degli adapter enterprise Nessus/Acunetix: in assenza
di configurazione viene saltato senza errori; senza scansioni live mostra dati
simulati a scopo didattico.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import requests

from config import settings


# Mappa il "threat level" testuale di Greenbone alle severità della piattaforma.
THREAT_SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "log": "info",
    "info": "info",
    "false positive": "info",
}


def _severity_from_cvss(score: Optional[float]) -> str:
    if score is None:
        return "info"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "info"


@dataclass
class OpenVASScanner:
    enable_live_scans: bool = False

    def run(self, target: str) -> Dict[str, Any]:
        if not self.enable_live_scans:
            return {
                "tool": "openvas",
                "status": "simulated",
                "findings": [
                    {
                        "tool": "openvas",
                        "title": "OpenSSH obsoleto esposto — versione con vulnerabilità note (CVE-2023-38408)",
                        "severity": "high",
                        "description": (
                            "Greenbone/OpenVAS ha rilevato sulla porta TCP 22 un servizio "
                            "OpenSSH 8.9 non aggiornato. La versione identificata è soggetta a "
                            "CVE-2023-38408, una vulnerabilità nell'agent forwarding di ssh-agent "
                            "che, in presenza di specifiche librerie nel sistema remoto, può "
                            "portare a esecuzione di codice remoto. L'esposizione diretta del "
                            "servizio SSH su Internet aumenta la superficie di attacco."
                        ),
                        "impact": (
                            "Lo sfruttamento può consentire l'esecuzione di codice nel contesto "
                            "dell'utente che inoltra l'agent SSH, con potenziale movimento laterale "
                            "verso altri host raggiungibili dalle credenziali compromesse."
                        ),
                        "recommendation": (
                            "1. Aggiornare OpenSSH all'ultima versione stabile fornita dalla distribuzione.\n"
                            "2. Disabilitare l'agent forwarding dove non strettamente necessario "
                            "(ForwardAgent no).\n"
                            "3. Limitare l'accesso SSH tramite allowlist IP/bastion host e MFA.\n"
                            "4. Rieseguire la scansione di verifica dopo il patching."
                        ),
                        "evidence": "22/tcp open ssh OpenSSH 8.9p1 — NVT: CVE-2023-38408",
                        "affected_component": "Servizio SSH — porta TCP 22",
                        "host": "10.0.0.10",
                        "port": "22",
                        "cve": ["CVE-2023-38408"],
                        "cwe": ["CWE-94"],
                        "cvss_score": 7.3,
                        "tags": ["openvas", "network", "ssh", "outdated-component"],
                        "references": [
                            "https://nvd.nist.gov/vuln/detail/CVE-2023-38408",
                            "https://www.openssh.com/security.html",
                        ],
                    },
                    {
                        "tool": "openvas",
                        "title": "SMBv1 abilitato — protocollo legacy vulnerabile (EternalBlue, CVE-2017-0144)",
                        "severity": "critical",
                        "description": (
                            "Greenbone/OpenVAS ha rilevato che l'host espone il protocollo SMBv1 "
                            "sulla porta 445. SMBv1 è affetto dalla famiglia di vulnerabilità "
                            "EternalBlue (CVE-2017-0144) sfruttata da WannaCry e NotPetya, che "
                            "consente esecuzione di codice remoto non autenticato. Microsoft ha "
                            "deprecato SMBv1 e ne raccomanda la rimozione."
                        ),
                        "impact": (
                            "Un attaccante non autenticato sulla rete può ottenere esecuzione di "
                            "codice remoto con privilegi SYSTEM, compromettere l'host e propagarsi "
                            "automaticamente (worm) verso altri sistemi che espongono SMBv1."
                        ),
                        "recommendation": (
                            "1. Disabilitare completamente SMBv1 (su Windows: rimuovere la feature "
                            "'SMB 1.0/CIFS File Sharing Support').\n"
                            "2. Applicare le patch MS17-010 su tutti i sistemi interessati.\n"
                            "3. Bloccare la porta 445 al perimetro e segmentare la rete interna.\n"
                            "4. Migrare a SMBv2/SMBv3 con firma del pacchetto abilitata."
                        ),
                        "evidence": "445/tcp open microsoft-ds — SMBv1 supportato — NVT: MS17-010 / CVE-2017-0144",
                        "affected_component": "Servizio SMB — porta TCP 445",
                        "host": "10.0.0.20",
                        "port": "445",
                        "cve": ["CVE-2017-0144"],
                        "cwe": ["CWE-20"],
                        "cvss_score": 8.1,
                        "tags": ["openvas", "network", "smb", "eternalblue"],
                        "references": [
                            "https://nvd.nist.gov/vuln/detail/CVE-2017-0144",
                            "https://learn.microsoft.com/security-updates/securitybulletins/2017/ms17-010",
                        ],
                    },
                ],
            }

        if not settings.openvas_api_base_url or not settings.openvas_api_key:
            return {
                "tool": "openvas",
                "status": "skipped",
                "message": "API OpenVAS/Greenbone non configurata.",
                "findings": [],
            }

        try:
            findings = self._fetch_findings(target)
        except requests.RequestException as exc:
            return {
                "tool": "openvas",
                "status": "error",
                "message": f"Errore API OpenVAS/Greenbone: {exc}",
                "findings": [],
            }

        return {
            "tool": "openvas",
            "status": "executed",
            "findings": findings,
        }

    def _fetch_findings(self, target: str) -> List[Dict[str, Any]]:
        url = f"{settings.openvas_api_base_url.rstrip('/')}{settings.openvas_vulnerabilities_endpoint}"
        headers = {"X-API-KEY": settings.openvas_api_key}
        response = requests.get(
            url,
            headers=headers,
            params={"target": target},
            timeout=settings.openvas_timeout_seconds,
        )
        response.raise_for_status()
        payload = response.json()

        if isinstance(payload, dict):
            results = payload.get("results") or payload.get("vulnerabilities") or []
        elif isinstance(payload, list):
            results = payload
        else:
            results = []

        findings: List[Dict[str, Any]] = []
        for item in results:
            if not isinstance(item, dict):
                continue
            findings.append(self._normalize_result(item))
        return findings

    def _normalize_result(self, item: Dict[str, Any]) -> Dict[str, Any]:
        cvss_score = self._parse_cvss(item)
        threat = str(item.get("threat", "")).strip().lower()
        severity = THREAT_SEVERITY_MAP.get(threat) or _severity_from_cvss(cvss_score)

        cves = item.get("cve")
        if isinstance(cves, str):
            cves = [cves]
        elif not isinstance(cves, list):
            cves = []

        finding: Dict[str, Any] = {
            "title": item.get("name") or item.get("nvt_name") or "Vulnerabilità OpenVAS",
            "severity": severity,
            "description": item.get("description", ""),
            "recommendation": item.get("solution", ""),
            "host": item.get("host", ""),
            "port": item.get("port", ""),
            "cve": [str(cve) for cve in cves if cve],
            "tags": ["openvas", "network"],
        }
        if cvss_score is not None:
            finding["cvss_score"] = cvss_score
        return finding

    def _parse_cvss(self, item: Dict[str, Any]) -> Optional[float]:
        for key in ("cvss_score", "cvss", "severity", "cvss_base"):
            value = item.get(key)
            if value is None:
                continue
            try:
                return float(value)
            except (TypeError, ValueError):
                continue
        return None
