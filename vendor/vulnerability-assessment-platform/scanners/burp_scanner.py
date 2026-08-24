"""Burp Suite REST API scanner wrapper."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List

import requests

from config import settings


RISK_MAPPING = {
    "info": "info",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}


@dataclass
class BurpScanner:
    enable_live_scans: bool = False

    def run(self, target: str) -> Dict[str, Any]:
        if not self.enable_live_scans:
            return {
                "tool": "burp",
                "status": "simulated",
                "findings": [
                    {
                        "tool": "burp",
                        "title": "Path Traversal / Local File Inclusion — Lettura arbitraria di file di sistema",
                        "severity": "high",
                        "description": (
                            "Burp Suite ha identificato una vulnerabilità di Path Traversal "
                            "nel parametro 'file' dell'endpoint /download?file=report.pdf. "
                            "Il valore del parametro viene utilizzato direttamente per costruire "
                            "il percorso del file da restituire, senza validazione né "
                            "canonicalizzazione del path. Utilizzando sequenze di traversal "
                            "(../), è stato possibile leggere file arbitrari del filesystem "
                            "del server, inclusi /etc/passwd, file di configurazione con "
                            "credenziali e chiavi private SSH. Il test ha confermato la "
                            "lettura di /etc/passwd con successo HTTP 200."
                        ),
                        "impact": (
                            "Path Traversal con impatto critico: lettura di file di sistema "
                            "sensibili (/etc/shadow, /etc/passwd, chiavi SSH private in "
                            "/root/.ssh/id_rsa, file di configurazione applicativi con "
                            "credenziali database), potenziale escalation verso Local File "
                            "Inclusion (LFI) con esecuzione di codice tramite log poisoning "
                            "o /proc/self/environ injection. L'impatto varia da "
                            "information disclosure a Remote Code Execution."
                        ),
                        "attack_scenario": (
                            "1. L'attaccante identifica il parametro: GET /download?file=report.pdf\n"
                            "2. Testa traversal: GET /download?file=../../../../etc/passwd\n"
                            "3. Il server risponde con il contenuto di /etc/passwd.\n"
                            "4. Enumerazione avanzata: tenta /proc/self/environ per variabili d'ambiente.\n"
                            "5. Log poisoning: inietta PHP code nel log Apache via User-Agent.\n"
                            "6. LFI: GET /download?file=../../../../var/log/apache2/access.log\n"
                            "   → Il codice PHP nel log viene eseguito lato server (RCE)."
                        ),
                        "recommendation": (
                            "1. Non utilizzare mai input utente direttamente nella costruzione "
                            "di percorsi file. Usare una mapping table (ID → path reale):\n"
                            "   allowed_files = {'report': '/safe/dir/report.pdf'}\n"
                            "   path = allowed_files.get(request.args.get('file'))\n"
                            "2. Se l'input deve determinare un file, canonicalizzare il path e "
                            "verificare che sia all'interno della directory consentita:\n"
                            "   real_path = os.path.realpath(os.path.join(BASE_DIR, user_input))\n"
                            "   if not real_path.startswith(BASE_DIR): abort(403)\n"
                            "3. Limitare i permessi del processo web server al minimo (principio "
                            "del minimo privilegio).\n"
                            "4. Implementare un WAF con regole anti-path-traversal (OWASP CRS)."
                        ),
                        "evidence": "GET /download?file=../../../../etc/passwd → HTTP 200 OK\nroot:x:0:0:root:/root:/bin/bash",
                        "affected_component": "Endpoint /download — parametro GET 'file'",
                        "path": "/download",
                        "parameter": "file",
                        "cwe": ["CWE-22", "CWE-23"],
                        "cvss_score": 7.5,
                        "cvss_metrics": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        "tags": ["owasp-a01", "path-traversal", "lfi"],
                        "references": [
                            "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
                            "https://cwe.mitre.org/data/definitions/22.html",
                            "https://portswigger.net/web-security/file-path-traversal",
                            "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html",
                        ],
                    },
                    {
                        "tool": "burp",
                        "title": "Insecure Direct Object Reference (IDOR) — Accesso non autorizzato a risorse utente",
                        "severity": "high",
                        "description": (
                            "Burp Suite ha scoperto una vulnerabilità IDOR critica nell'endpoint "
                            "/api/v1/orders/{order_id}. Modificando il parametro 'order_id' "
                            "nel path URL, un utente autenticato può accedere agli ordini di "
                            "qualsiasi altro utente. Il server non verifica che l'order_id "
                            "richiesto appartenga all'utente correntemente autenticato. "
                            "Il test ha dimostrato che l'utente con ID 1337 può leggere "
                            "l'ordine #5001 appartenente all'utente con ID 9999, inclusi "
                            "indirizzo di consegna, metodo di pagamento e storico acquisti."
                        ),
                        "impact": (
                            "IDOR con impatto su riservatezza e integrità: un attaccante "
                            "autenticato può enumerare e accedere ai dati di tutti gli utenti "
                            "(ordini, profilo, storico pagamenti), modificare ordini altrui "
                            "se l'endpoint supporta metodi PUT/PATCH, e raccogliere dati "
                            "personali e finanziari di tutti i clienti. Rappresenta una "
                            "grave violazione del GDPR con potenziale obbligo di notifica."
                        ),
                        "attack_scenario": (
                            "1. Utente legittimo accede a: GET /api/v1/orders/1337 (suo ordine).\n"
                            "2. L'attaccante osserva il pattern dell'ID e incrementa il valore.\n"
                            "3. Invia: GET /api/v1/orders/1 → dati ordine di un altro utente.\n"
                            "4. Script automatizzato enumera: for i in range(1, 10000): GET /api/v1/orders/{i}\n"
                            "5. Raccoglie indirizzi, metodi di pagamento e storico acquisti "
                            "di tutti gli utenti del sistema."
                        ),
                        "recommendation": (
                            "1. Implementare controlli di autorizzazione espliciti su ogni "
                            "endpoint che accede a risorse utente:\n"
                            "   if order.user_id != current_user.id: abort(403)\n"
                            "2. Utilizzare UUID casuali non incrementali come identificatori "
                            "di risorse invece di ID sequenziali.\n"
                            "3. Implementare object-level authorization a livello di ORM/repository.\n"
                            "4. Eseguire test di autorizzazione sistematici (IDOR testing) "
                            "come parte dei processi di QA e security review.\n"
                            "5. Applicare il principio del minimo privilegio a livello di "
                            "query database: le query devono filtrare sempre per user_id."
                        ),
                        "evidence": "GET /api/v1/orders/9999 (autenticato come user_id=1337) → HTTP 200 OK (dati di un altro utente)",
                        "affected_component": "REST API — /api/v1/orders/{order_id}",
                        "path": "/api/v1/orders",
                        "cwe": ["CWE-639", "CWE-284"],
                        "cvss_score": 8.1,
                        "cvss_metrics": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                        "tags": ["owasp-a01", "idor", "broken-access-control"],
                        "references": [
                            "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
                            "https://cwe.mitre.org/data/definitions/639.html",
                            "https://portswigger.net/web-security/access-control/idor",
                        ],
                    },
                ],
            }

        if not settings.burp_api_base_url or not settings.burp_api_key:
            return {
                "tool": "burp",
                "status": "skipped",
                "message": "API Burp non configurata.",
                "findings": [],
            }

        try:
            scan_id = self._start_scan(target)
            findings = self._fetch_issues(scan_id)
        except requests.RequestException as exc:
            return {
                "tool": "burp",
                "status": "error",
                "message": f"Errore API Burp: {exc}",
                "findings": [],
            }

        return {
            "tool": "burp",
            "status": "executed",
            "findings": findings,
        }

    def _headers(self) -> Dict[str, str]:
        return {"Authorization": f"Bearer {settings.burp_api_key}"}

    def _start_scan(self, target: str) -> str:
        response = requests.post(
            f"{settings.burp_api_base_url.rstrip('/')}{settings.burp_api_scan_endpoint}",
            json={"urls": [target]},
            headers=self._headers(),
            timeout=settings.burp_timeout_seconds,
        )
        response.raise_for_status()
        payload = response.json()
        scan_id = payload.get("scan_id") or payload.get("id") or ""
        if not scan_id:
            raise requests.RequestException("Scan ID non restituito da Burp.")
        return str(scan_id)

    def _fetch_issues(self, scan_id: str) -> List[Dict[str, Any]]:
        url = f"{settings.burp_api_base_url.rstrip('/')}{settings.burp_api_issues_endpoint}"
        response = requests.get(
            url.format(scan_id=scan_id),
            headers=self._headers(),
            timeout=settings.burp_timeout_seconds,
        )
        response.raise_for_status()
        payload = response.json()
        issues = payload.get("issues", []) if isinstance(payload, dict) else []

        findings: List[Dict[str, Any]] = []
        for issue in issues:
            if not isinstance(issue, dict):
                continue
            severity = RISK_MAPPING.get(str(issue.get("severity", "")).lower(), "info")
            findings.append(
                {
                    "title": issue.get("name", "Issue Burp"),
                    "severity": severity,
                    "description": issue.get("description", ""),
                    "recommendation": issue.get("remediation", ""),
                    "host": issue.get("host", ""),
                    "path": issue.get("path", ""),
                    "cwe": [str(issue.get("cwe"))] if issue.get("cwe") else [],
                    "tags": ["burp"],
                }
            )
        return findings
