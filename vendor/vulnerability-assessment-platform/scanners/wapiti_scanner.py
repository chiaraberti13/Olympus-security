"""Wapiti scanner wrapper."""
from __future__ import annotations

from dataclasses import dataclass
import json
import shutil
import subprocess
import tempfile
from typing import Any, Dict, List

from config import settings


@dataclass
class WapitiScanner:
    enable_live_scans: bool = False

    def run(self, target: str) -> Dict[str, Any]:
        if not self.enable_live_scans:
            return {
                "tool": "wapiti",
                "status": "simulated",
                "findings": [
                    {
                        "tool": "wapiti",
                        "title": "Stack Trace completo esposto nelle risposte di errore — Information Disclosure critica",
                        "severity": "medium",
                        "description": (
                            "Wapiti ha rilevato che l'applicazione espone stack trace completi "
                            "nelle risposte HTTP di errore (status 500). Il traceback Python "
                            "visibile nella risposta rivela: percorsi assoluti del filesystem "
                            "(/var/www/app/modules/database/connector.py), nomi di tabelle e "
                            "query SQL interne, versioni delle librerie in uso (SQLAlchemy 1.4.0, "
                            "Flask 2.0.1), variabili locali dei frame dello stack e logica "
                            "interna dell'applicazione. Questa configurazione è tipica di "
                            "ambienti di sviluppo con DEBUG=True accidentalmente in produzione."
                        ),
                        "impact": (
                            "Le informazioni nei stack trace forniscono a un attaccante una "
                            "mappa dettagliata dell'architettura interna dell'applicazione, "
                            "facilitando significativamente la pianificazione di attacchi "
                            "più sofisticati. I path del filesystem abilitano attacchi "
                            "path traversal mirati; i nomi delle tabelle facilitano SQL "
                            "injection; le versioni delle librerie permettono la ricerca "
                            "di vulnerabilità specifiche."
                        ),
                        "attack_scenario": (
                            "1. Wapiti invia parametri non validi all'endpoint /api/v1/report?format=xxx.\n"
                            "2. Il server risponde con HTTP 500 e stack trace completo:\n"
                            "   File '/var/www/app/modules/report.py', line 45\n"
                            "   query = 'SELECT * FROM reports WHERE format=' + format\n"
                            "3. L'attaccante vede la query SQL concatenata → punta SQL injection.\n"
                            "4. Testa: /api/v1/report?format=' OR '1'='1\n"
                            "5. Ottiene dump completo della tabella reports."
                        ),
                        "recommendation": (
                            "1. Impostare DEBUG=False in tutti gli ambienti di produzione.\n"
                            "2. Configurare handler di errore personalizzati che restituiscano "
                            "messaggi generici agli utenti:\n"
                            "   Flask: @app.errorhandler(500) → return 'Internal Server Error', 500\n"
                            "3. Redirezionare i log dettagliati degli errori solo verso file "
                            "di log interni e sistemi di monitoring (Sentry, ELK).\n"
                            "4. Impostare una variabile d'ambiente FLASK_ENV=production o "
                            "DJANGO_SETTINGS_MODULE=settings.production.\n"
                            "5. Eseguire audit della configurazione prima di ogni deploy in produzione."
                        ),
                        "evidence": "GET /api/v1/report?format=invalid → HTTP 500\nTraceback (most recent call last):\n  File '/var/www/app/modules/report.py', line 45...",
                        "affected_component": "Error Handler — tutti gli endpoint dell'applicazione",
                        "cwe": ["CWE-209", "CWE-497"],
                        "cvss_score": 5.3,
                        "tags": ["owasp-a05", "information-disclosure", "debug-mode"],
                        "references": [
                            "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
                            "https://cwe.mitre.org/data/definitions/209.html",
                        ],
                    },
                    {
                        "tool": "wapiti",
                        "title": "Open Redirect — Reindirizzamento verso URL esterno non controllato",
                        "severity": "medium",
                        "description": (
                            "Wapiti ha identificato una vulnerabilità Open Redirect nel "
                            "parametro 'next' dell'endpoint /auth/login?next=. "
                            "Dopo un'autenticazione riuscita, il server esegue un redirect "
                            "verso il valore del parametro 'next' senza validare che l'URL "
                            "sia interno all'applicazione. È possibile impostare 'next' su "
                            "qualsiasi URL esterno, reindirizzando l'utente verso siti malevoli "
                            "dopo il login. Questo pattern è ampiamente utilizzato in campagne "
                            "di phishing poiché l'URL iniziale appare legittimo."
                        ),
                        "impact": (
                            "Open Redirect facilita attacchi di phishing altamente credibili: "
                            "l'utente vede inizialmente un URL legittimo del sito reale "
                            "(https://target.com/auth/login?next=https://evil.com/fake-login), "
                            "effettua il login correttamente e viene poi reindirizzato verso "
                            "una pagina di phishing identica al sito reale. Può essere usato "
                            "anche in combinazione con OAuth per hijack di token di accesso "
                            "(OAuth redirect_uri manipulation)."
                        ),
                        "attack_scenario": (
                            "1. L'attaccante crea il link malevolo:\n"
                            "   https://target.com/auth/login?next=https://evil-phishing.com/fake-dashboard\n"
                            "2. Invia il link tramite email di phishing ('Aggiorna le tue credenziali').\n"
                            "3. La vittima vede target.com nell'URL → si fida e inserisce le credenziali.\n"
                            "4. Dopo il login reale, viene reindirizzata su evil-phishing.com.\n"
                            "5. La pagina fake chiede nuovamente le credenziali ('Sessione scaduta').\n"
                            "6. Le credenziali vengono catturate dall'attaccante."
                        ),
                        "recommendation": (
                            "1. Validare che il valore di 'next' sia un percorso relativo interno:\n"
                            "   from urllib.parse import urlparse\n"
                            "   parsed = urlparse(next_url)\n"
                            "   if parsed.netloc or parsed.scheme: abort(400)\n"
                            "2. Usare una whitelist di URL interni ammessi per il redirect.\n"
                            "3. Se il redirect esterno è necessario, mostrare una pagina "
                            "di conferma intermedia che avvisa l'utente.\n"
                            "4. Non fidarsi mai di parametri di redirect che vengono da input utente "
                            "senza validazione server-side."
                        ),
                        "evidence": "GET /auth/login?next=https://evil.com → Dopo login: 302 Location: https://evil.com",
                        "affected_component": "Autenticazione — /auth/login?next= redirect parameter",
                        "path": "/auth/login",
                        "parameter": "next",
                        "cwe": ["CWE-601"],
                        "cvss_score": 6.1,
                        "tags": ["owasp-a01", "open-redirect", "phishing"],
                        "references": [
                            "https://cwe.mitre.org/data/definitions/601.html",
                            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/04-Testing_for_Client-side_URL_Redirect",
                        ],
                    },
                ],
            }

        if not shutil.which(settings.wapiti_path):
            return {
                "tool": "wapiti",
                "status": "skipped",
                "message": "Tool Wapiti non installato.",
                "findings": [],
            }

        with tempfile.TemporaryDirectory() as tmp_dir:
            output_path = f"{tmp_dir}/wapiti.json"
            command = [
                settings.wapiti_path,
                "-u",
                target,
                "-f",
                "json",
                "-o",
                output_path,
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
                    "tool": "wapiti",
                    "status": "error",
                    "message": "Timeout durante l'esecuzione di Wapiti.",
                    "findings": [],
                }

            if completed.returncode != 0:
                message = completed.stderr.strip() if completed.stderr else "Errore durante Wapiti."
                return {
                    "tool": "wapiti",
                    "status": "error",
                    "message": message,
                    "findings": [],
                }

            try:
                with open(output_path, "r", encoding="utf-8") as handle:
                    payload = json.load(handle)
            except (OSError, json.JSONDecodeError):
                return {
                    "tool": "wapiti",
                    "status": "error",
                    "message": "Output Wapiti non valido.",
                    "findings": [],
                }

        findings: List[Dict[str, Any]] = []
        vulnerabilities = payload.get("vulnerabilities", {}) if isinstance(payload, dict) else {}
        for vuln_type, items in vulnerabilities.items():
            if not isinstance(items, list):
                continue
            for item in items:
                if not isinstance(item, dict):
                    continue
                findings.append(
                    {
                        "title": f"{vuln_type.title()} rilevata da Wapiti",
                        "severity": "medium",
                        "description": item.get("info", ""),
                        "recommendation": "Mitigare la vulnerabilità seguendo le best practice.",
                        "host": item.get("host", ""),
                        "path": item.get("path", ""),
                        "parameter": item.get("parameter", ""),
                        "tags": ["wapiti", vuln_type],
                    }
                )
        return {
            "tool": "wapiti",
            "status": "executed",
            "findings": findings,
        }
