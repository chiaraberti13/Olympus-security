"""Acunetix API scanner wrapper (optional)."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List

import requests

from config import settings


SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
}


@dataclass
class AcunetixScanner:
    enable_live_scans: bool = False

    def run(self, target: str) -> Dict[str, Any]:
        if not self.enable_live_scans:
            return {
                "tool": "acunetix",
                "status": "simulated",
                "findings": [
                    {
                        "tool": "acunetix",
                        "title": "Componente JavaScript vulnerabile — jQuery 1.12.4 (CVE-2020-11022, CVE-2020-11023)",
                        "severity": "medium",
                        "description": (
                            "Acunetix ha rilevato l'utilizzo di jQuery versione 1.12.4 nel "
                            "front-end dell'applicazione. Questa versione è affetta da due "
                            "vulnerabilità XSS documentate: CVE-2020-11022 e CVE-2020-11023. "
                            "Entrambe le CVE riguardano il metodo jQuery.htmlPrefilter() che "
                            "non gestisce correttamente determinati pattern HTML, permettendo "
                            "a un attaccante di iniettare HTML/JavaScript arbitrario quando "
                            "l'applicazione usa i metodi vulnerabili (.html(), .append(), "
                            ".prepend(), .before(), .after(), ecc.) con input non fidati. "
                            "La versione 1.12.x ha raggiunto End-of-Life nel 2021."
                        ),
                        "impact": (
                            "Le CVE permettono XSS stored o riflesso nelle applicazioni che "
                            "utilizzano le API jQuery vulnerabili con input utente. Con jQuery "
                            "1.12.x EOL, l'applicazione non riceverà future patch di sicurezza, "
                            "accumulando debt di sicurezza progressivo. L'XSS da componente "
                            "vulnerabile può portare a session hijacking, data exfiltration "
                            "e account takeover per gli utenti dell'applicazione."
                        ),
                        "attack_scenario": (
                            "1. L'applicazione usa: $('#container').html(userInput)\n"
                            "2. Con jQuery 1.12.4, htmlPrefilter non blocca: <img src=x onerror=alert(1)>\n"
                            "3. L'attaccante inserisce il payload XSS in un campo utente (profilo, commento).\n"
                            "4. Quando altri utenti visitano la pagina, il JS malevolo viene eseguito.\n"
                            "5. Stolen session tokens vengono inviati al server dell'attaccante."
                        ),
                        "recommendation": (
                            "1. Aggiornare jQuery all'ultima versione stabile (≥3.7.x) "
                            "che risolve entrambe le CVE.\n"
                            "2. In alternativa, considerare la migrazione a framework moderni "
                            "che non dipendono da jQuery (React, Vue, vanilla JS ES2020+).\n"
                            "3. Eseguire un audit di tutte le dipendenze JavaScript con strumenti "
                            "come npm audit, OWASP Dependency-Check o Snyk.\n"
                            "4. Implementare una policy di aggiornamento automatico delle "
                            "dipendenze con Dependabot o Renovate.\n"
                            "5. Evitare l'uso di .html() con dati non fidati indipendentemente "
                            "dalla versione di jQuery; preferire .text() per contenuto testuale."
                        ),
                        "evidence": "<script src='/static/js/jquery-1.12.4.min.js'></script>",
                        "affected_component": "jQuery 1.12.4 (EOL) — front-end JavaScript",
                        "cve": ["CVE-2020-11022", "CVE-2020-11023"],
                        "cwe": ["CWE-79", "CWE-1104"],
                        "cvss_score": 6.9,
                        "tags": ["owasp-a06", "vulnerable-component", "javascript", "jquery"],
                        "references": [
                            "https://nvd.nist.gov/vuln/detail/CVE-2020-11022",
                            "https://nvd.nist.gov/vuln/detail/CVE-2020-11023",
                            "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
                            "https://blog.jquery.com/2020/04/10/jquery-3-5-0-released/",
                        ],
                    },
                    {
                        "tool": "acunetix",
                        "title": "Server-Side Template Injection (SSTI) — esecuzione di codice via template engine",
                        "severity": "critical",
                        "description": (
                            "Acunetix ha identificato una vulnerabilità di Server-Side Template "
                            "Injection nel campo 'name' del modulo di personalizzazione email. "
                            "L'input utente viene passato direttamente al motore di template "
                            "(Jinja2) senza essere preventivamente sanitizzato o trattato come "
                            "dati puri. L'iniezione di espressioni template ({{7*7}}) restituisce "
                            "'49' nella risposta, confermando l'esecuzione server-side. "
                            "Con template engine Jinja2, SSTI può essere escalato ad RCE "
                            "completo tramite accesso alla classe object e ai metodi Python."
                        ),
                        "impact": (
                            "SSTI su Jinja2 porta direttamente a Remote Code Execution: "
                            "l'attaccante può eseguire comandi arbitrari sul sistema, "
                            "leggere file sensibili, estrarre environment variables "
                            "(chiavi AWS, JWT secrets, credenziali DB), modificare file "
                            "di sistema e installare backdoor persistenti. "
                            "La CVSS score è tipicamente 9.8-10.0 per SSTI con RCE."
                        ),
                        "attack_scenario": (
                            "1. Test iniziale: {name}={{7*7}} → risposta include '49' → SSTI confermato.\n"
                            "2. Esplorazione: {{config}} → rivela SECRET_KEY e SQLALCHEMY_DATABASE_URI.\n"
                            "3. RCE tramite Python object traversal:\n"
                            "   {{''.__class__.__mro__[1].__subclasses__()[408]('id',shell=True,stdout=-1).communicate()}}\n"
                            "4. Output: uid=33(www-data) gid=33(www-data)\n"
                            "5. Reverse shell: ls /etc/cron.d/ → aggiunge cron job backdoor."
                        ),
                        "recommendation": (
                            "1. Non passare MAI input utente direttamente al motore template. "
                            "Usare esclusivamente variabili con rendering sicuro:\n"
                            "   # SBAGLIATO: Template(user_input).render()\n"
                            "   # CORRETTO: render_template('page.html', name=user_input)\n"
                            "2. In Jinja2, abilitare il sandboxing: usare SandboxedEnvironment "
                            "invece di Environment.\n"
                            "3. Validare e sanitizzare tutti gli input con una whitelist "
                            "di caratteri ammessi (regex: [a-zA-Z0-9 ,-._]).\n"
                            "4. Eseguire SAST con Semgrep o Bandit per rilevare template "
                            "injection in fase di sviluppo.\n"
                            "5. Separare il rendering template dal codice applicativo tramite "
                            "architettura a livelli rigorosa."
                        ),
                        "evidence": "POST /email/personalize — name={{7*7}} → risposta: 'Ciao 49, benvenuto!'",
                        "affected_component": "Email Template Engine — Jinja2, campo 'name'",
                        "path": "/email/personalize",
                        "parameter": "name",
                        "cwe": ["CWE-1336", "CWE-94"],
                        "cvss_score": 9.8,
                        "cvss_metrics": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        "tags": ["owasp-a03", "ssti", "rce", "injection"],
                        "references": [
                            "https://owasp.org/Top10/A03_2021-Injection/",
                            "https://cwe.mitre.org/data/definitions/1336.html",
                            "https://portswigger.net/web-security/server-side-template-injection",
                        ],
                    },
                ],
            }

        if not settings.acunetix_api_base_url or not settings.acunetix_api_key:
            return {
                "tool": "acunetix",
                "status": "skipped",
                "message": "API Acunetix non configurata.",
                "findings": [],
            }

        try:
            findings = self._fetch_findings(target)
        except requests.RequestException as exc:
            return {
                "tool": "acunetix",
                "status": "error",
                "message": f"Errore API Acunetix: {exc}",
                "findings": [],
            }

        return {
            "tool": "acunetix",
            "status": "executed",
            "findings": findings,
        }

    def _fetch_findings(self, target: str) -> List[Dict[str, Any]]:
        url = f"{settings.acunetix_api_base_url.rstrip('/')}{settings.acunetix_vulnerabilities_endpoint}"
        headers = {"X-Auth": settings.acunetix_api_key}
        response = requests.get(
            url,
            headers=headers,
            params={"q": target},
            timeout=settings.acunetix_timeout_seconds,
        )
        response.raise_for_status()
        payload = response.json()
        vulnerabilities = payload.get("vulnerabilities", []) if isinstance(payload, dict) else []

        findings: List[Dict[str, Any]] = []
        for vuln in vulnerabilities:
            if not isinstance(vuln, dict):
                continue
            severity = SEVERITY_MAP.get(str(vuln.get("severity", "")).lower(), "info")
            findings.append(
                {
                    "title": vuln.get("name", "Vulnerabilità Acunetix"),
                    "severity": severity,
                    "description": vuln.get("description", ""),
                    "recommendation": vuln.get("remediation", ""),
                    "host": vuln.get("host", ""),
                    "path": vuln.get("path", ""),
                    "cve": vuln.get("cve", []) if isinstance(vuln.get("cve"), list) else [],
                    "tags": ["acunetix"],
                }
            )
        return findings
