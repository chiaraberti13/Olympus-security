"""Nessus API scanner wrapper (optional)."""
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
class NessusScanner:
    enable_live_scans: bool = False

    def run(self, target: str) -> Dict[str, Any]:
        if not self.enable_live_scans:
            return {
                "tool": "nessus",
                "status": "simulated",
                "findings": [
                    {
                        "tool": "nessus",
                        "title": "TLS 1.0 e 1.1 abilitati — Protocolli deprecati vulnerabili a POODLE e BEAST",
                        "severity": "medium",
                        "description": (
                            "Nessus ha verificato che il server accetta connessioni TLS con "
                            "protocolli deprecati TLS 1.0 e TLS 1.1. TLS 1.0 è vulnerabile "
                            "agli attacchi POODLE (CVE-2014-3566) e BEAST (CVE-2011-3389), "
                            "mentre TLS 1.1 non supporta cipher suite AEAD moderne. "
                            "Il test ha confermato che il server negozia TLS 1.0 quando il "
                            "client dichiara supporto a quella versione. "
                            "TLS 1.0 e 1.1 sono stati ufficialmente deprecati dall'IETF "
                            "(RFC 8996, marzo 2021) e rimossi da tutti i principali browser "
                            "nel 2020. La PCI DSS 3.2 ha reso obbligatoria la disabilitazione "
                            "di TLS 1.0 dal giugno 2018."
                        ),
                        "impact": (
                            "Attacchi POODLE e BEAST possono decifrare il traffico TLS 1.0 "
                            "in determinati scenari di rete (MITM su stesso segmento). "
                            "Le cipher suite disponibili in TLS 1.0 includono RC4 e 3DES, "
                            "entrambe con vulnerabilità crittografiche note. La non-conformità "
                            "PCI DSS espone l'organizzazione a sanzioni e alla revoca "
                            "della certificazione per la gestione di dati di pagamento."
                        ),
                        "attack_scenario": (
                            "POODLE Attack (TLS 1.0):\n"
                            "1. MITM posizionato tra client e server sulla stessa rete.\n"
                            "2. Forza il downgrade della connessione a TLS 1.0.\n"
                            "3. Sfrutta la vulnerabilità del padding CBC in TLS 1.0.\n"
                            "4. Con ~256 richieste induce il client a inviare un token segreto.\n"
                            "5. Decifra il cookie di sessione un byte alla volta.\n"
                            "6. Impersona l'utente autenticato."
                        ),
                        "recommendation": (
                            "1. Disabilitare TLS 1.0 e TLS 1.1 nella configurazione del server:\n"
                            "   Nginx: ssl_protocols TLSv1.2 TLSv1.3;\n"
                            "   Apache: SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1\n"
                            "2. Abilitare esclusivamente cipher suite moderne:\n"
                            "   ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:...;\n"
                            "3. Abilitare TLS 1.3 per prestazioni e sicurezza ottimali.\n"
                            "4. Configurare HSTS con preload per prevenire downgrade attacks:\n"
                            "   Strict-Transport-Security: max-age=31536000; includeSubDomains; preload\n"
                            "5. Verificare la configurazione con SSL Labs (ssllabs.com/ssltest) "
                            "puntando ad almeno un rating A."
                        ),
                        "evidence": (
                            "TLS 1.0 negoziato → Cipher: TLS_RSA_WITH_3DES_EDE_CBC_SHA\n"
                            "TLS 1.1 negoziato → Cipher: TLS_RSA_WITH_AES_128_CBC_SHA"
                        ),
                        "affected_component": "TLS/SSL — configurazione del server web",
                        "cve": ["CVE-2014-3566", "CVE-2011-3389"],
                        "cwe": ["CWE-326", "CWE-757"],
                        "cvss_score": 5.9,
                        "tags": ["owasp-a02", "tls", "cryptographic-failures"],
                        "references": [
                            "https://nvd.nist.gov/vuln/detail/CVE-2014-3566",
                            "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
                            "https://datatracker.ietf.org/doc/html/rfc8996",
                            "https://www.ssllabs.com/ssltest/",
                        ],
                    },
                    {
                        "tool": "nessus",
                        "title": "HTTP Strict Transport Security (HSTS) non configurato — Downgrade attack possibile",
                        "severity": "medium",
                        "description": (
                            "Nessus ha verificato l'assenza dell'header "
                            "Strict-Transport-Security (HSTS) nelle risposte HTTPS del server. "
                            "HSTS è un meccanismo di sicurezza che istruisce il browser a "
                            "utilizzare esclusivamente HTTPS per le future connessioni al dominio, "
                            "prevenendo attacchi di SSL stripping. Senza HSTS, la prima "
                            "connessione HTTP di un utente può essere intercettata da un "
                            "attaccante MITM che converte le risorse HTTPS in HTTP prima "
                            "che il browser le riceva (SSL stripping attack)."
                        ),
                        "impact": (
                            "Un attaccante MITM sulla rete locale (WiFi pubblico, ARP poisoning) "
                            "può intercettare la prima connessione HTTP e downgradare l'intera "
                            "sessione a HTTP in chiaro, esponendo credenziali, cookie di sessione "
                            "e tutti i dati trasmessi. Senza il preloading HSTS, il dominio "
                            "rimane vulnerabile anche dopo la prima connessione HTTPS se la "
                            "cache del browser viene svuotata."
                        ),
                        "attack_scenario": (
                            "SSL Stripping Attack (sslstrip):\n"
                            "1. Attaccante esegue ARP poisoning sulla rete locale per posizionarsi MITM.\n"
                            "2. Avvia sslstrip che intercetta risposte HTTP e converte href https:// in http://.\n"
                            "3. L'utente tenta https://target.com → sslstrip intercetta e serve http://target.com.\n"
                            "4. L'utente non nota la mancanza di HTTPS (nessun lock nel browser).\n"
                            "5. Credenziali inviate in chiaro → sslstrip le cattura e le forwarda."
                        ),
                        "recommendation": (
                            "1. Aggiungere l'header HSTS a tutte le risposte HTTPS:\n"
                            "   Strict-Transport-Security: max-age=31536000; includeSubDomains; preload\n"
                            "   (max-age minimo raccomandato: 1 anno = 31536000 secondi)\n"
                            "2. Abilitare 'includeSubDomains' solo dopo aver verificato che "
                            "tutti i sottodomini supportano HTTPS.\n"
                            "3. Aggiungere il dominio al HSTS Preload List (hstspreload.org) "
                            "per protezione anche sulla prima connessione.\n"
                            "4. Configurare redirect 301 permanente da HTTP a HTTPS per "
                            "tutte le richieste non sicure."
                        ),
                        "evidence": "HTTPS GET / → risposta senza header Strict-Transport-Security",
                        "affected_component": "HTTPS Configuration — header HSTS mancante",
                        "cwe": ["CWE-319", "CWE-523"],
                        "cvss_score": 4.8,
                        "tags": ["owasp-a02", "hsts", "ssl-stripping", "cryptographic-failures"],
                        "references": [
                            "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
                            "https://cwe.mitre.org/data/definitions/319.html",
                            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
                            "https://hstspreload.org/",
                        ],
                    },
                ],
            }

        if not settings.nessus_api_base_url or not settings.nessus_api_key:
            return {
                "tool": "nessus",
                "status": "skipped",
                "message": "API Nessus non configurata.",
                "findings": [],
            }

        try:
            findings = self._fetch_findings(target)
        except requests.RequestException as exc:
            return {
                "tool": "nessus",
                "status": "error",
                "message": f"Errore API Nessus: {exc}",
                "findings": [],
            }

        return {
            "tool": "nessus",
            "status": "executed",
            "findings": findings,
        }

    def _fetch_findings(self, target: str) -> List[Dict[str, Any]]:
        url = f"{settings.nessus_api_base_url.rstrip('/')}{settings.nessus_vulnerabilities_endpoint}"
        headers = {"X-ApiKeys": settings.nessus_api_key}
        response = requests.get(
            url,
            headers=headers,
            params={"target": target},
            timeout=settings.nessus_timeout_seconds,
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
                    "title": vuln.get("plugin_name", "Vulnerabilità Nessus"),
                    "severity": severity,
                    "description": vuln.get("description", ""),
                    "recommendation": vuln.get("solution", ""),
                    "host": vuln.get("host", ""),
                    "port": vuln.get("port", ""),
                    "cve": vuln.get("cve", []) if isinstance(vuln.get("cve"), list) else [],
                    "tags": ["nessus"],
                }
            )
        return findings
