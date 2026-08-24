"""Nikto scanner wrapper."""
from __future__ import annotations

from dataclasses import dataclass
import json
import shutil
import subprocess
from typing import Any, Dict, List

from config import settings


SENSITIVE_PATH_HINTS = (
    ".git",
    ".env",
    ".bak",
    ".backup",
    ".old",
    ".swp",
    ".zip",
    ".tar.gz",
    ".sql",
)


@dataclass
class NiktoScanner:
    enable_live_scans: bool = False

    def run(self, target: str) -> Dict[str, Any]:
        if not self.enable_live_scans:
            return {
                "tool": "nikto",
                "status": "simulated",
                "findings": [
                    {
                        "tool": "nikto",
                        "title": "Security Headers HTTP critici mancanti — CSP, HSTS, X-Frame-Options assenti",
                        "severity": "medium",
                        "description": (
                            "Nikto ha verificato che l'applicazione web non implementa i "
                            "principali header di sicurezza HTTP raccomandati da OWASP e "
                            "dai browser vendor. In particolare risultano assenti: "
                            "Content-Security-Policy (CSP), Strict-Transport-Security (HSTS), "
                            "X-Frame-Options, X-Content-Type-Options, Referrer-Policy e "
                            "Permissions-Policy. L'assenza di questi header amplifica "
                            "l'impatto di altre vulnerabilità come XSS e Clickjacking e "
                            "indebolisce le difese del browser dell'utente finale."
                        ),
                        "impact": (
                            "Senza CSP, eventuali vulnerabilità XSS possono eseguire script "
                            "arbitrari senza restrizioni. Senza HSTS, gli utenti sono vulnerabili "
                            "ad attacchi SSL stripping e MITM sulle prime connessioni HTTP. "
                            "Senza X-Frame-Options, l'applicazione è vulnerabile a Clickjacking, "
                            "permettendo a un attaccante di ingannare gli utenti per eseguire "
                            "azioni non intenzionali su un iframe nascosto."
                        ),
                        "attack_scenario": (
                            "Clickjacking Attack:\n"
                            "1. L'attaccante crea una pagina HTML con un iframe invisibile che "
                            "carica la pagina di pagamento dell'applicazione target.\n"
                            "2. Sovrappone elementi visibili ingannevoli ('Vinci un iPhone!').\n"
                            "3. La vittima clicca sul pulsante visibile attivando in realtà "
                            "'Conferma pagamento' nell'iframe nascosto.\n\n"
                            "SSL Stripping Attack (assenza HSTS):\n"
                            "1. MITM sulla rete locale sostituisce i link https:// con http://.\n"
                            "2. Le credenziali viaggiano in chiaro verso l'attaccante."
                        ),
                        "recommendation": (
                            "Aggiungere i seguenti header HTTP in tutte le risposte del server:\n"
                            "1. Content-Security-Policy: default-src 'self'; script-src 'self' "
                            "'nonce-{random}'; object-src 'none';\n"
                            "2. Strict-Transport-Security: max-age=31536000; includeSubDomains; preload\n"
                            "3. X-Frame-Options: DENY\n"
                            "4. X-Content-Type-Options: nosniff\n"
                            "5. Referrer-Policy: strict-origin-when-cross-origin\n"
                            "6. Permissions-Policy: geolocation=(), camera=(), microphone=()"
                        ),
                        "evidence": (
                            "HTTP/1.1 200 OK\n"
                            "Content-Type: text/html\n"
                            "# Assenti: Content-Security-Policy, Strict-Transport-Security,\n"
                            "# X-Frame-Options, X-Content-Type-Options"
                        ),
                        "affected_component": "HTTP Response Headers — tutte le pagine dell'applicazione",
                        "cwe": ["CWE-1021", "CWE-693", "CWE-16"],
                        "cvss_score": 6.1,
                        "tags": ["owasp-a05", "security-headers", "clickjacking", "xss"],
                        "references": [
                            "https://owasp.org/www-project-secure-headers/",
                            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy",
                            "https://cwe.mitre.org/data/definitions/1021.html",
                        ],
                    },
                    {
                        "tool": "nikto",
                        "title": "File di backup accessibile — database.sql.bak esposto nella webroot",
                        "severity": "high",
                        "description": (
                            "Nikto ha rilevato il file '/backup/database.sql.bak' accessibile "
                            "pubblicamente via HTTP (risposta 200 OK, Content-Length: 4.2MB). "
                            "Il file contiene il dump completo del database dell'applicazione, "
                            "incluse la struttura delle tabelle, tutti i record utente con "
                            "credenziali (hashate), dati personali e configurazioni applicative. "
                            "La presenza di file di backup nella webroot è un errore operativo "
                            "critico che espone l'intera base dati."
                        ),
                        "impact": (
                            "L'accesso al dump del database permette l'estrazione di tutti i dati "
                            "utente (PII, credenziali, dati di pagamento se presenti), la "
                            "ricostruzione dello schema del database per attacchi SQL injection "
                            "mirati, e il recupero di chiavi di cifratura o token segreti "
                            "eventualmente salvati nel database. Costituisce una violazione "
                            "GDPR con obbligo di notifica all'autorità di controllo."
                        ),
                        "attack_scenario": (
                            "1. Nikto o Dirsearch identificano /backup/database.sql.bak.\n"
                            "2. L'attaccante scarica il file con wget o curl.\n"
                            "3. Importa il database localmente e analizza la struttura.\n"
                            "4. Estrae 50.000 record utenti con email, hash bcrypt delle password.\n"
                            "5. Tenta attacchi dictionary su hash bcrypt con hashcat e wordlist rockyou.\n"
                            "6. Recupera password di account amministrativi e accede al pannello."
                        ),
                        "recommendation": (
                            "1. Rimuovere immediatamente il file dalla webroot e verificare "
                            "altri file di backup presenti (.sql, .bak, .tar.gz, .zip, .old).\n"
                            "2. Spostare i backup in storage separati non accessibili via web "
                            "(S3 privato, NAS interno, storage cifrato off-site).\n"
                            "3. Implementare regole nel web server per bloccare l'accesso a "
                            "estensioni di backup: deny all per .bak, .sql, .old, .backup.\n"
                            "4. Eseguire un audit di tutti i file presenti nella webroot.\n"
                            "5. Valutare l'impatto della violazione ed eseguire notifica GDPR "
                            "se i dati esposti includono PII di soggetti europei (entro 72h)."
                        ),
                        "evidence": "GET /backup/database.sql.bak → HTTP 200 OK (Content-Length: 4,294,967 bytes)",
                        "affected_component": "Web Server — file system della webroot /backup/",
                        "path": "/backup/database.sql.bak",
                        "cwe": ["CWE-530", "CWE-552"],
                        "cvss_score": 8.2,
                        "tags": ["owasp-a05", "sensitive-data-exposure", "backup-file"],
                        "references": [
                            "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
                            "https://cwe.mitre.org/data/definitions/530.html",
                        ],
                    },
                ],
            }

        if not shutil.which("nikto"):
            return {
                "tool": "nikto",
                "status": "skipped",
                "message": "Tool nikto non installato.",
                "findings": [],
            }

        command = ["nikto", "-h", target, "-Format", "json"]
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
                "tool": "nikto",
                "status": "timeout",
                "message": "Timeout durante l'esecuzione di Nikto.",
                "findings": [],
            }

        output = completed.stdout.strip()
        if not output:
            message = completed.stderr.strip() or "Output Nikto vuoto."
            return {
                "tool": "nikto",
                "status": "error",
                "message": message,
                "findings": [],
            }

        payload = self._parse_json_output(output)
        if payload is None:
            return {
                "tool": "nikto",
                "status": "error",
                "message": "Impossibile interpretare l'output JSON di Nikto.",
                "findings": [],
            }

        items = self._extract_vulnerabilities(payload)
        findings = [self._build_finding(item) for item in items]
        findings = [item for item in findings if item]

        status = "executed" if completed.returncode == 0 else "completed_with_warnings"
        return {
            "tool": "nikto",
            "status": status,
            "target": target,
            "findings": findings[: settings.max_findings],
        }

    def _parse_json_output(self, output: str) -> Dict[str, Any] | None:
        try:
            return json.loads(output)
        except json.JSONDecodeError:
            start = output.find("{")
            end = output.rfind("}")
            if start == -1 or end == -1:
                return None
            try:
                return json.loads(output[start : end + 1])
            except json.JSONDecodeError:
                return None

    def _extract_vulnerabilities(self, payload: Dict[str, Any]) -> List[Dict[str, Any]]:
        if "vulnerabilities" in payload:
            return payload.get("vulnerabilities", [])
        if "scan" in payload and isinstance(payload["scan"], dict):
            scan_payload = payload["scan"]
            if "vulnerabilities" in scan_payload:
                return scan_payload.get("vulnerabilities", [])
        if "vuln" in payload:
            return payload.get("vuln", [])

        for value in payload.values():
            if isinstance(value, list) and value and isinstance(value[0], dict):
                return value
        return []

    def _build_finding(self, item: Dict[str, Any]) -> Dict[str, Any] | None:
        message = item.get("msg") or item.get("message") or item.get("description")
        if not message:
            return None

        uri = item.get("uri") or item.get("path") or ""
        method = item.get("method") or "GET"
        references = item.get("references") or item.get("ref") or []
        if isinstance(references, str):
            references = [references]

        severity = self._classify_severity(message, uri)
        title = self._title_from_message(message, uri)

        description = f"{message}"
        if uri:
            description = f"{description} (Endpoint: {method} {uri})"
        if references:
            description = f"{description}. Riferimenti: {', '.join(references)}"

        return {
            "title": title,
            "severity": severity,
            "description": description,
            "recommendation": self._recommendation_for_item(message, uri),
        }

    def _classify_severity(self, message: str, uri: str) -> str:
        message_lower = message.lower()
        uri_lower = uri.lower()

        if "path traversal" in message_lower or "../" in message_lower:
            return "high"
        if "directory listing" in message_lower or "directory indexing" in message_lower:
            return "medium"
        if any(hint in uri_lower for hint in SENSITIVE_PATH_HINTS):
            return "high"
        if "ssl" in message_lower or "tls" in message_lower or "certificate" in message_lower:
            return "medium"
        if "x-frame-options" in message_lower or "content-security-policy" in message_lower:
            return "medium"
        if "missing" in message_lower and "header" in message_lower:
            return "low"
        return "low"

    def _title_from_message(self, message: str, uri: str) -> str:
        message_lower = message.lower()
        uri_lower = uri.lower()
        if "path traversal" in message_lower:
            return "Possibile path traversal rilevato"
        if "directory listing" in message_lower or "directory indexing" in message_lower:
            return "Directory listing abilitata"
        if any(hint in uri_lower for hint in SENSITIVE_PATH_HINTS):
            return "File sensibile esposto"
        if "ssl" in message_lower or "tls" in message_lower:
            return "Configurazione SSL/TLS potenzialmente debole"
        return "Vulnerabilità web rilevata"

    def _recommendation_for_item(self, message: str, uri: str) -> str:
        message_lower = message.lower()
        uri_lower = uri.lower()
        if "path traversal" in message_lower or "../" in message_lower:
            return "Validare gli input e limitare l'accesso ai percorsi del filesystem."
        if "directory listing" in message_lower or "directory indexing" in message_lower:
            return "Disabilitare l'indicizzazione directory sul web server."
        if any(hint in uri_lower for hint in SENSITIVE_PATH_HINTS):
            return "Rimuovere i file sensibili dall'area web o proteggerli con access control."
        if "ssl" in message_lower or "tls" in message_lower:
            return "Aggiornare cipher suite e abilitare solo TLS 1.2+."
        if "header" in message_lower:
            return "Configurare header di sicurezza (CSP, HSTS, X-Frame-Options)."
        return "Applicare patch e hardening secondo le best practice OWASP."
