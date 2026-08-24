"""Dirsearch scanner wrapper."""
from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from typing import Any, Dict, List, Optional, Tuple

from config import settings


ADMIN_HINTS = ("admin", "login", "dashboard", "wp-admin", "cpanel", "console")


@dataclass
class DirsearchScanner:
    enable_live_scans: bool = False

    def run(self, target: str) -> Dict[str, Any]:
        if not self.enable_live_scans:
            return {
                "tool": "dirsearch",
                "status": "simulated",
                "findings": [
                    {
                        "tool": "dirsearch",
                        "title": "Repository Git esposto pubblicamente — /.git/ accessibile via HTTP",
                        "severity": "critical",
                        "description": (
                            "Dirsearch ha scoperto la directory /.git/ accessibile via HTTP "
                            "sul server web target. Il repository Git contiene l'intera "
                            "storia del codice sorgente dell'applicazione, inclusi file di "
                            "configurazione con credenziali hardcoded, chiavi API, segreti di "
                            "cifratura e variabili d'ambiente. Il file /.git/config è leggibile "
                            "e rivela l'URL del repository remoto. Con strumenti come GitDumper "
                            "o git-dumper, un attaccante può ricostruire l'intero repository "
                            "anche se il directory listing è disabilitato."
                        ),
                        "impact": (
                            "L'esposizione del repository Git rappresenta una delle vulnerabilità "
                            "più critiche per un'applicazione web. Consente l'accesso completo "
                            "al codice sorgente (logiche di business, algoritmi proprietari), "
                            "il recupero di credenziali hardcoded (database, AWS keys, JWT secrets), "
                            "la ricostruzione di versioni precedenti che potrebbero contenere "
                            "vulnerabilità già 'corrette' ma ancora sfruttabili, e la scoperta "
                            "di endpoint nascosti non documentati."
                        ),
                        "attack_scenario": (
                            "1. Dirsearch identifica HTTP 200 su /.git/HEAD (contenuto: 'ref: refs/heads/main').\n"
                            "2. L'attaccante esegue: git-dumper http://target.com/.git ./repo_dump\n"
                            "3. Analizza la history git: git log --all --oneline --format='%H %s'\n"
                            "4. Trova commit con messaggio 'temp: hardcoded DB password'.\n"
                            "5. Recupera: git show abc123:config/database.yml → password: 'prod_super_secret_2023'\n"
                            "6. Usa le credenziali per accedere direttamente al database PostgreSQL."
                        ),
                        "recommendation": (
                            "1. Bloccare immediatamente l'accesso a /.git/ nel web server:\n"
                            "   - Nginx: location ^~ /.git { deny all; return 404; }\n"
                            "   - Apache: RedirectMatch 404 /\\.git\n"
                            "2. Revocare tutte le credenziali e i token esposti nella history git.\n"
                            "3. Non memorizzare segreti nel codice sorgente: usare variabili "
                            "d'ambiente o un secrets manager (HashiCorp Vault, AWS Secrets Manager).\n"
                            "4. Aggiungere un file .gitignore appropriato per escludere file "
                            "di configurazione sensibili.\n"
                            "5. Considerare la rotazione di tutte le chiavi API e credenziali "
                            "per l'intera storia del repository."
                        ),
                        "evidence": "GET /.git/HEAD → HTTP 200 OK\nref: refs/heads/main",
                        "affected_component": "Repository Git — /.git/config, /.git/FETCH_HEAD",
                        "path": "/.git/",
                        "cwe": ["CWE-312", "CWE-538"],
                        "cvss_score": 9.1,
                        "tags": ["owasp-a02", "git-exposure", "credential-exposure", "source-code"],
                        "references": [
                            "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
                            "https://cwe.mitre.org/data/definitions/538.html",
                            "https://github.com/arthaud/git-dumper",
                        ],
                    },
                    {
                        "tool": "dirsearch",
                        "title": "Interfaccia amministrativa esposta — /admin/dashboard accessibile",
                        "severity": "high",
                        "description": (
                            "Dirsearch ha identificato l'endpoint /admin/dashboard accessibile "
                            "pubblicamente con risposta HTTP 200. Il pannello di amministrazione "
                            "espone funzionalità sensibili quali la gestione utenti, la "
                            "configurazione del sistema e l'accesso ai log applicativi. "
                            "Il pannello non implementa autenticazione aggiuntiva oltre al "
                            "form di login standard, rendendolo vulnerabile ad attacchi di "
                            "brute force e a exploit di vulnerabilità note nei framework "
                            "di admin panel comunemente utilizzati."
                        ),
                        "impact": (
                            "L'accesso non autorizzato al pannello amministrativo può portare "
                            "alla compromissione completa dell'applicazione: creazione di "
                            "account admin aggiuntivi, modifica dei contenuti, accesso ai "
                            "dati di tutti gli utenti, upload di file malevoli e potenziale "
                            "esecuzione di codice sul server attraverso funzionalità di "
                            "gestione avanzate."
                        ),
                        "attack_scenario": (
                            "1. Dirsearch identifica /admin/dashboard → HTTP 200.\n"
                            "2. L'attaccante accede e trova un form di login senza rate limiting.\n"
                            "3. Esegue attacco brute force con Hydra usando wordlist admin-specific.\n"
                            "4. Accede con credenziali di default 'admin/admin' non cambiate.\n"
                            "5. Carica una web shell tramite la funzione 'Upload Template'.\n"
                            "6. Esegue comandi OS con i privilegi dell'utente web server."
                        ),
                        "recommendation": (
                            "1. Limitare l'accesso a /admin/* tramite IP allowlist o VPN.\n"
                            "2. Implementare autenticazione MFA obbligatoria per tutti gli "
                            "account amministrativi.\n"
                            "3. Spostare il pannello admin su un percorso non predicibile "
                            "e non indicizzato dai motori di ricerca (X-Robots-Tag: noindex).\n"
                            "4. Aggiungere rate limiting severo: max 3 tentativi in 10 minuti.\n"
                            "5. Abilitare logging dettagliato e alerting real-time per "
                            "ogni accesso all'area amministrativa."
                        ),
                        "evidence": "GET /admin/dashboard → HTTP 200 OK (Admin Panel v2.4.1)",
                        "affected_component": "Admin Panel — /admin/dashboard, /admin/users",
                        "path": "/admin/dashboard",
                        "cwe": ["CWE-284", "CWE-521"],
                        "cvss_score": 8.8,
                        "tags": ["owasp-a01", "broken-access-control", "admin-panel"],
                        "references": [
                            "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
                            "https://cwe.mitre.org/data/definitions/284.html",
                        ],
                    },
                ],
            }

        command, wordlist, error = self._resolve_command_and_wordlist()
        if error:
            return {
                "tool": "dirsearch",
                "status": "skipped",
                "message": error,
                "findings": [],
            }

        fd, output_name = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        output_path = Path(output_name)
        cmd = [
            *command,
            "-u",
            target,
            "-w",
            wordlist,
            "--format",
            "json",
            "--output",
            str(output_path),
            "--quiet",
        ]
        if settings.dirsearch_extensions:
            cmd.extend(["-e", settings.dirsearch_extensions])
        if settings.dirsearch_threads:
            cmd.extend(["--threads", str(settings.dirsearch_threads)])

        try:
            completed = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=settings.scan_timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return {
                "tool": "dirsearch",
                "status": "timeout",
                "message": "Timeout durante l'esecuzione di Dirsearch.",
                "findings": [],
            }
        finally:
            if output_path.exists() and output_path.stat().st_size == 0:
                output_path.unlink(missing_ok=True)

        if completed.returncode not in (0, 1):
            return {
                "tool": "dirsearch",
                "status": "error",
                "message": completed.stderr.strip() or "Errore durante Dirsearch.",
                "findings": [],
            }

        entries = self._load_results(output_path)
        findings = self._build_findings(entries)
        status = "executed" if completed.returncode == 0 else "completed_with_warnings"

        return {
            "tool": "dirsearch",
            "status": status,
            "target": target,
            "endpoints": entries,
            "findings": findings[: settings.max_findings],
        }

    def _resolve_command_and_wordlist(self) -> Tuple[List[str], str, Optional[str]]:
        command = self._resolve_command()
        if not command:
            return [], "", "Tool dirsearch non installato o path non valido."

        wordlist = self._resolve_wordlist()
        if not wordlist:
            return [], "", "Wordlist dirsearch non trovata. Configura VAP_DIRSEARCH_WORDLIST."

        return command, wordlist, None

    def _resolve_command(self) -> List[str]:
        if shutil.which("dirsearch"):
            return ["dirsearch"]

        path = Path(settings.dirsearch_path)
        if path.is_dir():
            script = path / "dirsearch.py"
            if script.exists():
                return [sys.executable, str(script)]
        elif path.exists():
            if path.suffix == ".py":
                return [sys.executable, str(path)]
            return [str(path)]

        return []

    def _resolve_wordlist(self) -> str:
        if settings.dirsearch_wordlist:
            wordlist = Path(settings.dirsearch_wordlist)
            if wordlist.exists():
                return str(wordlist)

        path = Path(settings.dirsearch_path)
        if path.is_dir():
            default_wordlist = path / "db" / "dicc.txt"
            if default_wordlist.exists():
                return str(default_wordlist)
        return ""

    def _load_results(self, output_path: Path) -> List[Dict[str, Any]]:
        if not output_path.exists():
            return []
        try:
            payload = json.loads(output_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return []
        finally:
            output_path.unlink(missing_ok=True)

        return self._extract_entries(payload)

    def _extract_entries(self, payload: Any) -> List[Dict[str, Any]]:
        if isinstance(payload, list):
            return payload
        if isinstance(payload, dict):
            if "results" in payload:
                return payload.get("results", [])
            for value in payload.values():
                if isinstance(value, list):
                    return value
        return []

    def _build_findings(self, entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        if not entries:
            return findings

        findings.append(
            {
                "title": "Endpoint nascosti individuati",
                "severity": "info",
                "description": f"Rilevati {len(entries)} endpoint tramite directory brute force.",
                "recommendation": "Verificare access control e rimuovere percorsi inutilizzati.",
            }
        )

        for entry in entries:
            path = entry.get("path") or entry.get("url") or ""
            status = entry.get("status") or entry.get("status_code") or "n/d"
            length = entry.get("length") or entry.get("size") or "n/d"
            severity = self._severity_for_entry(path, status)
            title = self._title_for_entry(path, status)
            findings.append(
                {
                    "title": title,
                    "severity": severity,
                    "description": f"Endpoint {path} (status {status}, size {length}).",
                    "recommendation": self._recommendation_for_entry(path, status),
                }
            )

        return findings

    def _severity_for_entry(self, path: str, status: Any) -> str:
        path_lower = str(path).lower()
        if any(hint in path_lower for hint in ADMIN_HINTS):
            return "medium"
        try:
            status_code = int(status)
        except (TypeError, ValueError):
            return "low"
        if status_code == 403:
            return "low"
        if 200 <= status_code < 300:
            return "medium"
        return "low"

    def _title_for_entry(self, path: str, status: Any) -> str:
        path_lower = str(path).lower()
        if any(hint in path_lower for hint in ADMIN_HINTS):
            return "Possibile pannello amministrativo"
        try:
            status_code = int(status)
        except (TypeError, ValueError):
            return "Endpoint trovato"
        if status_code == 403:
            return "Endpoint protetto rilevato"
        return "Endpoint trovato"

    def _recommendation_for_entry(self, path: str, status: Any) -> str:
        path_lower = str(path).lower()
        if any(hint in path_lower for hint in ADMIN_HINTS):
            return "Proteggere l'endpoint con autenticazione forte e allowlist IP."
        try:
            status_code = int(status)
        except (TypeError, ValueError):
            return "Verificare l'esposizione dell'endpoint."
        if status_code == 403:
            return "Confermare che i controlli di accesso siano correttamente configurati."
        return "Valutare se l'endpoint deve rimanere pubblico."
