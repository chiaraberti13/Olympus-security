"""SQLMap scanner wrapper."""
from __future__ import annotations

from dataclasses import dataclass
import re
import shlex
import shutil
import subprocess
from typing import Any, Dict, List

from config import settings


SQLMAP_PARAM_REGEX = re.compile(r"parameter '([^']+)' is vulnerable", re.IGNORECASE)


@dataclass
class SqlmapScanner:
    enable_live_scans: bool = False

    def run(self, target: str) -> Dict[str, Any]:
        if not self.enable_live_scans:
            return {
                "tool": "sqlmap",
                "status": "simulated",
                "findings": [
                    {
                        "tool": "sqlmap",
                        "title": "SQL Injection Boolean-Based — Parametro 'id' vulnerabile a estrazione dati",
                        "severity": "critical",
                        "description": (
                            "SQLMap ha confermato la presenza di una vulnerabilità di SQL Injection "
                            "di tipo boolean-based blind nel parametro GET 'id' dell'endpoint "
                            "/products?id=1. Il parametro viene concatenato direttamente alla "
                            "query SQL senza sanitizzazione né utilizzo di prepared statement. "
                            "È stato possibile estrarre la versione del database (MySQL 8.0.27), "
                            "il nome del database corrente ('webapp_db'), la lista completa delle "
                            "tabelle e il contenuto della tabella 'users' con 15.000 record. "
                            "La vulnerabilità permette anche l'esecuzione di comandi OS se "
                            "l'utente DB ha privilegi FILE."
                        ),
                        "impact": (
                            "SQL Injection di tipo critico che consente: estrazione completa del "
                            "database (dump di tutte le tabelle), lettura/scrittura di file sul "
                            "filesystem del server (con privilegi adeguati), potenziale esecuzione "
                            "di comandi OS tramite xp_cmdshell (SQL Server) o UDF (MySQL), "
                            "bypass dell'autenticazione e privilege escalation completa "
                            "nell'applicazione. Classificata CVSS 9.8 (Critica)."
                        ),
                        "attack_scenario": (
                            "Fase 1 — Rilevamento:\n"
                            "GET /products?id=1' → Errore SQL rivelato nella risposta\n"
                            "GET /products?id=1 AND 1=1 → Risposta normale (true)\n"
                            "GET /products?id=1 AND 1=2 → Risposta vuota (false)\n\n"
                            "Fase 2 — Estrazione dati:\n"
                            "GET /products?id=1 AND SUBSTRING(password,1,1)='a' → enumerazione carattere per carattere\n\n"
                            "Fase 3 — Automazione con SQLMap:\n"
                            "sqlmap -u 'http://target/products?id=1' --dbs --dump -T users --batch\n"
                            "→ Dump completo: 15.000 utenti con email e password hash MD5 non salate"
                        ),
                        "recommendation": (
                            "1. IMMEDIATO: Utilizzare esclusivamente prepared statement / "
                            "query parametrizzate in tutto il codice di accesso al database:\n"
                            "   Python: cursor.execute('SELECT * FROM products WHERE id = %s', (id,))\n"
                            "   Java: PreparedStatement ps = conn.prepareStatement('SELECT * FROM products WHERE id = ?')\n"
                            "2. Implementare un ORM (SQLAlchemy, Hibernate, ActiveRecord) che "
                            "gestisca automaticamente l'escaping degli input.\n"
                            "3. Applicare il principio del minimo privilegio: l'utente DB deve "
                            "avere solo i permessi necessari (SELECT, INSERT, UPDATE — no FILE, SUPER).\n"
                            "4. Abilitare un WAF con regole SQL injection (ModSecurity CRS).\n"
                            "5. Validare e sanitizzare tutti gli input utente lato server "
                            "(whitelist dei tipi attesi: int, string con lunghezza massima).\n"
                            "6. Disabilitare la visualizzazione di errori SQL nelle risposte HTTP."
                        ),
                        "evidence": (
                            "GET /products?id=1 AND 1=1 → 200 OK (10 prodotti)\n"
                            "GET /products?id=1 AND 1=2 → 200 OK (0 prodotti)\n"
                            "Payload: id=1 AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))"
                        ),
                        "affected_component": "Endpoint /products — parametro GET 'id'",
                        "path": "/products",
                        "parameter": "id",
                        "cwe": ["CWE-89"],
                        "cvss_score": 9.8,
                        "cvss_metrics": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        "tags": ["owasp-a03", "sql-injection", "injection"],
                        "references": [
                            "https://owasp.org/Top10/A03_2021-Injection/",
                            "https://cwe.mitre.org/data/definitions/89.html",
                            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                            "https://sqlmap.org/",
                        ],
                    },
                ],
            }

        if not shutil.which(settings.sqlmap_path):
            return {
                "tool": "sqlmap",
                "status": "skipped",
                "message": "Tool sqlmap non installato.",
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
                "tool": "sqlmap",
                "status": "error",
                "message": "Timeout durante l'esecuzione di sqlmap.",
                "findings": [],
            }

        findings = self._parse_findings(completed.stdout)
        message = completed.stderr.strip() if completed.stderr else ""
        status = "executed" if completed.returncode == 0 else "error"
        if completed.returncode != 0 and not message:
            message = "Errore durante l'esecuzione di sqlmap."

        return {
            "tool": "sqlmap",
            "status": status,
            "message": message,
            "findings": findings,
        }

    def _build_command(self, target: str) -> List[str]:
        command = [
            settings.sqlmap_path,
            "-u",
            target,
            "--batch",
            "--level",
            str(settings.sqlmap_level),
            "--risk",
            str(settings.sqlmap_risk),
            "--crawl",
            str(settings.sqlmap_crawl_depth),
        ]
        if settings.sqlmap_forms:
            command.append("--forms")
        if settings.sqlmap_additional_args:
            command.extend(shlex.split(settings.sqlmap_additional_args))
        return command

    def _parse_findings(self, stdout: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for line in stdout.splitlines():
            match = SQLMAP_PARAM_REGEX.search(line)
            if not match:
                continue
            parameter = match.group(1)
            findings.append(
                {
                    "title": f"SQL Injection su parametro {parameter}",
                    "severity": "high",
                    "description": "SQLMap ha individuato un possibile vettore di SQL injection.",
                    "recommendation": "Usare query parametrizzate e disabilitare l'output di errori SQL.",
                    "parameter": parameter,
                    "cwe": ["CWE-89"],
                    "tags": ["owasp-a03", "sql-injection"],
                }
            )
        return findings
