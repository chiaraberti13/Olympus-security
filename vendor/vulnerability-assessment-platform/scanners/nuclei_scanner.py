"""Nuclei scanner wrapper."""
from __future__ import annotations

from dataclasses import dataclass
import json
import shlex
import shutil
import subprocess
from typing import Any, Dict, List, Optional

from config import settings


SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


@dataclass
class NucleiScanner:
    enable_live_scans: bool = False
    template_profile: Optional[str] = None

    def run(self, target: str) -> Dict[str, Any]:
        if not self.enable_live_scans:
            return {
                "tool": "nuclei",
                "status": "simulated",
                "findings": [
                    {
                        "tool": "nuclei",
                        "title": "Endpoint API amministrativo esposto senza autenticazione",
                        "severity": "high",
                        "description": (
                            "Nuclei ha rilevato un endpoint API di tipo amministrativo "
                            "(/api/v1/admin/users) raggiungibile pubblicamente senza alcun "
                            "meccanismo di autenticazione o autorizzazione. L'endpoint risponde "
                            "con HTTP 200 e restituisce una lista completa degli utenti del sistema, "
                            "inclusi hash delle password e token di sessione attivi. "
                            "La vulnerabilità è classificata come Broken Access Control (OWASP A01:2021) "
                            "e consente a qualsiasi attore non autenticato di enumerare utenti "
                            "e potenzialmente scalare i privilegi."
                        ),
                        "impact": (
                            "Un attaccante può enumerare tutti gli account del sistema, ottenere hash "
                            "delle password per attacchi offline (password cracking), invalidare "
                            "sessioni attive e ottenere accesso non autorizzato a funzionalità "
                            "riservate agli amministratori, portando potenzialmente alla compromissione "
                            "totale dell'applicazione."
                        ),
                        "attack_scenario": (
                            "1. L'attaccante esegue una ricognizione passiva tramite Google Dork "
                            "o Shodan per identificare endpoint esposti.\n"
                            "2. Invia una richiesta GET non autenticata a /api/v1/admin/users.\n"
                            "3. Il server risponde con un array JSON contenente username, email, "
                            "ruoli e hash delle password.\n"
                            "4. L'attaccante effettua un attacco dictionary offline sugli hash "
                            "ottenendo le credenziali in chiaro.\n"
                            "5. Accede all'interfaccia amministrativa con le credenziali recuperate."
                        ),
                        "recommendation": (
                            "1. Implementare autenticazione JWT o OAuth 2.0 su tutti gli endpoint "
                            "amministrativi.\n"
                            "2. Applicare controllo degli accessi basato su ruoli (RBAC) verificando "
                            "i permessi a livello di ogni endpoint.\n"
                            "3. Posizionare gli endpoint admin su subnet interne non raggiungibili "
                            "dall'esterno o proteggere con allowlist IP.\n"
                            "4. Implementare rate limiting (max 10 richieste/min per IP) sulle "
                            "API sensibili.\n"
                            "5. Aggiungere logging e alerting per accessi non autorizzati."
                        ),
                        "evidence": "GET /api/v1/admin/users → HTTP 200 OK [{\"id\":1,\"username\":\"admin\",\"password_hash\":\"...\"}]",
                        "affected_component": "REST API — endpoint /api/v1/admin/users",
                        "cwe": ["CWE-284", "CWE-862"],
                        "cvss_score": 8.6,
                        "cvss_metrics": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
                        "tags": ["owasp-a01", "broken-access-control", "api-security"],
                        "references": [
                            "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
                            "https://cwe.mitre.org/data/definitions/284.html",
                            "https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html",
                        ],
                    },
                    {
                        "tool": "nuclei",
                        "title": "Rate Limiting assente sull'endpoint di login — Brute Force possibile",
                        "severity": "medium",
                        "description": (
                            "L'endpoint di autenticazione POST /auth/login non implementa alcun "
                            "meccanismo di rate limiting né di account lockout. È possibile inviare "
                            "un numero illimitato di tentativi di accesso senza restrizioni, "
                            "rendendo l'applicazione vulnerabile ad attacchi di brute force e "
                            "credential stuffing. Il test ha verificato 500 richieste consecutive "
                            "senza alcun blocco o rallentamento da parte del server."
                        ),
                        "impact": (
                            "Attacchi di brute force e credential stuffing possono portare alla "
                            "compromissione di account utente, in particolare quelli con password "
                            "deboli o già comparse in precedenti data breach. L'assenza di lockout "
                            "rende praticabile anche l'enumerazione di username validi analizzando "
                            "i tempi di risposta differenziali."
                        ),
                        "attack_scenario": (
                            "1. L'attaccante ottiene una wordlist di password comuni o una lista "
                            "di credenziali da breach precedenti (es. HaveIBeenPwned).\n"
                            "2. Esegue uno script di credential stuffing con Hydra o Burp Intruder "
                            "inviando centinaia di richieste POST/min all'endpoint /auth/login.\n"
                            "3. Il server non blocca né rallenta il traffico.\n"
                            "4. L'attaccante ottiene accesso agli account con password deboli "
                            "o riutilizzate."
                        ),
                        "recommendation": (
                            "1. Implementare rate limiting a livello applicativo: max 5 tentativi "
                            "falliti per account in 15 minuti.\n"
                            "2. Introdurre account lockout temporaneo con notifica via email dopo "
                            "tentativi falliti ripetuti.\n"
                            "3. Aggiungere CAPTCHA (reCAPTCHA v3) dopo 3 tentativi falliti "
                            "consecutivi dallo stesso IP.\n"
                            "4. Implementare Multi-Factor Authentication (MFA/TOTP) come misura "
                            "difensiva indipendente.\n"
                            "5. Integrare un WAF con regole anti-brute-force."
                        ),
                        "evidence": "500 richieste POST /auth/login in 60s — 0 blocchi, 0 429 Too Many Requests",
                        "affected_component": "Endpoint autenticazione — POST /auth/login",
                        "cwe": ["CWE-307", "CWE-799"],
                        "cvss_score": 6.5,
                        "cvss_metrics": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        "tags": ["owasp-a07", "brute-force", "authentication"],
                        "references": [
                            "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
                            "https://cwe.mitre.org/data/definitions/307.html",
                            "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
                        ],
                    },
                ],
            }

        if not shutil.which("nuclei"):
            return {
                "tool": "nuclei",
                "status": "skipped",
                "message": "Tool nuclei non installato.",
                "findings": [],
            }

        update_result = self._update_templates()
        if update_result:
            return update_result

        severity_filter = self._normalize_severities(settings.nuclei_severities)
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
                "tool": "nuclei",
                "status": "error",
                "message": "Timeout durante l'esecuzione di nuclei.",
                "findings": [],
            }

        findings = self._parse_findings(completed.stdout, severity_filter)
        message = completed.stderr.strip() if completed.stderr else ""
        status = "executed" if completed.returncode == 0 else "error"
        if completed.returncode != 0 and not message:
            message = "Errore durante l'esecuzione di nuclei."

        return {
            "tool": "nuclei",
            "status": status,
            "message": message,
            "findings": findings,
        }

    def _update_templates(self) -> Optional[Dict[str, Any]]:
        if not settings.nuclei_update_templates:
            return None

        try:
            completed = subprocess.run(
                ["nuclei", "-update-templates"],
                capture_output=True,
                text=True,
                timeout=settings.scan_timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return {
                "tool": "nuclei",
                "status": "error",
                "message": "Timeout durante l'aggiornamento dei template nuclei.",
                "findings": [],
            }

        if completed.returncode != 0:
            message = completed.stderr.strip() if completed.stderr else "Errore update template nuclei."
            return {
                "tool": "nuclei",
                "status": "error",
                "message": message,
                "findings": [],
            }
        return None

    def _build_command(self, target: str) -> List[str]:
        command = [
            "nuclei",
            "-u",
            target,
            "-json",
            "-rl",
            str(settings.nuclei_rate_limit),
            "-timeout",
            str(settings.nuclei_timeout_seconds),
        ]

        templates = [item.strip() for item in settings.nuclei_templates.split(",") if item.strip()]
        if templates:
            command.extend(["-t", ",".join(templates)])

        if self.template_profile == "wordpress":
            command.extend(["-tags", "wordpress"])

        if settings.nuclei_additional_args:
            command.extend(shlex.split(settings.nuclei_additional_args))

        return command

    def _normalize_severities(self, value: str) -> List[str]:
        if not value:
            return list(SEVERITY_ORDER)
        raw = [item.strip().lower() for item in value.split(",") if item.strip()]
        ordered = [sev for sev in SEVERITY_ORDER if sev in raw]
        return ordered or list(SEVERITY_ORDER)

    def _parse_findings(self, stdout: str, severity_filter: List[str]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue

            info = payload.get("info", {}) if isinstance(payload, dict) else {}
            severity = str(info.get("severity", "info")).lower()
            if severity not in severity_filter:
                continue

            classification = info.get("classification", {}) if isinstance(info, dict) else {}
            cve_ids = classification.get("cve-id") or []
            if isinstance(cve_ids, str):
                cve_ids = [cve_ids]
            cwe_ids = classification.get("cwe-id") or []
            if isinstance(cwe_ids, str):
                cwe_ids = [cwe_ids]

            references = info.get("reference") or []
            if isinstance(references, str):
                references = [references]

            finding = {
                "title": info.get("name") or payload.get("template-id", "Finding Nuclei"),
                "severity": severity,
                "description": info.get("description", ""),
                "recommendation": info.get("remediation", ""),
                "host": payload.get("host"),
                "matched_at": payload.get("matched-at"),
                "template_id": payload.get("template-id"),
                "matcher": payload.get("matcher-name"),
                "cve": cve_ids,
                "cwe": cwe_ids,
                "cvss_score": classification.get("cvss-score"),
                "cvss_metrics": classification.get("cvss-metrics"),
                "references": references,
                "tags": info.get("tags", []),
                "timestamp": payload.get("timestamp"),
            }
            findings.append(finding)

        return findings
