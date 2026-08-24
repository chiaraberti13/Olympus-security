"""Nmap scanner wrapper."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List
from urllib.parse import urlparse
import re
import shlex
import shutil
import subprocess
import xml.etree.ElementTree as ET

from config import settings


# Riconosce gli identificatori CVE nell'output degli script NSE (es. vulners).
CVE_REGEX = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


VULNERABLE_SERVICE_HINTS = {
    "telnet": ("Servizio Telnet non cifrato esposto.", "high"),
    "ftp": ("Servizio FTP esposto: possibile intercettazione credenziali.", "medium"),
    "smtp": ("Servizio SMTP esposto: verificare configurazioni relaying.", "medium"),
    "smb": ("Servizio SMB esposto: verificare patch e accessi.", "high"),
    "rdp": ("Servizio RDP esposto: verificare MFA e policy.", "high"),
    "vnc": ("Servizio VNC esposto: rischio accesso remoto non autorizzato.", "high"),
    "redis": ("Servizio Redis esposto: verificare autenticazione.", "high"),
    "mongodb": ("Servizio MongoDB esposto: verificare autenticazione.", "high"),
}


@dataclass
class NmapScanner:
    enable_live_scans: bool = False

    def run(self, target: str) -> Dict[str, Any]:
        if not self.enable_live_scans:
            return {
                "tool": "nmap",
                "status": "simulated",
                "findings": [
                    {
                        "tool": "nmap",
                        "title": "Porta di gestione 8080 esposta pubblicamente — Pannello admin accessibile",
                        "severity": "medium",
                        "description": (
                            "Nmap ha rilevato la porta TCP 8080 aperta sull'host target con un "
                            "servizio HTTP attivo (Apache Tomcat 9.0.45). La porta espone "
                            "l'interfaccia di gestione del server applicativo direttamente su "
                            "Internet senza restrizioni di accesso IP. Servizi di management "
                            "come Tomcat Manager, Jenkins o simili su porte non standard "
                            "spesso presentano credenziali di default o vulnerabilità note."
                        ),
                        "impact": (
                            "L'accesso all'interfaccia di gestione può permettere il deploy di "
                            "applicazioni WAR malevole (nel caso di Tomcat Manager), l'esecuzione "
                            "di comandi arbitrari sul sistema operativo sottostante e la "
                            "compromissione totale del server. Le credenziali di default "
                            "(admin/admin, tomcat/tomcat) sono spesso ancora attive."
                        ),
                        "attack_scenario": (
                            "1. Nmap o Shodan identificano la porta 8080 aperta sul target.\n"
                            "2. L'attaccante accede a http://target:8080/manager/html.\n"
                            "3. Tenta credenziali di default: admin/admin, tomcat/s3cret.\n"
                            "4. Se autenticato, carica una WAR shell (es. msfvenom -p java/jsp_shell_reverse_tcp).\n"
                            "5. Ottiene una reverse shell con i privilegi dell'utente Tomcat sul sistema."
                        ),
                        "recommendation": (
                            "1. Bloccare la porta 8080 a livello di firewall/security group, "
                            "rendendola accessibile solo da IP di gestione autorizzati.\n"
                            "2. Spostare l'interfaccia di gestione su una rete di management "
                            "separata (VLAN dedicata).\n"
                            "3. Cambiare tutte le credenziali di default e applicare una password "
                            "policy robusta.\n"
                            "4. Aggiornare Tomcat all'ultima versione stabile con patch di sicurezza.\n"
                            "5. Abilitare TLS/HTTPS anche sull'interfaccia di management."
                        ),
                        "evidence": "PORT 8080/tcp OPEN  http  Apache Tomcat 9.0.45",
                        "affected_component": "Apache Tomcat — porta TCP 8080",
                        "port": "8080",
                        "protocol": "tcp",
                        "cwe": ["CWE-284", "CWE-1188"],
                        "cvss_score": 6.8,
                        "tags": ["owasp-a05", "misconfiguration", "exposed-service"],
                        "references": [
                            "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
                            "https://cwe.mitre.org/data/definitions/1188.html",
                            "https://tomcat.apache.org/security.html",
                        ],
                    },
                    {
                        "tool": "nmap",
                        "title": "Server Banner Disclosure — Versione software esposta negli header HTTP",
                        "severity": "low",
                        "description": (
                            "Il server web risponde includendo negli header HTTP la versione "
                            "esatta del software in uso: 'Server: nginx/1.18.0 (Ubuntu)'. "
                            "Questa informazione consente a un attaccante di identificare "
                            "immediatamente il software installato e ricercare vulnerabilità "
                            "specifiche per quella versione nei database CVE pubblici (NVD, "
                            "ExploitDB). Il banner disclosure riduce significativamente il "
                            "costo della ricognizione per un attaccante."
                        ),
                        "impact": (
                            "L'esposizione della versione del server facilita la selezione "
                            "mirata di exploit per vulnerabilità note nella versione identificata. "
                            "Sebbene non costituisca una vulnerabilità direttamente sfruttabile, "
                            "riduce il tempo necessario per un attaccante per trovare un vettore "
                            "di attacco specifico e aumenta la superficie di attacco complessiva."
                        ),
                        "attack_scenario": (
                            "1. L'attaccante invia una semplice richiesta HTTP HEAD al target.\n"
                            "2. Legge l'header 'Server: nginx/1.18.0 (Ubuntu)' nella risposta.\n"
                            "3. Cerca su NVD/ExploitDB le CVE per nginx 1.18.0.\n"
                            "4. Identifica CVE-2021-23017 (1-byte memory overwrite) applicabile.\n"
                            "5. Prepara un exploit mirato per la versione specifica rilevata."
                        ),
                        "recommendation": (
                            "1. Configurare nginx con 'server_tokens off;' nel file nginx.conf "
                            "per rimuovere la versione dall'header Server.\n"
                            "2. Per Apache: impostare 'ServerTokens Prod' e 'ServerSignature Off'.\n"
                            "3. Rimuovere o oscurare l'header X-Powered-By e simili.\n"
                            "4. Mantenere il software aggiornato all'ultima versione stabile "
                            "per ridurre la superficie di attacco nota."
                        ),
                        "evidence": "HTTP/1.1 200 OK\nServer: nginx/1.18.0 (Ubuntu)\nX-Powered-By: PHP/7.4.3",
                        "affected_component": "HTTP Server — header di risposta",
                        "cwe": ["CWE-200"],
                        "cve": ["CVE-2021-23017"],
                        "cvss_score": 3.7,
                        "tags": ["owasp-a05", "information-disclosure", "banner-disclosure"],
                        "references": [
                            "https://cwe.mitre.org/data/definitions/200.html",
                            "https://nginx.org/en/docs/http/ngx_http_core_module.html#server_tokens",
                        ],
                    },
                ],
            }

        if not shutil.which("nmap"):
            return {
                "tool": "nmap",
                "status": "skipped",
                "message": "Tool nmap non installato.",
                "findings": [],
            }

        normalized_target = self._normalize_target(target)
        profile = settings.nmap_profile
        command = self._build_command(normalized_target, profile)

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
                "tool": "nmap",
                "status": "timeout",
                "message": "Timeout durante l'esecuzione di Nmap.",
                "findings": [],
            }

        xml_output = completed.stdout.strip()
        if not xml_output:
            message = completed.stderr.strip() or "Output XML Nmap vuoto."
            return {
                "tool": "nmap",
                "status": "error",
                "message": message,
                "findings": [],
            }

        findings = self._parse_nmap_xml(xml_output)
        status = "executed" if completed.returncode == 0 else "completed_with_warnings"

        return {
            "tool": "nmap",
            "status": status,
            "profile": profile,
            "target": normalized_target,
            "findings": findings,
        }

    def _normalize_target(self, target: str) -> str:
        if "://" in target:
            parsed = urlparse(target)
            return parsed.hostname or target
        return target

    def _build_command(self, target: str, profile: str) -> List[str]:
        base_args = ["nmap", "-sV", "-sC", "-O"]
        profile_args = self._profile_args(profile)
        script_args = self._script_args()
        additional_args = shlex.split(settings.nmap_additional_args)
        return [*base_args, *profile_args, *script_args, *additional_args, "-oX", "-", target]

    def _profile_args(self, profile: str) -> List[str]:
        profiles = {
            "quick": ["-T4", "-F"],
            "service": ["-T4"],
            "full": ["-T4", "-p-"],
            "vuln": ["-T4"],
            "stealth": ["-sS", "-T2", "-Pn"],
        }
        return profiles.get(profile, profiles["quick"])

    def _script_args(self) -> List[str]:
        """Argomenti NSE aggiuntivi. Le sottoclassi (es. rete) li sovrascrivono."""
        return []

    def _parse_nmap_xml(self, xml_output: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        try:
            root = ET.fromstring(xml_output)
        except ET.ParseError:
            return [
                {
                    "title": "Errore parsing XML Nmap",
                    "severity": "low",
                    "description": "Output XML non valido, impossibile analizzare i risultati.",
                    "recommendation": "Verificare la versione di Nmap o rieseguire la scansione.",
                }
            ]

        for host in root.findall("host"):
            status = host.find("status")
            if status is not None and status.get("state") == "down":
                continue
            addresses = [addr.get("addr") for addr in host.findall("address") if addr.get("addr")]
            hostnames = [
                node.get("name") for node in host.findall("hostnames/hostname") if node.get("name")
            ]
            os_matches = [
                {
                    "name": osmatch.get("name"),
                    "accuracy": osmatch.get("accuracy"),
                }
                for osmatch in host.findall("os/osmatch")
                if osmatch.get("name")
            ]
            if os_matches:
                best_match = os_matches[0]
                findings.append(
                    {
                        "title": "OS detection rilevata",
                        "severity": "info",
                        "description": (
                            f"OS probabile: {best_match['name']} "
                            f"(accuratezza {best_match.get('accuracy', 'n/d')}%)."
                        ),
                        "recommendation": "Verificare che l'OS sia aggiornato e supportato.",
                    }
                )

            for port in host.findall("ports/port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue

                service = port.find("service")
                service_name = service.get("name") if service is not None else "sconosciuto"
                product = service.get("product") if service is not None else None
                version = service.get("version") if service is not None else None
                extrainfo = service.get("extrainfo") if service is not None else None
                cpe_list = [cpe.text for cpe in port.findall("service/cpe") if cpe.text]
                banner_parts = [part for part in [product, version, extrainfo] if part]
                banner = " ".join(banner_parts) if banner_parts else "Banner non disponibile"

                port_id = port.get("portid")
                protocol = port.get("protocol")
                host_label = ", ".join(hostnames or addresses) or "host sconosciuto"

                findings.append(
                    {
                        "title": f"Porta aperta {port_id}/{protocol}",
                        "severity": "low",
                        "description": (
                            f"{host_label}: servizio {service_name} ({banner}). "
                            f"CPE: {', '.join(cpe_list) if cpe_list else 'n/d'}."
                        ),
                        "recommendation": "Confermare necessità del servizio e limitare l'esposizione.",
                    }
                )

                self._append_service_risk(findings, service_name, port_id, host_label)
                self._append_script_findings(findings, port, host_label)

        return findings

    def _append_service_risk(
        self, findings: List[Dict[str, Any]], service_name: str, port_id: str | None, host_label: str
    ) -> None:
        hint = VULNERABLE_SERVICE_HINTS.get(service_name)
        if not hint:
            return
        message, severity = hint
        findings.append(
            {
                "title": f"Servizio potenzialmente vulnerabile: {service_name}",
                "severity": severity,
                "description": f"{host_label} (porta {port_id}): {message}",
                "recommendation": "Applicare hardening, patch e restrizioni di accesso.",
            }
        )

    def _append_script_findings(
        self, findings: List[Dict[str, Any]], port: ET.Element, host_label: str
    ) -> None:
        for script in port.findall("script"):
            script_id = script.get("id", "script")
            output = script.get("output", "").strip()
            if not output:
                continue
            cves = sorted({match.upper() for match in CVE_REGEX.findall(output)})
            severity = "medium" if "VULNERABLE" in output.upper() else "info"
            if "vuln" in script_id or "vulners" in script_id:
                severity = "high" if cves else "medium"
            title = f"Risultato script Nmap: {script_id}"
            if cves:
                title += f" — {len(cves)} CVE rilevate"
            finding: Dict[str, Any] = {
                "title": title,
                "severity": severity,
                "description": f"{host_label}: {output}",
                "recommendation": "Analizzare il risultato e applicare le mitigazioni indicate.",
            }
            if cves:
                finding["cve"] = cves
                finding["recommendation"] = (
                    "Verificare le CVE rilevate (vedi enrichment NVD/CVSS/EPSS) e applicare "
                    "patch o aggiornamenti del servizio interessato."
                )
            findings.append(finding)
