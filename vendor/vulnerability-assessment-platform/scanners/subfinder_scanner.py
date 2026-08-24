"""Subfinder scanner wrapper."""
from __future__ import annotations

from dataclasses import dataclass
import json
import shutil
import socket
import subprocess
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

import requests

from config import settings


TAKEOVER_SIGNATURES = {
    "s3.amazonaws.com": "Amazon S3",
    "s3-website": "Amazon S3 Website",
    "cloudfront.net": "Amazon CloudFront",
    "herokuapp.com": "Heroku",
    "github.io": "GitHub Pages",
    "azurewebsites.net": "Azure App Service",
    "trafficmanager.net": "Azure Traffic Manager",
    "cloudapp.net": "Azure CloudApp",
    "pantheonsite.io": "Pantheon",
    "surge.sh": "Surge",
    "fastly.net": "Fastly",
    "readme.io": "Readme",
}


@dataclass
class SubfinderScanner:
    enable_live_scans: bool = False

    def run(self, target: str) -> Dict[str, Any]:
        if not self.enable_live_scans:
            return {
                "tool": "subfinder",
                "status": "simulated",
                "findings": [
                    {
                        "tool": "subfinder",
                        "title": "Subdomain Takeover — Record DNS pendente su risorsa cloud non più attiva",
                        "severity": "high",
                        "description": (
                            "Subfinder ha scoperto il sottodominio 'staging.example.com' con un "
                            "record CNAME che punta a 'example-staging.herokuapp.com', un "
                            "dyno Heroku non più registrato. Il dominio Heroku di destinazione "
                            "risulta disponibile per la registrazione, permettendo a un attaccante "
                            "di registrarlo e ottenere il pieno controllo del sottodominio "
                            "staging.example.com. Questo scenario, noto come Subdomain Takeover, "
                            "è una delle vulnerabilità più critiche in ambito DNS."
                        ),
                        "impact": (
                            "Un attaccante che registra il dominio Heroku puntato può: "
                            "servire contenuti arbitrari da staging.example.com (phishing, "
                            "malware), rubare cookie di sessione condivisi tra sottodomini "
                            "(se il cookie non ha il flag 'domain' ristretto), eseguire attacchi "
                            "Cross-Site Scripting che bypassano le policy Same-Origin, e ottenere "
                            "certificati TLS validi per il sottodominio tramite challenge DNS-01."
                        ),
                        "attack_scenario": (
                            "1. L'attaccante esegue Subfinder e identifica staging.example.com "
                            "→ CNAME → example-staging.herokuapp.com.\n"
                            "2. Verifica che 'example-staging.herokuapp.com' non sia registrato: "
                            "curl -I https://example-staging.herokuapp.com → Error 'No such app'.\n"
                            "3. Registra gratuitamente 'example-staging' su Heroku.\n"
                            "4. Carica un'app che risponde per staging.example.com con contenuto "
                            "fraudolento (fake login, cookie stealer).\n"
                            "5. Utenti che visitano staging.example.com vengono compromessi."
                        ),
                        "recommendation": (
                            "1. Rimuovere immediatamente il record CNAME pendente da staging.example.com.\n"
                            "2. Eseguire un audit completo di tutti i record DNS per identificare "
                            "altri CNAME/A record che puntano a risorse non più attive.\n"
                            "3. Implementare un processo di decommissioning che preveda la "
                            "rimozione dei record DNS prima del rilascio delle risorse cloud.\n"
                            "4. Monitorare periodicamente tutti i sottodomini con strumenti come "
                            "can-i-take-over-xyz o nuclei template dns-subdomain-takeover.\n"
                            "5. Utilizzare DMARC, SPF e DKIM per proteggere il dominio principale "
                            "da spoofing via sottodomini compromessi."
                        ),
                        "evidence": "staging.example.com. CNAME example-staging.herokuapp.com. → HTTP 404 'No such app'",
                        "affected_component": "DNS — CNAME record staging.example.com",
                        "host": "staging.example.com",
                        "cwe": ["CWE-350"],
                        "cvss_score": 8.1,
                        "tags": ["owasp-a05", "subdomain-takeover", "dns"],
                        "references": [
                            "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
                            "https://github.com/EdOverflow/can-i-take-over-xyz",
                            "https://cwe.mitre.org/data/definitions/350.html",
                        ],
                    },
                    {
                        "tool": "subfinder",
                        "title": "Ambiente di sviluppo accessibile pubblicamente — dev.example.com esposto",
                        "severity": "medium",
                        "description": (
                            "Subfinder ha identificato il sottodominio 'dev.example.com' attivo "
                            "e raggiungibile pubblicamente. L'ambiente di sviluppo espone "
                            "funzionalità non ancora approvate per la produzione, file di "
                            "configurazione con debug mode attivo, endpoint di test non "
                            "autenticati e potenzialmente credenziali hardcoded nei sorgenti "
                            "accessibili. L'interfaccia web mostra stack trace completi per "
                            "qualsiasi errore applicativo."
                        ),
                        "impact": (
                            "Gli ambienti di sviluppo contengono tipicamente credenziali di "
                            "database, chiavi API e segreti di configurazione diversi ma spesso "
                            "simili a quelli di produzione. L'accesso all'ambiente dev può "
                            "rivelare logiche di business non documentate, vulnerabilità non "
                            "ancora risolte e informazioni strutturali sull'architettura "
                            "dell'applicazione di produzione."
                        ),
                        "attack_scenario": (
                            "1. L'attaccante scopre dev.example.com tramite enumerazione DNS.\n"
                            "2. Accede all'applicazione con debug mode attivo, leggendo stack trace.\n"
                            "3. Identifica path interni, nomi di moduli e librerie utilizzate.\n"
                            "4. Trova endpoint /debug/config che espone variabili d'ambiente.\n"
                            "5. Utilizza chiavi API di sviluppo trovate per accedere a servizi "
                            "cloud condivisi con l'ambiente di produzione."
                        ),
                        "recommendation": (
                            "1. Rendere dev.example.com accessibile solo dalla rete aziendale "
                            "tramite VPN o IP allowlist.\n"
                            "2. Disabilitare il debug mode in tutti gli ambienti non-development "
                            "e assicurarsi che le credenziali dev/prod siano completamente separate.\n"
                            "3. Implementare autenticazione HTTP Basic o OAuth come protezione "
                            "aggiuntiva dell'ambiente di sviluppo.\n"
                            "4. Rimuovere endpoint di debug e diagnostica prima dell'esposizione "
                            "anche parziale all'esterno."
                        ),
                        "evidence": "dev.example.com → HTTP 200 OK (DEBUG=True, Stack Trace visibile)",
                        "affected_component": "Ambiente di sviluppo — dev.example.com",
                        "host": "dev.example.com",
                        "cwe": ["CWE-215", "CWE-1244"],
                        "cvss_score": 5.3,
                        "tags": ["owasp-a05", "information-disclosure", "misconfiguration"],
                        "references": [
                            "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
                            "https://cwe.mitre.org/data/definitions/215.html",
                        ],
                    },
                ],
            }

        domain = self._normalize_domain(target)
        sources: Dict[str, Any] = {"subfinder": 0, "securitytrails": 0, "virustotal": 0, "shodan": 0}
        errors: List[str] = []
        subdomains: Set[str] = set()

        if shutil.which("subfinder"):
            found, error = self._run_subfinder(domain)
            subdomains.update(found)
            sources["subfinder"] = len(found)
            if error:
                errors.append(error)
        else:
            errors.append("Tool subfinder non installato: uso solo integrazioni API.")

        external_subdomains, external_errors = self._collect_external_subdomains(domain)
        for key, value in external_subdomains.items():
            subdomains.update(value)
            sources[key] = len(value)
        errors.extend(external_errors)

        if not subdomains:
            return {
                "tool": "subfinder",
                "status": "completed_with_warnings" if errors else "executed",
                "target": domain,
                "message": "Nessun sottodominio rilevato.",
                "errors": errors,
                "findings": [],
            }

        resolved, unresolved = self._resolve_subdomains(sorted(subdomains))
        takeover_candidates = self._detect_takeovers(unresolved)

        findings = [
            {
                "title": "Sottodomini individuati",
                "severity": "info",
                "description": (
                    f"Trovati {len(subdomains)} sottodomini per {domain}. "
                    f"Risolti: {len(resolved)} | Non risolti: {len(unresolved)}."
                ),
                "recommendation": "Verificare la necessità degli asset esposti e consolidare i DNS.",
            }
        ]

        if unresolved:
            findings.append(
                {
                    "title": "Sottodomini non risolti",
                    "severity": "low",
                    "description": "Alcuni sottodomini non risolvono correttamente.",
                    "recommendation": "Rimuovere record obsoleti o correggere la configurazione DNS.",
                }
            )

        if takeover_candidates:
            findings.append(
                {
                    "title": "Potenziali takeover di sottodominio",
                    "severity": "high",
                    "description": (
                        "Rilevati record CNAME verso provider noti senza risoluzione attiva."
                    ),
                    "recommendation": "Verificare la proprietà del servizio o rimuovere i record CNAME.",
                }
            )

        if errors:
            findings.append(
                {
                    "title": "Avvisi integrazione Subfinder/API",
                    "severity": "low",
                    "description": "Alcune fonti non hanno risposto correttamente.",
                    "recommendation": "Verificare le API key e ripetere la scansione.",
                }
            )

        status = "executed" if not errors else "completed_with_warnings"
        return {
            "tool": "subfinder",
            "status": status,
            "target": domain,
            "sources": sources,
            "errors": errors,
            "subdomains": sorted(subdomains),
            "resolved": resolved,
            "unresolved": unresolved,
            "takeover_candidates": takeover_candidates,
            "export_targets": sorted(resolved.keys()),
            "findings": findings,
        }

    def _normalize_domain(self, target: str) -> str:
        if "://" in target:
            parsed = urlparse(target)
            return parsed.hostname or target
        return target.split("/")[0]

    def _run_subfinder(self, domain: str) -> Tuple[Set[str], Optional[str]]:
        command = ["subfinder", "-d", domain, "-json"]
        if settings.subfinder_sources:
            command.extend(["-sources", settings.subfinder_sources])
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=settings.scan_timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return set(), "Timeout durante l'esecuzione di Subfinder."

        if completed.returncode != 0 and not completed.stdout:
            return set(), (completed.stderr.strip() or "Errore durante Subfinder.")

        subdomains = set()
        for line in completed.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            host = payload.get("host") or payload.get("hostname")
            if host:
                subdomains.add(host.lower())
        return subdomains, None

    def _collect_external_subdomains(self, domain: str) -> Tuple[Dict[str, Set[str]], List[str]]:
        results: Dict[str, Set[str]] = {"securitytrails": set(), "virustotal": set(), "shodan": set()}
        errors: List[str] = []

        if settings.securitytrails_api_key:
            subdomains, error = self._query_securitytrails(domain)
            results["securitytrails"] = subdomains
            if error:
                errors.append(error)

        if settings.virustotal_api_key:
            subdomains, error = self._query_virustotal(domain)
            results["virustotal"] = subdomains
            if error:
                errors.append(error)

        if settings.shodan_api_key:
            subdomains, error = self._query_shodan(domain)
            results["shodan"] = subdomains
            if error:
                errors.append(error)

        return results, errors

    def _query_securitytrails(self, domain: str) -> Tuple[Set[str], Optional[str]]:
        url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
        headers = {"APIKEY": settings.securitytrails_api_key}
        try:
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            payload = response.json()
        except requests.RequestException as exc:
            return set(), f"SecurityTrails: {exc}"
        except ValueError:
            return set(), "SecurityTrails: risposta JSON non valida."

        subdomains = {
            f"{sub}.{domain}".lower()
            for sub in payload.get("subdomains", [])
            if isinstance(sub, str)
        }
        return subdomains, None

    def _query_virustotal(self, domain: str) -> Tuple[Set[str], Optional[str]]:
        url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=200"
        headers = {"x-apikey": settings.virustotal_api_key}
        try:
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            payload = response.json()
        except requests.RequestException as exc:
            return set(), f"VirusTotal: {exc}"
        except ValueError:
            return set(), "VirusTotal: risposta JSON non valida."

        subdomains = {
            item.get("id", "").lower()
            for item in payload.get("data", [])
            if isinstance(item, dict) and item.get("id")
        }
        return subdomains, None

    def _query_shodan(self, domain: str) -> Tuple[Set[str], Optional[str]]:
        url = f"https://api.shodan.io/dns/domain/{domain}?key={settings.shodan_api_key}"
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            payload = response.json()
        except requests.RequestException as exc:
            return set(), f"Shodan: {exc}"
        except ValueError:
            return set(), "Shodan: risposta JSON non valida."

        subdomains = {
            f"{sub}.{domain}".lower()
            for sub in payload.get("subdomains", [])
            if isinstance(sub, str)
        }
        return subdomains, None

    def _resolve_subdomains(self, subdomains: List[str]) -> Tuple[Dict[str, List[str]], List[str]]:
        socket.setdefaulttimeout(3)
        limit = settings.subfinder_resolve_limit
        resolved: Dict[str, List[str]] = {}
        unresolved: List[str] = []

        for subdomain in subdomains[:limit]:
            try:
                _, _, addresses = socket.gethostbyname_ex(subdomain)
                if addresses:
                    resolved[subdomain] = addresses
                else:
                    unresolved.append(subdomain)
            except socket.gaierror:
                unresolved.append(subdomain)

        return resolved, unresolved

    def _detect_takeovers(self, unresolved: List[str]) -> List[Dict[str, str]]:
        candidates: List[Dict[str, str]] = []
        for subdomain in unresolved:
            cname = self._lookup_cname(subdomain)
            if not cname:
                continue
            provider = self._match_takeover_provider(cname)
            if provider:
                candidates.append(
                    {
                        "subdomain": subdomain,
                        "cname": cname,
                        "provider": provider,
                    }
                )
        return candidates

    def _lookup_cname(self, hostname: str) -> Optional[str]:
        if shutil.which("dig"):
            try:
                output = subprocess.run(
                    ["dig", "+short", "CNAME", hostname],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                ).stdout
            except subprocess.TimeoutExpired:
                return None
            cname = output.strip().splitlines()
            return cname[0].strip().rstrip(".") if cname else None

        if shutil.which("nslookup"):
            try:
                output = subprocess.run(
                    ["nslookup", "-type=CNAME", hostname],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                ).stdout
            except subprocess.TimeoutExpired:
                return None
            for line in output.splitlines():
                if "canonical name" in line:
                    return line.split("=", maxsplit=1)[-1].strip().rstrip(".")

        return None

    def _match_takeover_provider(self, cname: str) -> Optional[str]:
        cname_lower = cname.lower()
        for signature, provider in TAKEOVER_SIGNATURES.items():
            if signature in cname_lower:
                return provider
        return None
