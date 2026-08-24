# AEGIS 24-scanner dependency & execution matrix

_Generated from `olympus.integrations.scanners` (the Olympus-native registry that drives `olympus aegis scanners --check` / `deps` / `doctor`)._

> **Default mode is simulated.** Each scanner returns hard-coded educational findings unless `VAP_ENABLE_LIVE_SCANS=true`, the binary/API below is present, and the target is authorized/in-scope. 'Executed here' therefore refers to *live* execution in this sandbox, which had no scanner binaries and no Docker daemon — so live execution is **not executable here** for every scanner and must be reproduced with `docker-compose.scanners.yml` or the vendored `installer.sh`.

| Scanner | Category | Purpose | Binary / API | Licence | Redistributable | Install method | In scanner image | Executed live here | Fallback when unavailable |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| subfinder | dns | Passive subdomain enumeration | `subfinder` | MIT | yes | go install github.com/projectdiscovery/subfinder | yes | not executable here | simulated findings + graceful 'tool not installed' |
| theharvester | dns | OSINT email/subdomain harvesting | `theHarvester` | GPL-2.0 | yes | pip install theHarvester | yes | not executable here | simulated findings + graceful 'tool not installed' |
| nmap | network | Network port & service enumeration | `nmap` | GPL-2.0 | yes | apt-get install nmap | yes | not executable here | simulated findings + graceful 'tool not installed' |
| testssl | tls | TLS/SSL configuration analysis | `testssl.sh` | GPL-2.0 | yes | git clone testssl.sh | yes | not executable here | simulated findings + graceful 'tool not installed' |
| nessus | vuln | Tenable Nessus vulnerability scan | `API/daemon` | Commercial (Tenable) | no (manual/commercial) | Manual install + licence (API-driven) | no (API/commercial) | not executable here | simulated findings + graceful 'tool not installed' |
| openvas | vuln | OpenVAS/GVM network vulnerability scan | `API/daemon` | GPL-2.0 | yes | Greenbone GVM stack (heavy; docker/manual, API-driven) | no (API/commercial) | not executable here | simulated findings + graceful 'tool not installed' |
| acunetix | web | Invicti/Acunetix DAST | `API/daemon` | Commercial (Invicti) | no (manual/commercial) | Manual install + licence (API-driven) | no (API/commercial) | not executable here | simulated findings + graceful 'tool not installed' |
| arjun | web | HTTP parameter discovery | `arjun` | AGPL-3.0 | yes | pip install arjun | yes | not executable here | simulated findings + graceful 'tool not installed' |
| burp | web | PortSwigger Burp Suite (Pro API) | `API/daemon` | Commercial (PortSwigger) | no (manual/commercial) | Manual install + licence (API-driven) | no (API/commercial) | not executable here | simulated findings + graceful 'tool not installed' |
| commix | web | Command-injection detection | `commix` | GPL-3.0 | yes | pip install commix (VAP_COMMIX_PATH) | yes | not executable here | simulated findings + graceful 'tool not installed' |
| dalfox | web | XSS scanning/parameter analysis | `dalfox` | MIT | yes | go install github.com/hahwul/dalfox | yes | not executable here | simulated findings + graceful 'tool not installed' |
| dirsearch | web | Content/path discovery | `dirsearch` | GPL-2.0 | yes | pip install dirsearch (VAP_DIRSEARCH_PATH) | yes | not executable here | simulated findings + graceful 'tool not installed' |
| httpx | web | Fast HTTP probing/toolkit | `httpx` | MIT | yes | go install github.com/projectdiscovery/httpx | yes | not executable here | simulated findings + graceful 'tool not installed' |
| katana | web | Crawling / endpoint discovery | `katana` | MIT | yes | go install github.com/projectdiscovery/katana | yes | not executable here | simulated findings + graceful 'tool not installed' |
| nikto | web | Web server misconfiguration scan | `nikto` | GPL-2.0 | yes | apt-get install nikto | yes | not executable here | simulated findings + graceful 'tool not installed' |
| nosqlmap | web | NoSQL injection detection | `nosqlmap` | GPL-3.0 | yes | git clone NoSQLMap | yes | not executable here | simulated findings + graceful 'tool not installed' |
| nuclei | web | Template-based vulnerability scan | `nuclei` | MIT | yes | go install github.com/projectdiscovery/nuclei | yes | not executable here | simulated findings + graceful 'tool not installed' |
| sqlmap | web | SQL injection detection/exploitation | `sqlmap` | GPL-2.0 | yes | pip install sqlmap (VAP_SQLMAP_PATH) | yes | not executable here | simulated findings + graceful 'tool not installed' |
| wafw00f | web | WAF detection | `wafw00f` | BSD-3-Clause | yes | pip install wafw00f | yes | not executable here | simulated findings + graceful 'tool not installed' |
| wapiti | web | Web application vulnerability scan | `wapiti` | GPL-2.0 | yes | pip install wapiti3 (VAP_WAPITI_PATH) | yes | not executable here | simulated findings + graceful 'tool not installed' |
| whatweb | web | Web technology fingerprinting | `whatweb` | GPL-3.0 | yes | apt-get install whatweb | yes | not executable here | simulated findings + graceful 'tool not installed' |
| wpscan | web | WordPress vulnerability scan | `wpscan` | WPScan Public Source (non-OSI) | no (manual/commercial) | gem install wpscan (free token required for the vuln DB) | yes | not executable here | simulated findings + graceful 'tool not installed' |
| xsstrike | web | XSS detection | `xsstrike` | GPL-3.0 | yes | git clone XSStrike (VAP_XSSTRIKE_PATH) | yes | not executable here | simulated findings + graceful 'tool not installed' |
| zap | web | OWASP ZAP DAST (API/daemon) | `API/daemon` | Apache-2.0 | yes | OWASP ZAP daemon / docker image (API-driven) | no (API/commercial) | not executable here | simulated findings + graceful 'tool not installed' |

**Totals:** 24 scanners — 20 redistributable (OSS), 4 commercial/non-OSI; 19 bundled by `docker/Dockerfile.scanners`, 5 API/commercial requiring manual install.

## Component using each scanner

All 24 are used by the **AEGIS** component (`olympus aegis`, vendored VAP `scanner_engine.py` + `scanners/*_scanner.py`).

## Unavailable-tool policy

For any scanner whose binary/API is missing, AEGIS: (1) keeps the complete integration; (2) the vendored scanner checks `shutil.which(...)`/API reachability and returns a clear unavailable state; (3) `olympus aegis deps` and `olympus aegis doctor` surface availability and versions; (4) never reports simulated output as a real live scan. Commercial engines (nessus, burp, acunetix) and heavy/daemon engines (openvas, zap) require manual install + licence/API configuration via their `VAP_*` settings.

