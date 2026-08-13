# TASKS — Olympus Security

> Un task alla volta. Spunta SOLO se `make check` è verde e il criterio è soddisfatto.
> One task at a time. Tick ONLY if `make check` is green and the criterion is met.

## ✅ Done — W0 Foundations
- [x] T-000 Scaffold monorepo + pyproject + CI + gate configurati
- [x] T-001 core.enums (Severity, FindingStatus, Criticality, AssetType, Source)
- [x] T-002 core.ids (IdGenerator + new_id, formato PREFIX-YYYY-NNNNN)
- [x] T-003 core.models (Asset, Finding) con schema_name/version + extra=forbid
- [x] T-004 core.errors (ValidationReport: to_human + to_dict)
- [x] T-005 CLI unico `olympus <tool> <cmd>` + core export-schemas
- [x] T-006 Test unit core + CLI, coverage ≥ 90% (attuale 98.7%)

## ✅ Done — W1 First value
### Argus (🔴 OSINT)
- [x] T-101 `argus scan --domain` recon passiva DNS/MX/SPF/DMARC — done: test + fixture
- [x] T-102 Certificate Transparency + sottodomini passivi — done: test su fixture offline
- [x] T-103 Export `argus-assets.json` conforme a core.Asset — done: round-trip validato
- [x] T-104 Change monitoring (diff tra due snapshot) — done: test diff
- [x] T-105 README modulo bilingue + `argus demo` reale — done: demo esce 0

### Hermes (🔵 Secret scanner)
- [x] T-111 Motore regex + prefissi noti (AWS, GitHub, JWT...) — done: test veri/falsi positivi
- [x] T-112 Motore entropia + soglia configurabile — done: test
      (regressione risolta: ERR-2026-08-11-06, test demo isolato da esempio tracciato)
- [x] T-113 Scan della history Git — done: test su repo fixture
- [x] T-114 Output SARIF valido + mascheramento del secret — done: schema SARIF validato
- [x] T-115 Hook pre-commit + README bilingue + `hermes demo` — done: demo esce 0

## ✅ Done — W2 Surface & detection
### Core (⚙️ Alert/Event/Evidence)
- [x] T-120 core.models Event/Alert/Evidence + core.ids prefisso "event" — done: test + export-schemas

### Helios (🔴 Network attack-surface mapper)
- [x] T-121 `helios scan` — motore TCP connect + profilo porte comuni, PortScanner iniettabile
      — done: test su scanner fake offline
- [x] T-122 Scope file obbligatorio (host/CIDR) + blocco+log fuori scope — done: test
- [x] T-123 Export `helios-findings.json` (Asset per host + Finding per porta aperta)
      conforme a core — done: round-trip validato
- [x] T-124 Alert per servizi esposti ad alto rischio (porte critiche) — done: test
- [x] T-125 README modulo bilingue + `helios demo` reale — done: demo esce 0

### Apollo (🔵 Detection engineering)
- [x] T-131 Schema regole YAML + mapping MITRE ATT&CK + loader — done: test regole valide/invalide
- [x] T-132 Motore di match regole su core.Event — done: test veri/falsi positivi
- [x] T-133 Generazione Alert da regola scattata (con evidence linking) — done: test
- [x] T-134 Harness di detection testing (regola + eventi sintetici etichettati) — done: test
- [x] T-135 README modulo bilingue + `apollo demo` reale — done: demo esce 0

## 🔜 To do — W3 Web, response, reporting
### Core (⚙️ Incident)
- [x] T-140 core.models Incident (lifecycle NEW→TRIAGED→CONTAINED→RESOLVED→CLOSED)
      — done: test + export-schemas

### Artemis (🔴 Web recon)
- [x] T-141 HttpClient iniettabile (protocol + adapter urllib) — done: test su client fake offline
- [x] T-142 Analisi header di sicurezza (CSP/HSTS/X-Frame-Options/...) → Finding — done: test
- [x] T-143 Rilevamento CORS misconfigurato (wildcard+credentials, origin riflessa) → Finding
      — done: test
- [ ] T-144 Content discovery (path comuni esposti: .git, .env, admin...) + scope obbligatorio
      con blocco+log — done: test
- [ ] T-145 README modulo bilingue + `artemis demo` reale — done: demo esce 0

### Minerva (🔵 IR/DFIR)
- [ ] T-151 Apertura incidente: aggrega Alert/Finding in un core.Incident — done: test
- [ ] T-152 Chain of custody: log evidenze append-only con hash-chain a prova di manomissione
      — done: test rilevamento manomissione
- [ ] T-153 Transizioni di stato dell'incidente (macchina a stati, transizioni invalide rifiutate)
      — done: test transizioni valide/invalide
- [ ] T-154 Export/import report incidente conforme a core.Incident — done: round-trip validato
- [ ] T-155 README modulo bilingue + `minerva demo` reale — done: demo esce 0

### Proteus (🔴 Phishing sim, mai credenziali reali)
- [ ] T-161 Generatore campagna simulata (destinatari sintetici, nessun invio email reale)
      — done: test
- [ ] T-162 Pagina di training statica (mai raccolta credenziali) + tracking click simulato
      — done: test
- [ ] T-163 Scope/allowlist destinatari obbligatoria + blocco+log fuori scope — done: test
- [ ] T-164 Export report campagna (Finding per destinatario) conforme a core — done: round-trip
      validato
- [ ] T-165 README modulo bilingue + `proteus demo` reale — done: demo esce 0

### Vulcan (🟣 Aggregazione + report pentest)
- [ ] T-171 Aggregazione Asset/Finding/Alert da export multipli con deduplica — done: test
- [ ] T-172 Scoring/ordinamento per rischio (CVSS + severità) — done: test
- [ ] T-173 Generazione report di pentest (Markdown) da dati aggregati — done: test struttura
- [ ] T-174 Export `vulcan-report.json` conforme a core — done: round-trip validato
- [ ] T-175 README modulo bilingue + `vulcan demo` reale — done: demo esce 0

## ⏳ Backlog — W4
Mars (vedi PLAN.md).

## 🔁 Generati da ERRORS.md / Generated from ERRORS.md
- (nessuno aperto / none open)
