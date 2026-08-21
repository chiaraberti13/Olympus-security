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

## 🔜 To do — W1 First value
### Argus (🔴 OSINT)
- [x] T-101 `argus scan --domain` recon passiva DNS/MX/SPF/DMARC — done: test + fixture
- [x] T-102 Certificate Transparency + sottodomini passivi — done: test su fixture offline
- [x] T-103 Export `argus-assets.json` conforme a core.Asset — done: round-trip validato
- [x] T-104 Change monitoring (diff tra due snapshot) — done: test diff
- [x] T-105 README modulo bilingue + `argus demo` reale — done: demo esce 0

### Hermes (🔵 Secret scanner)
- [x] T-111 Motore regex + prefissi noti (AWS, GitHub, JWT...) — done: test veri/falsi positivi
- [x] T-112 Motore entropia + soglia configurabile — done: test
- [x] T-113 Scan della history Git — done: test su repo fixture
- [x] T-114 Output SARIF valido + mascheramento del secret — done: struttura SARIF validata
- [x] T-115 Hook pre-commit + README bilingue + `hermes demo` — done: demo esce 0

## 🔜 To do — W2 Surface & detection
### Core contract
- [x] T-201 `core.models` Event, Evidence e Alert + export JSON Schema — done: round-trip validato

### Helios (🔴 Surface mapping)
- [x] T-202 Scope CIDR/host con blocco e audit log fuori perimetro — done: test IPv4/IPv6
- [x] T-203 Discovery TCP non distruttiva con timeout e limiti — done: connector offline iniettato
- [x] T-204 Export `helios-findings.json` conforme a core.Finding — done: round-trip validato
- [x] T-205 README bilingue + `helios demo` sintetico — done: demo esce 0

### Apollo (🔵 Detection engineering)
- [x] T-211 Parser regole YAML sicuro + schema rule — done: YAML reale, fixture valida/non valida
- [x] T-212 Mapping MITRE ATT&CK e validazione ID tecnica — done: test
- [x] T-213 Detection testing Event → Alert — done: veri/falsi positivi
- [x] T-214 Export alert conforme a core.Alert — done: round-trip validato
- [x] T-215 README bilingue + `apollo demo` sintetico — done: demo esce 0

## 🔜 To do — W3 Web, response & reporting
### Core contract
- [x] T-301 `core.models.Incident` + lifecycle + export JSON Schema — done: round-trip validato

### Minerva (🔵 IR/DFIR)
- [x] T-302 Chain of custody append-only per core.Evidence + demo bilingue — done: tamper test
- [x] T-303 Triage deterministico Alert → Incident + export core.Incident — done: round-trip CLI

### Artemis (🔴 Web recon)
- [x] T-304 Scope URL/origin/path obbligatorio + blocco audit + demo bilingue — done: zero rete
- [x] T-305 HTTP GET-only iniettabile + redirect scoped + timeout/size cap — done: transport offline
- [x] T-306 DNS pinning + allowlist CIDR per ogni hop HTTP(S) — done: IPv4/IPv6 offline
- [x] T-307 Fingerprinting tecnologico passivo ispirato a dismap, con conferma autorizzazione
  prima della rete — done: firme header/body, export Finding e test CLI offline

## ⏳ Backlog — resto W3 e W4
Resto Artemis/Minerva, Proteus, Vulcan e Mars sarà scomposto dopo T-307 (vedi PLAN.md).

## ✅ Done — extra
- [x] T-921 Apollo: pack `apollo-redteam` (RedTeam-Tools, tattiche MITRE non coperte da
  apollo-ad/apollo-blueteam: Discovery, Lateral Movement, Collection, C2, Exfiltration,
  Impact) — done: 4 test, `make check` verde
- [x] T-922 Mars: scenario purple end-to-end (`mars-post-exploitation.ndjson`) — traccia di
  eventi sintetici che riproduce cosa produrrebbe un endpoint compromesso da tecniche stile
  KLogger/symbiote, rilevata da `apollo-redteam` (mai una cattura reale) — done: 3 test,
  `make check` verde
- [x] T-923 Argus accounts: metadati profilo TikTok estesi (following, like, video, avatar,
  verificato) — stessi campi di TokIntel via GET onesta sulla pagina pubblica, nessuna chiave
  a pagamento — done: 2 test, `make check` verde

## 🔁 Generati da ERRORS.md / Generated from ERRORS.md
- [ ] T-903 Isolare il log bloccati del test CLI account Argus per mantenere il working tree
  stabile dopo `make check` (ERR-2026-08-20-01)
- [x] T-901 Ripristinare il gate coverage installando le dipendenze dev e rieseguire `make check`
  (ERR-2026-08-14-01) — done: coverage ≥ 90% verificata
- [x] T-902 Correggere il falso supporto YAML di Apollo (ERR-2026-08-14-11) — done: parser
  YAML ristretto testato contro tag/costruttori
