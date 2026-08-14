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

## ⏳ Backlog — W3..W4
Artemis, Minerva, Proteus, Vulcan, Mars (vedi PLAN.md).

## 🔁 Generati da ERRORS.md / Generated from ERRORS.md
- [x] T-901 Ripristinare il gate coverage installando le dipendenze dev e rieseguire `make check`
  (ERR-2026-08-14-01) — done: coverage ≥ 90% verificata
- [x] T-902 Correggere il falso supporto YAML di Apollo (ERR-2026-08-14-11) — done: parser
  YAML ristretto testato contro tag/costruttori
