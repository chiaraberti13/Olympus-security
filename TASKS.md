# TASKS — Olympus Security

> Un task alla volta. Spunta SOLO se `make check` è verde e il criterio è soddisfatto.
> One task at a time. Tick ONLY if `make check` is green and the criterion is met.

> 🇮🇹 Storico W0–W4 (release `1.0.0`, 55 task T-000..T-185, tutti chiusi) rimosso da questo
> file: cronologia completa in [CHANGELOG.md](CHANGELOG.md). Da qui in poi solo backlog di
> potenziamento per modulo, non ancora iniziato.
> 🇬🇧 W0–W4 history (release `1.0.0`, 55 tasks T-000..T-185, all closed) removed from this
> file: full history in [CHANGELOG.md](CHANGELOG.md). From here on, per-module enhancement
> backlog only, not started yet.

## ✅ Fatto — Integrazione fonti esterne / External sources integrated
> Concetti da progetti esterni reimplementati nella disciplina Olympus (scope+block+log,
> adapter dormienti, consenso esplicito, nessuna evasione, nessun exploit). Dettagli e
> motivazioni in [SECURITY.md](SECURITY.md).
- [x] T-230 Argus **phone OSINT**: parsing offline `phonenumbers` + enrichment reale dormiente
      (Numverify/breach-intel/messaging) — da SearchPhone + WhatsApp-OSINT
- [x] T-231 Argus **account enumeration**: presenza + metadati pubblici su siti curati, senza
      evasione TLS/proxy — da user-scanner
- [x] T-232 Apollo **regola Metabase SQLi** `/api/session/reset_password` (CVE-2026-72898,
      MITRE T1190) + detection test — da GHSA-vwf4-m7j8-wcjf
- [x] T-233 Artemis **check esposizione Metabase** (CVE-2026-72898), fingerprint versione non
      -exploitativo → Finding CRITICAL con rimedio — da GHSA-vwf4-m7j8-wcjf
- [x] T-234 core: `AssetType.PHONE`/`ACCOUNT` + `core.http` HTTP client condiviso (User-Agent
      onesto, nessuna impersonazione)
- [x] T-235 `SECURITY.md`: fonti curate + esclusione esplicita di hackingtool (DDoS/RAT/
      payload/evasion fuori dai limiti di Olympus)

## 🕓 Proposto — Argus (🔴 OSINT)
- [ ] T-201 WHOIS/ASN passivo (ownership IP/dominio) come fonte OSINT aggiuntiva best-effort
- [ ] T-202 Fingerprint tecnologico passivo via header HTTP (server/framework), no probing attivo

## 🕓 Proposto — Hermes (🔵 Secret scanner)
- [ ] T-203 Nuovi pattern/prefissi secret provider (Slack, Stripe, GCP service account...)
- [ ] T-204 Merge dell'output SARIF con altri tool di scansione per report unificato

## 🕓 Proposto — Helios (🔴 Network attack-surface mapper)
- [ ] T-205 Banner/service fingerprinting opzionale sulle porte aperte (best-effort)

## 🕓 Proposto — Apollo (🔵 Detection engineering)
- [ ] T-206 Regola MITRE T1110.003 (Password Spraying)
- [ ] T-207 Regola MITRE T1595 (Active Scanning)
- [ ] T-208 Regola MITRE T1071 (C2 su porte comuni)
- [ ] T-209 Regola MITRE T1078 (Valid Accounts anomaly)

## 🕓 Proposto — Artemis (🔴 Web recon)
- [ ] T-210 Controlli header aggiuntivi (Permissions-Policy, Referrer-Policy) → Finding
- [ ] T-211 Lista path di content discovery estesa (backup, config framework comuni)

## 🕓 Proposto — Minerva (🔵 IR/DFIR)
- [ ] T-212 Export report incidente in formati aggiuntivi oltre al JSON conforme a core

## 🕓 Proposto — Proteus (🔴 Phishing sim, mai credenziali reali)
- [ ] T-213 Più varianti di template campagna/training page, senza raccolta credenziali reale

## 🕓 Proposto — Vulcan (🟣 Aggregazione + report pentest)
- [ ] T-214 Export HTML del pentest report (riuso `aggregate.py`/`risk.py`)
- [ ] T-215 Filtro severità minima configurabile da CLI per il report

## 🕓 Proposto — Mars (🟣 Cyber range + scenari purple)
- [ ] T-216 Verifica opzionale in CI con daemon Docker disponibile (self-hosted runner)
- [ ] T-217 Segmentazione di rete aggiuntiva nel range (oltre alla singola rete `dmz`)

## 🕓 Proposto — Cross-cutting / DevEx
- [ ] T-218 CI matrix multi-Python (3.11/3.12) in `.github/workflows/ci.yml`
- [ ] T-219 Badge di stato CI nel `README.md`
- [ ] T-220 Packaging: pubblicazione del pacchetto (build già riproducibile)
- [ ] T-221 Timeout/rate-limit configurabili da CLI per i client di rete (Argus CT, Artemis
      HttpClient)

## ⏸️ Rinviato (nota, non task) / Deferred (note, not a task)
Dashboard web, DB persistente, layer API/autenticazione — nessun problema reale da risolvere
oggi, vedi `PLAN.md` § Anti-over-engineering. Nessun task aperto per questi finché non emerge
una necessità concreta.

## 🔁 Generati da ERRORS.md / Generated from ERRORS.md
- (nessuno aperto / none open)
