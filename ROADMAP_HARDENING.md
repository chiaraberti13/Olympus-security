# Olympus Security — roadmap: correzioni, potenziamenti e nuovi tool

Baseline: `main@8a9cc70` (206 commit · 13 moduli CLI + `core` + `tui` · versione `0.2.0`).

Registro operativo del lavoro. Una voce si spunta solo quando **codice, test e documentazione**
sono presenti e i controlli CI pertinenti sono verdi. Le funzionalità parziali restano non spuntate.

Ordine del documento, pensato per essere azionabile:

1. **Correzioni** — cosa non torna o è a metà, da sistemare.
2. **Potenziamenti** — rendere più forti i moduli che già esistono.
3. **Nuovi tool** — cosa aggiungere all'ecosistema e come.
4. **Regole configurabili** — bound di esecuzione e profilo lab editabili da un unico file.
5. **Hardening residuo** — voci della roadmap precedente non assorbite da §1–§4.
6. **Definition of Done** + **Registro avanzamento**.

## Legenda

- `[ ]` da fare · `[x]` fatto e verificato
- Priorità: `P0` sicurezza · `P1` affidabilità · `P2` supply chain · `P3` qualità/prodotto

---

# 1 — Correzioni (grounded sul codice attuale)

## 1.1 — Adapter scanner incompleti (il buco più grande)

Il registro `src/olympus/integrations/scanners.py` dichiara **24 scanner**, ma in
`src/olympus/aegis/adapters/` esistono solo **6 adapter nativi**: `nikto`, `nmap`,
`sqlmap`, `testssl`, `wafw00f`, `whatweb`. Gli altri 18 sono a catalogo ma non eseguibili
nativamente. Inoltre `testssl` e `whatweb` hanno solo il parser, non il test live.

- [ ] `P1` Completare i 18 adapter mancanti (dettaglio in §3.1).
- [ ] `P1` Test live autorizzati per `whatweb` e `testssl` (oggi "parser only").
- [ ] `P1` `olympus aegis capabilities` deve esporre lo stato reale per ogni scanner
      (`catalog-only` / `adapter-ready` / `offline-tested` / `live-tested` / `production-ready`),
      così il catalogo non promette più di quel che esegue.

## 1.2 — Coerenza README ↔ realtà

- [ ] `P3` Il README parla di "native ARGUS and AEGIS" come se AEGIS fosse completo, ma la
      migrazione dal VAP vendored è ancora in corso (`aegis serve/migrate/workers` richiedono
      ancora `vendor/`). Allineare il testo allo stato effettivo.
- [ ] `P3` Dichiarare esplicitamente nel README quanti adapter sono `production-ready`
      (oggi 4/24 verificati live), invece di lasciarlo solo in `docs/scanner-matrix.md`.
- [ ] `P3` Documentare OS/Python realmente testati, exit code e stati parziali.

## 1.3 — Dipendenze e supply chain

- [ ] `P2` Il VAP vendored trascina dipendenze datate (nella sua `requirements.txt`, es.
      `python-jose 3.3.0`, `passlib`, `bleach`): pianificare la sostituzione o l'isolamento.
- [ ] `P2` Introdurre lock/constraints con hash sugli extra `dev`/`api`/`aegis`.
- [ ] `P2` Fissare le immagini Docker per digest ed eliminare `@latest` / `|| true` sui
      componenti obbligatori.
- [ ] `P2` Generare SBOM e scansione vulnerabilità in CI (vedi §3.5, Syft/Grype/Trivy).

## 1.4 — Runtime `vendor/`

- [ ] `P2` `aegis serve`, `migrate` e `workers` dipendono ancora da un path relativo `vendor/`.
      Decidere: pacchetto separato, container-only, o control-plane nativo (obiettivo finale).

## 1.5 — P0 di sicurezza ancora aperti (Web VAP legacy)

- [ ] `P0` Proteggere tutte le route HTML (`/`, `/scans`, `/scans/{id}`).
- [ ] `P0` Auth/JWT fail-closed; nessun ruolo admin implicito; RBAC (admin/operator/reviewer/read-only).
- [ ] `P0` Rifiutare avvio non locale senza TLS + segreti validi.
- [ ] `P0` Eliminare API key da query string, redirect e link di download.
- [ ] `P0` Allowlist target obbligatoria in produzione.
- [ ] `P0` Applicare egress allowlist ai container/processi di scansione.
- [ ] `P0` Correggere le richieste VAP che seguono redirect senza rivalidare scope e DNS.

_(I P0 già chiusi — SSRF guard, IP pinning, limiti HTTP/decompressione, secret scanning —
restano invariati e verificati; vedi Registro.)_

---

# 2 — Potenziamenti dei moduli esistenti

| Modulo | Potenziamento | Prio |
|---|---|---|
| **Argus** (OSINT/recon) | Grafo investigativo più ricco, correlazione entità, arricchimento IOC | `P1` |
| **Athena** (orchestrazione) | Cancellazione effettiva su operazioni non cooperative; backoff con jitter e budget massimo; adapter reali verso gli altri moduli; event contract versionato | `P1` |
| **Helios** (scanning) | Fingerprinting sicuro più esteso (già distingue closed/filtered/unreachable/dns_failure/denied) | `P2` |
| **Artemis** (web probing) | Coverage report per endpoint; più check web dietro scope | `P2` |
| **Hermes** (secret scan) | Baseline, allowlist, entropy detection, output SARIF, hook pre-commit/CI | `P1` |
| **Apollo** (detection) | Import regole **Sigma**, normalizzazione **ECS/OCSF**, connettori SIEM | `P1` |
| **Minerva** (IR/chain-of-custody) | Ledger firmato **Ed25519/HMAC**, trusted timestamp, anchor append-only | `P1` |
| **Vulcan** (aggregazione/report) | Arricchimento **CVSS + EPSS + CISA KEV**, template report versionati e firmati (PDF/HTML/SARIF/JSON) | `P1` |
| **Metis** (CTI) | **STIX/TAXII 2.1**, **MISP**, backup/restore, cifratura campi sensibili | `P1` |
| **Proteus** (SE simulato) | Minimizzazione PII, retention, lifecycle campagne, audit | `P2` |
| **TUI** | Kill del process group, risultati parziali/errori visibili, test resize/focus/no-color, accessibilità | `P1` |
| **AEGIS** (control plane) | Control-plane nativo completo (ritiro `vendor/`), `aegis doctor --scanner`, capability matrix generata dal registro | `P1` |

Task trasversali di qualità:

- [ ] `P3` Separare domain/service logic dagli handler Typer in tutti i moduli.
- [ ] `P3` Unificare errori, output JSON/SARIF/console, deadline e cancellazione.
- [ ] `P3` Property-based testing e fuzzing su parser/normalizzatori.
- [ ] `P3` Coverage per modulo con soglia progressiva; mypy/pyright bloccante.

---

# 3 — Nuovi tool da aggiungere

## 3.0 — Come si aggiunge uno scanner (meccanismo esistente)

Ogni scanner è una `ScannerSpec` (dataclass frozen) in
`src/olympus/integrations/scanners.py`; l'esecuzione nativa è un adapter in
`src/olympus/aegis/adapters/<nome>.py`. Aggiungere un tool = **1)** registrare la
`ScannerSpec` (nome, categoria, kind, binario/licenza) + **2)** scrivere l'adapter con
parser + **3)** fixture offline, unit/contract test e test live. Nessuna nuova architettura:
si riusa quella dei 6 adapter già funzionanti.

## 3.1 — Completare gli scanner già a catalogo (18 mancanti)

Web OSS: `arjun`, `commix`, `dalfox`, `dirsearch`, `httpx`, `katana`, `nosqlmap`, `nuclei`, `wapiti`, `xsstrike`.
DNS/recon OSS: `subfinder`, `theharvester`.
WordPress: `wpscan` (gestione token API vuln DB).
Servizi OSS via API: `zap` (Apache-2.0), `openvas`/GVM (GPL-2.0) — adapter con auth/TLS/health.
Commerciali via API (opzionali, dietro config): `nessus`, `burp`, `acunetix` — stato `unavailable` finché non configurati.

- [ ] `P1` Adapter + parser + test per ciascuno, fino a `production-ready`.

## 3.2 — Nuovi tool NON ancora nel registro (recon)

Assenti oggi dal registro, da aggiungere come nuove `ScannerSpec` + adapter:

- [ ] `P1` **naabu** — port scanner veloce (ProjectDiscovery). MIT. → https://github.com/projectdiscovery/naabu
- [ ] `P1` **dnsx** — toolkit DNS (ProjectDiscovery). MIT. → https://github.com/projectdiscovery/dnsx
- [ ] `P1` **OWASP Amass** — attack-surface mapping. Apache-2.0. → https://github.com/owasp-amass/amass
- [ ] `P2` Profilo "recon automation" ispirato a **reconftw** (pipeline recon→web→vuln, sempre scope-gated). → https://github.com/six2dez/reconftw
- Docs ProjectDiscovery: https://docs.projectdiscovery.io

## 3.3 — Detection & Blue Team

- [ ] `P1` Import/conversione regole **Sigma** verso i backend SIEM (in Apollo). → https://github.com/SigmaHQ/sigma · https://sigmahq.io
- [ ] `P1` Validazione detection con **Atomic Red Team** in lab autorizzato. → https://github.com/redcanaryco/atomic-red-team
- [ ] `P1` Mappatura finding/detection su **MITRE ATT&CK**. → https://attack.mitre.org

## 3.4 — Threat Intelligence (Metis)

- [ ] `P1` **STIX/TAXII 2.1** + integrazione **MISP**. → https://github.com/MISP/MISP · https://oasis-open.github.io/cti-documentation
- [ ] `P2` Connettore **OpenCTI** per correlazione IOC/campagne. → https://github.com/OpenCTI-Platform/opencti

## 3.5 — Vulnerability, cloud, container, SBOM

- [ ] `P1` Arricchimento automatico **EPSS** + **CISA KEV** su ogni finding (Vulcan). → https://www.first.org/epss · https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- [ ] `P2` Export verso gestore vulnerabilità stile **DefectDojo**. → https://github.com/DefectDojo/django-DefectDojo
- [ ] `P2` Cloud posture: **Prowler** (AWS/Azure/GCP), **ScoutSuite**. → https://github.com/prowler-cloud/prowler · https://github.com/nccgroup/ScoutSuite
- [ ] `P2` Container/IaC/dependency: **Trivy**, **Grype**. → https://github.com/aquasecurity/trivy · https://github.com/anchore/grype
- [ ] `P2` **SBOM** con **Syft** su ogni immagine/artefatto rilasciato. → https://github.com/anchore/syft

## 3.6 — Nuovo modulo proposto

- [ ] `P3` `hephaestus` — hardening/benchmark **CIS** su host e config. → https://www.cisecurity.org/cis-benchmarks

> **Regola per tutte le integrazioni**: governate, non copiate. Olympus rileva la versione
> installata, valida la config, esegue entro scope autorizzato, normalizza l'output e registra
> l'evidenza. Licenze e canali d'installazione dei tool di terze parti restano autoritativi
> (`THIRD_PARTY_NOTICES.md`).

---

# 4 — Regole di esecuzione configurabili

Obiettivo: rendere **editabile da un unico file** ciò che oggi è hardcoded, senza toccare
codice a ogni engagement. Riguarda i **bound operativi** e un **profilo lab** per il tuo
ambiente di test.

## 4.1 — Bound editabili

Oggi i limiti sono costanti in `src/olympus/core/execution.py`
(`MAX_TIMEOUT_SECONDS`, `MAX_DEADLINE_SECONDS`, `MAX_CONCURRENCY`, `MAX_RETRIES`,
`MAX_BACKOFF_SECONDS`, `MAX_MIN_INTERVAL_SECONDS`, `MAX_JITTER_RATIO`).

- [x] `P1` Introdurre `olympus.core.policy` con `PolicyRuleset` versionato (Pydantic v2) che
      legge timeout/deadline/concorrenza/retry/backoff/interval/jitter da un file.
- [x] `P1` I valori attuali diventano i **default** e restano i **tetti di sicurezza** massimi:
      un file che supera un `MAX_*` viene **rifiutato**, non riportato in silenzio al massimo.
- [x] `P1` Precedenza: `CLI → env → file policy → default`; risoluzione `OLYMPUS_POLICY` →
      `./olympus.policy.toml` → `~/.olympus/policy.toml`.
- [x] `P1` CLI: `olympus policy show|validate|diff|edit` (segreti redatti; `validate` bloccante,
      exit code `2`). Documentazione: [`docs/policy.md`](docs/policy.md).

Esempio (`olympus.policy.toml`):

```toml
schema_version = "1.0.0"
engagement     = "demo-2026"

[bounds.default]
timeout_seconds  = 10
deadline_seconds = 600
max_concurrency  = 4
retries          = 1
backoff_seconds  = 0.5
jitter_ratio     = 0.2

[bounds.aggressive]        # selezionabile con --profile aggressive
max_concurrency = 16
retries         = 3

[scope.domains]
allowed  = ["example.com"]
excluded = ["vpn.example.com"]
```

Cambiare un limite = modificare una riga e rilanciare. Nessun codice da toccare.

## 4.2 — Profilo `lab`

Per testare comodamente nel tuo ambiente isolato senza combattere con lo scope:

- [x] `P1` Profilo `lab` che autorizza esplicitamente i **tuoi** range privati dichiarati
      (es. `10.10.0.0/16`), altrimenti bloccati dalla SSRF guard. `is_globally_routable` resta
      puro; il nuovo `is_authorized_destination` è l'unico predicato che legge la policy.
- [x] `P1` Attivazione esplicita e tracciata: `enabled = true` esige `allowed_networks`,
      `activated_by` e `activated_at`, e produce un record con digest del documento, firmato
      in HMAC-SHA256 quando è configurata `OLYMPUS_POLICY_LAB_KEY`.

```toml
[lab]
enabled          = true
allowed_networks = ["10.10.0.0/16"]   # range che dichiari di possedere
activated_by     = "operator@example.com"
activated_at     = 2026-01-01T00:00:00Z
```

Lo scope-check, i gate di autorizzazione sulle operazioni sensibili e la protezione SSRF
restano attivi come guardrail: quello che cambi è **cosa dichiari come autorizzato**, con la
lista interamente in mano tua.

---

# 5 — Hardening residuo (ereditato dalla roadmap precedente)

Voci già tracciate e ancora aperte che §1–§4 non assorbono. Restano qui per non perderle:
la riorganizzazione del documento non chiude lavoro.

## 5.1 — Isolamento e segmentazione

- [ ] `P1` Applicare seccomp/AppArmor e filesystem read-only agli scanner
      (le scratch directory isolate e i rlimit sono già in `olympus.aegis.sandbox`).
- [ ] `P1` Separare rete di controllo e rete di scansione.

## 5.2 — Output ed evidenze

- [ ] `P2` Scrittura atomica, owner-only e no-follow in **tutti** i moduli, non solo in `core.fileio`.
- [ ] `P2` Validare path, collisioni, overwrite e traversal prima di scrivere.
- [ ] `P2` Calcolare i digest al momento della creazione dell'artefatto, non a posteriori.
- [ ] `P2` Testare truncation, reorder, fork e riscrittura completa del ledger Minerva.

## 5.3 — Container e immagini

- [ ] `P2` Build multi-stage con runtime privo di toolchain.
- [ ] `P2` Eseguire i container non-root con `read_only`, `cap_drop`, `no-new-privileges` e limiti.
- [ ] `P2` Proteggere l'API ZAP e segmentare le reti Compose.
- [ ] `P2` Health/capability gate che fallisce se mancano gli scanner dichiarati.
- [ ] `P2` Firma delle immagini e provenance, oltre a SBOM e vulnerability scan (§1.3).

## 5.4 — CI/CD e release

- [ ] `P3` Matrice Python 3.11–3.14 oppure restrizione formale delle versioni supportate.
- [ ] `P3` Test di core/CLI su Ubuntu, Windows e macOS.
- [ ] `P3` Separare le suite `unit`, `contract`, `integration`, `offline-e2e`, `live-e2e`.
- [ ] `P3` Integrare SAST, SCA/OSV, license compliance e CodeQL.
- [ ] `P3` Verificare Docker Compose, build delle immagini e laboratorio e2e autorizzato.
- [ ] `P3` Introdurre CHANGELOG, SemVer, tag/release firmati, migrazioni e rollback.

## 5.5 — Governance del repository

- [ ] `P3` Proteggere `main`: PR obbligatoria, review, CI verde, niente force-push.
- [ ] `P3` Aggiungere CODEOWNERS e mantenere SECURITY.md e la disclosure policy.
- [ ] `P3` Pubblicare threat model, security architecture e deployment hardening guide.
- [ ] `P3` Sostituire le approvazioni didattiche predefinite del VAP con riferimenti verificabili.
- [ ] `P3` Pulire branch temporanei e obsoleti.

---

# Definition of Done per tool/adapter/integrazione

- [ ] Scope e autorizzazione verificati prima di ogni traffico.
- [ ] Bound (timeout/deadline/cancellazione/limiti risorse) applicati dalla policy.
- [ ] Parser strutturato e output redatto/atomico.
- [ ] Fixture offline, unit test, contract test e test live autorizzato.
- [ ] Versioni compatibili e dipendenze documentate.
- [ ] Stati errore/partial e exit code non ambigui.
- [ ] Documentazione generata, SBOM e vulnerability scan.
- [ ] Evidence manifest con digest e cleanup/rollback verificati.

---

# Registro avanzamento

| Data | Tranche | Stato | Evidenza |
|---|---|---|---|
| 2026-08-29 | P0 foundations | CI verde | Run `#119`: Ruff, 687 test, gitleaks e wheel smoke |
| 2026-08-29 | Secret history | CI verde | Run `#121`: scansione completa history su `main` |
| 2026-08-29 | P0 runtime limits | CI verde | Run `#122`: body streaming, cancellazione HTTP, deadline Athena |
| 2026-08-29 | P0 HTTP policy | CI verde | Run `#125`: header, redirect e deadline bounded |
| 2026-08-29 | P0 SSRF e decompressione | verificato | 859 test verdi su `main@d94bbf4`: IP pinning per hop, limiti decompressione, SARIF gitleaks con canary |
| 2026-08-30 | P1 isolamento esecuzioni | CI verde | `aegis.sandbox`: drop utente, rlimit CPU/RAM/NPROC/NOFILE/FSIZE/CORE, scratch dir privata, escalation SIGTERM→SIGKILL |
| 2026-08-30 | P1 job plane AEGIS | CI verde | Lease/heartbeat/ownership, retry+idempotency, schema SQLite versionato+WAL, stati distinti, path redatti |
| 2026-08-30 | P1 identità API AEGIS | CI verde | Scope per route, rotazione con overlap, revoca, rate limit, audit redatto |
| 2026-08-30 | P1 retention AEGIS | CI verde | Budget età/numero/dimensione, log append-only, prune con `secure_delete`, VACUUM |
| 2026-08-30 | Wheel senza vendor | verificato | Diagnostica non richiede più `vendor/`; comandi che lo richiedono escono con codice 2 |
| 2026-08-30 | P1 stati/coverage Artemis/Helios | CI verde | `core.coverage`: stati CLEAN/FINDINGS/PARTIAL/FAILED, exit code 5/6/7 |
| 2026-08-30 | P2 configurazione | CI verde | Run `#137`: precedenza CLI/env/TOML/default, `config validate` redatto, 1040 test |
| _(prossima)_ | **Correzioni §1** | da iniziare | 18 adapter, coerenza README, dipendenze VAP, ritiro `vendor/` |
| _(prossima)_ | **Nuovi tool §3** | da iniziare | naabu/dnsx/amass, Sigma/ATT&CK, STIX/MISP, EPSS/KEV, Trivy/Grype/Syft |
| 2026-09-05 | **Policy editabile §4** | test locali verdi, CI da confermare | `olympus.core.policy`: `PolicyRuleset` Pydantic v2 versionato, profili come overlay di `[bounds.default]`, `MAX_*` come tetti rifiutati-non-clampati, precedenza CLI/env/file/default, `olympus policy show\|validate\|diff\|edit`, profilo `lab` con record di attivazione firmato e `is_authorized_destination` nella SSRF guard. Ruff pulito, mypy pulito sui moduli toccati, 1108 test |

**Nota evidenze.** Tranche P1 riconfermate da `main` run `#135` (Ruff, 1033 test, gitleaks, wheel smoke);
configurazione da PR run `#137` (1040 test). Nessuna voce nuova si spunta senza codice, test e —
per i tool — evidenza live.

La tranche **§4** è stata verificata in locale (Ruff pulito, mypy pulito su
`core/policy.py`, `core/addresses.py` e `athena/scope.py`, 1108 test verdi): la conferma in CI
è la condizione per considerarla chiusa secondo la Definition of Done.
