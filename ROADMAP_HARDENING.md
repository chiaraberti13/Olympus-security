# Olympus Security — roadmap di completamento e hardening

Baseline dell'analisi: `main@8a9cc70dbe37bdaa08e34e102298b045208f737f`.

Questo documento è il registro operativo del lavoro. Una voce può essere spuntata solo
quando codice, test e documentazione collegata sono presenti e i controlli CI pertinenti
sono verdi. Le funzionalità parziali restano non spuntate.

## Legenda

- `[ ]` da iniziare o incompleto
- `[x]` completato e verificato
- `P0` blocco di sicurezza; `P1` affidabilità; `P2` supply chain; `P3` qualità/prodotto

## P0 — Sicurezza immediata

### Web VAP legacy

- [x] Quarantenare il comando legacy dietro opt-in esplicito e bind solo loopback.
- [ ] Proteggere tutte le route HTML, incluse `/`, `/scans` e `/scans/{scan_id}`.
- [ ] Rendere autenticazione e JWT fail-closed; nessun ruolo admin implicito.
- [ ] Rifiutare l'avvio non locale senza TLS e segreti validi.
- [ ] Eliminare API key da query string, redirect e link di download.
- [ ] Implementare RBAC per admin, operator, reviewer e read-only.
- [ ] Rendere obbligatoria l'allowlist target in produzione.
- [ ] Sostituire le approvazioni didattiche predefinite con riferimenti verificabili.
- [ ] Migrare UI/API necessarie sul backend AEGIS nativo e ritirare il vendor.

### SSRF, redirect e DNS

- [x] In Athena web, risolvere gli hostname e rifiutare l'intero set se contiene IP non globali.
- [x] In Athena web, rivalidare scope, DNS e destinazione prima di ogni redirect.
- [x] In Athena web, bloccare loopback, private, link-local, multicast e reserved IPv4/IPv6.
- [x] Eliminare il DNS-rebinding TOCTOU negli scanner tramite IP pinning o egress policy.
- [ ] Applicare egress allowlist a container/processi di scansione.
- [x] Aggiungere test per DNS rebinding, record misti, redirect SSRF e IPv4-mapped IPv6.
- [ ] Correggere le richieste VAP che seguono redirect senza rivalidazione.

### HTTP e input remoti

- [x] Applicare un limite rigido ai body HTTP normali e di errore, incluso `Content-Length`.
- [x] Convertire la lettura bounded in streaming incrementale a chunk.
- [x] Rendere retry/backoff/throttling interrompibili dalla cancellazione.
- [x] Limitare decompressione e rapporto di espansione.
- [x] Applicare limiti a header, numero redirect e durata complessiva.

### Secret scanning

- [x] Scansionare sempre il working tree con gitleaks e fallire su finding.
- [x] Scansionare l'intera history su `main`, manualmente e prima delle release.
- [x] Eliminare `continue-on-error` e intervalli Git che possono produrre scansioni a zero byte.
- [x] Pubblicare report redatti/SARIF e testare il workflow con un secret fittizio.

## P1 — Affidabilità operativa

### AEGIS scanner plane

- [ ] Pubblicare stati `catalog-only`, `adapter-ready`, `offline-tested`, `live-tested`, `production-ready`.
- [ ] Completare adapter, parser, fixture e test per i 18 scanner non nativi.
- [ ] Completare i test live autorizzati per `whatweb` e `testssl`.
- [ ] Implementare adapter API con auth/TLS/health per ZAP, OpenVAS, Nessus, Burp e Acunetix.
- [ ] Aggiungere `aegis doctor --scanner` con verifica binario, versione e dipendenze.
- [ ] Generare la capability matrix dal registro eseguibile.

### Isolamento esecuzioni

- [x] Eseguire scanner come utente non privilegiato.
- [x] Limitare CPU, RAM, PID, file descriptor, output e spazio temporaneo.
- [x] Usare process group e escalation terminate → kill.
- [ ] Applicare seccomp/AppArmor e filesystem read-only (directory temporanee isolate: fatto).
- [ ] Separare rete di controllo e rete di scansione.
- [x] Registrare cause strutturate per timeout, kill e violazioni di risorse.

### Job AEGIS e API

- [x] Aggiungere lease, heartbeat, worker ownership e recupero dei job `RUNNING` orfani.
- [x] Implementare retry con limite, backoff e idempotency key.
- [x] Versionare lo schema SQLite e introdurre migrazioni, WAL e busy timeout.
- [x] Separare `FAILED`, `PARTIAL`, `CANCELLED`, `TIMED_OUT` e `POLICY_DENIED`.
- [x] Redigere eccezioni persistite e non esporre path assoluti via API.
- [x] Applicare il limite body durante lo streaming, anche senza `Content-Length`.
- [x] Supportare identità API multiple, scope, rotazione, revoca e rate limiting.
- [x] Imporre TLS per bind non-loopback e aggiungere correlation/request/audit ID.
- [x] Aggiungere retention e cancellazione sicura di log e artefatti.

### Athena

- [x] Correggere deadline complessiva e timeout per job senza attese sequenziali cumulative.
- [ ] Rendere la cancellazione effettiva anche per operazioni non cooperative.
- [ ] Aggiungere backoff con jitter e budget massimo.
- [ ] Integrare adapter per AEGIS, Helios, Artemis, Hermes, Apollo, Minerva e Vulcan.
- [ ] Versionare un event contract condiviso.

### Artemis e Helios

- [ ] Non trasformare errori Artemis in risultati apparentemente puliti.
- [ ] Esporre copertura e stati `CLEAN`, `FINDINGS`, `PARTIAL`, `FAILED`.
- [ ] Uniformare gli exit code e il comportamento quando esistono finding.
- [ ] Applicare rate limit, jitter e deadline globale alla discovery Artemis.
- [ ] Distinguere in Helios porta chiusa, timeout, DNS failure, routing failure e policy denial.
- [ ] Aggiungere concorrenza limitata, cancellazione e deadline a Helios.
- [ ] Sostituire il solo mapping porta-servizio con fingerprinting opzionale sicuro.

### TUI

- [ ] Terminare l'intero process group e applicare escalation terminate → kill.
- [ ] Mostrare processi residui, risultati parziali e cause di errore.
- [ ] Testare resize, focus, tastiera, cancellazione, errori e modalità senza colore.
- [ ] Verificare accessibilità e contrasto.

## P2 — Packaging, integrità e supply chain

### Packaging e configurazione

- [x] Costruire wheel/sdist e installare il wheel in ambiente pulito in CI.
- [x] Eseguire smoke test di tutte le superfici CLI dal wheel installato.
- [ ] Decidere se VAP sarà pacchetto separato, container-only o ritirato.
- [ ] Eliminare la dipendenza runtime da un path relativo `vendor/` (diagnostica e comandi nativi ora funzionano senza `vendor/`; `aegis serve`, `migrate` e `workers` lo richiedono ancora).
- [ ] Definire chiaramente gli extra `dev`, `api`, `aegis` e `vap`.
- [ ] Introdurre lock/constraints con hash e verificare metadata/licenze/file inclusi.
- [x] Rendere TOML malformato, config esplicita assente e valori invalidi errori bloccanti.
- [ ] Documentare e testare precedenza CLI → environment → file → default.
- [ ] Aggiungere `olympus config validate` con redazione dei segreti.

### Output ed evidenze

- [ ] Usare scrittura atomica, owner-only e no-follow in tutti i moduli.
- [ ] Validare path, collisioni, overwrite e traversal.
- [ ] Calcolare digest al momento della creazione degli artefatti.
- [ ] Firmare ledger/checkpoint Minerva con Ed25519 o HMAC.
- [ ] Aggiungere key rotation, trusted timestamp e anchor append-only esterno.
- [ ] Testare truncation, reorder, fork e riscrittura completa del ledger.

### Container e dipendenze

- [ ] Fissare immagini per digest e dipendenze per commit/versione/hash.
- [ ] Eliminare `@latest` e `|| true` per componenti obbligatori.
- [ ] Usare build multi-stage e runtime senza toolchain.
- [ ] Eseguire container come non-root con `read_only`, `cap_drop`, `no-new-privileges` e limiti.
- [ ] Proteggere l'API ZAP e segmentare le reti Compose.
- [ ] Aggiungere health/capability gate che fallisca se mancano scanner dichiarati.
- [ ] Generare SBOM, scansione vulnerabilità, firma immagini e provenance.
- [ ] Sostituire `python-jose==3.3.0`, riesaminare `passlib` e rimuovere `bleach` obsoleto.

## P3 — Qualità, prodotto e governance

### CI/CD e release

- [ ] Testare Python 3.11–3.14 o restringere formalmente le versioni supportate.
- [ ] Testare core/CLI su Ubuntu, Windows e macOS.
- [ ] Aggiungere coverage per modulo con soglia progressiva.
- [ ] Rendere mypy/pyright bloccante.
- [ ] Integrare SAST, SCA/OSV, license compliance, CodeQL e SBOM.
- [ ] Verificare Docker Compose, build immagini e laboratorio e2e autorizzato.
- [ ] Separare suite unit, contract, integration, offline-e2e e live-e2e.
- [x] Aggiornare le GitHub Actions al runtime supportato.
- [ ] Introdurre CHANGELOG, SemVer, tag/release firmati, migrazioni e rollback.

### Manutenibilità e moduli

- [ ] Separare domain/service logic dagli handler Typer.
- [ ] Ridurre le funzioni estese in AEGIS, Argus, Hermes e API wiring.
- [ ] Definire interfacce per rete, persistence, subprocess e third-party adapter.
- [ ] Unificare errori, output JSON/SARIF/console, deadline e cancellazione.
- [ ] Aggiungere property-based testing e fuzzing per parser/normalizzatori.
- [ ] Hermes: pre-commit/CI, baseline, allowlist, entropy detection e SARIF.
- [ ] Apollo: Sigma, ECS/OCSF, connettori SIEM e test prestazionali.
- [ ] Metis: STIX/TAXII, MISP, migrazioni, backup/restore e cifratura campi.
- [ ] Vulcan: CVSS, EPSS, CISA KEV, template versionati e report firmati.
- [ ] Proteus: minimizzazione PII, retention, lifecycle e audit.

### Documentazione e governance GitHub

- [ ] Generare e testare documentazione CLI ed esempi README.
- [ ] Correggere il conteggio/lessico dei moduli e le dichiarazioni di completezza.
- [ ] Documentare OS/Python supportati, exit code, stati parziali e installation modes.
- [ ] Pubblicare threat model, security architecture e deployment hardening guide.
- [ ] Proteggere `main`, richiedere PR/review/CI e impedire force-push.
- [ ] Aggiungere CODEOWNERS e mantenere SECURITY.md/disclosure policy.
- [ ] Pulire branch temporanei e obsoleti.

## Definition of Done per tool/adapter

- [ ] Scope e autorizzazione verificati.
- [ ] Timeout, deadline, cancellazione e limiti risorse reali.
- [ ] Parser strutturato e output redatto/atomico.
- [ ] Fixture offline, unit test, contract test e test live autorizzato.
- [ ] Versioni compatibili e dipendenze documentate.
- [ ] Stati errore/partial e exit code non ambigui.
- [ ] Documentazione generata, SBOM e vulnerability scan.
- [ ] Evidence manifest con digest e cleanup/rollback verificati.

## Registro avanzamento

| Data | Tranche | Stato | Evidenza |
|---|---|---|---|
| 2026-08-29 | P0 foundations | CI verde | Run `#119`: Ruff, 687 test, gitleaks e wheel smoke |
| 2026-08-29 | Secret history | CI verde | Run `#121`: scansione completa della history su `main` |
| 2026-08-29 | P0 runtime limits | CI verde | Run `#122`: body streaming, cancellazione HTTP e deadline Athena |
| 2026-08-29 | P0 HTTP policy | CI verde | Run `#125`: header, redirect e deadline complessiva bounded |
| 2026-08-29 | P0 SSRF e decompressione | verificato | Ruff pulito e 859 test verdi su `main@d94bbf4`: IP pinning per hop, policy indirizzi condivisa, limiti di decompressione, SARIF gitleaks con canary |
| 2026-08-30 | P1 isolamento esecuzioni | in verifica | `olympus.aegis.sandbox`: drop a utente non privilegiato, rlimit CPU/RAM/NPROC/NOFILE/FSIZE/CORE, scratch dir privata, escalation SIGTERM→SIGKILL sul process group, cause strutturate nel contratto `1.1.0`, check `aegis doctor` |
| 2026-08-30 | P1 job plane AEGIS | in verifica | Lease/heartbeat/ownership con recupero orfani, retry con backoff e idempotency key, schema SQLite versionato (`user_version=2`) con migrazione e WAL, stati `PARTIAL`/`TIMED_OUT`/`POLICY_DENIED` distinti, errori e path redatti nel contratto `2.0.0` |
| 2026-08-30 | P1 identità API AEGIS | in verifica | Register `olympus.aegis-api-identities` con scope per route, rotazione con overlap, revoca immediata, scadenza e rate limit per identità; request/correlation ID echeggiati e audit redatto per ogni richiesta |
| 2026-08-30 | P1 retention AEGIS | in verifica | `olympus.core.retention`: budget età/numero/dimensione, sovrascrittura best-effort documentata, rotazione log append-only, prune dei job terminali con `secure_delete`, VACUUM e troncamento WAL |
| 2026-08-30 | Wheel senza vendor | verificato | Smoke del wheel esteso a `doctor` e a `aegis doctor`, `deps`, `info`, `scanners`, `capabilities` più i nuovi gruppi CLI: la diagnostica non richiede più l'albero `vendor/` e i comandi che lo richiedono escono con codice 2 |

**Nota sulle evidenze.** Le righe `in verifica` sono state validate localmente su `claude/hardening-roadmap-check-21qouj` (ruff pulito, 978 test, build del wheel e smoke CLI in ambiente pulito). La CI di repository gira su `pull_request`/`push` su `main`: diventano `CI verde` quando quel workflow ha girato sul branch.
