# SECURITY & responsible use / Sicurezza e uso responsabile

> 🇮🇹/🇬🇧 Olympus è una piattaforma di security **offensiva + difensiva** per **test
> autorizzati, CTF e studio**. Ogni modulo Red è non distruttivo, con scope obbligatorio e
> log degli accessi fuori perimetro. / Olympus is an **offensive + defensive** security
> platform for **authorized testing, CTFs and study**. Every Red module is non-destructive,
> scope-gated, and logs out-of-scope attempts.

## 🇮🇹 Modello di sicurezza trasversale

Tutte le funzionalità che toccano un target reale rispettano queste regole, senza eccezioni:

1. **Adapter reali dormienti di default.** Il percorso predefinito di ogni demo/test è un
   doppio offline. Gli adapter che interrogano terze parti si attivano **solo** con chiavi
   API fornite dall'operatore via variabili d'ambiente (es. `OLYMPUS_NUMVERIFY_KEY`,
   `OLYMPUS_RAPIDAPI_KEY`). **Nessuna chiave è mai committata** (Hermes + hook pre-commit
   fanno da guardia).
2. **Scope obbligatorio + block+log.** Ogni target (dominio, host/CIDR, numero E.164,
   handle, URL) è verificato contro una allowlist prima di qualunque lookup; ciò che è fuori
   perimetro viene bloccato e registrato in un log di audit append-only.
3. **Gate di consenso esplicito.** I lookup privacy-sensibili (breach intel, presenza su
   messaggistica, metadati profilo) richiedono il flag `--i-am-authorized` con un disclaimer
   esplicito.
4. **Nessuna evasione.** User-Agent onesto e dichiarato; **nessuna** impersonazione di
   fingerprint TLS, rotazione proxy o tecniche anti-bot.
5. **Nessun exploit.** I check di vulnerabilità (es. Metabase CVE-2026-72898) sono di solo
   **fingerprint**: leggono versione/reachability, non inviano mai payload di attacco.
6. **Verde o non fatto.** `make check` (ruff + mypy strict + pytest ≥90%) è l'unico criterio
   di completamento; nessun secret nel repo.

## 🇮🇹 Fonti esterne curate

Concetti presi da progetti esterni e **reimplementati** (non copiati) nella disciplina
Olympus — con miglioramenti di sicurezza rispetto agli originali:

| Fonte | Integrato come | Note di sicurezza |
|---|---|---|
| [SearchPhone](https://github.com/HackUnderway/SearchPhone) | `argus phone` (parsing offline + enrichment opzionale) | Core offline senza chiavi; enrichment reale dormiente |
| [user-scanner](https://github.com/kaifcodec/user-scanner) | `argus accounts` (presenza + metadati) | **Rimossa** l'evasione (TLS-impersonation/proxy) dell'originale |
| [WhatsApp-OSINT](https://github.com/kinghacker0/WhatsApp-OSINT) | segnale messaging in `argus phone --messaging` | Adapter dormiente + consenso esplicito + disclaimer |
| [Metabase GHSA-vwf4-m7j8-wcjf](https://github.com/metabase/metabase/security/advisories/GHSA-vwf4-m7j8-wcjf) | regola Apollo + check Artemis | Solo detection/fingerprint, **nessun exploit** |
| [hackingtool](https://github.com/Z4nzu/hackingtool) | **non integrato** (vedi sotto) | Solo il *pattern* di autorizzazione |

### Perché hackingtool NON è integrato
`hackingtool` è un launcher di ~215 tool esterni, molti dei quali **fuori dai limiti di
Olympus per design**: DDoS, RAT/backdoor, generazione di payload, kit di phishing con
raccolta di credenziali reali, tecniche di anonimizzazione/evasione a scopo malevolo. Nulla
di tutto questo viene importato. L'unico elemento coerente che riprendiamo è il suo **pattern
di sicurezza** (conferma di autorizzazione, nessuna auto-esecuzione, download verificati) —
principi che Olympus già incarna.

## 🇬🇧 Cross-cutting security model

Every capability that touches a real target follows these rules, without exception:

1. **Real adapters dormant by default.** The default path of every demo/test is an offline
   double. Third-party adapters activate **only** with operator-supplied API keys via
   environment variables (e.g. `OLYMPUS_NUMVERIFY_KEY`, `OLYMPUS_RAPIDAPI_KEY`). **No key is
   ever committed** (Hermes + the pre-commit hook stand guard).
2. **Mandatory scope + block+log.** Every target (domain, host/CIDR, E.164 number, handle,
   URL) is checked against an allowlist before any lookup; out-of-scope targets are blocked
   and recorded in an append-only audit log.
3. **Explicit consent gate.** Privacy-sensitive lookups (breach intel, messaging presence,
   profile metadata) require the `--i-am-authorized` flag with an explicit disclaimer.
4. **No evasion.** An honest, declared User-Agent; **no** TLS-fingerprint impersonation,
   proxy rotation, or anti-bot techniques.
5. **No exploitation.** Vulnerability checks (e.g. Metabase CVE-2026-72898) are
   **fingerprint-only**: they read version/reachability and never send an attack payload.
6. **Green or not done.** `make check` (ruff + mypy strict + pytest ≥90%) is the only
   definition of done; no secrets in the repo.

### Why hackingtool is NOT integrated
`hackingtool` is a launcher for ~215 external tools, many of which are **out of bounds for
Olympus by design**: DDoS, RATs/backdoors, payload generation, phishing kits that harvest
real credentials, and anonymity/evasion techniques for malicious use. None of it is imported.
The only coherent thing we borrow is its **safety pattern** (authorization confirmation, no
auto-execution, verified downloads) — principles Olympus already embodies.

## Reporting
This is a study/portfolio project with synthetic demo data only. For any real security issue
in the code itself, open an issue describing the problem (no live exploit details required).
