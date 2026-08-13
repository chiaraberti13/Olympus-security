# CHANGELOG — Olympus Security

> 🇮🇹 Formato ispirato a [Keep a Changelog](https://keepachangelog.com/). Ogni voce
> corrisponde a un'ondata (`W0`..`W4`) del loop auto-correttivo descritto in [PLAN.md](PLAN.md).
> 🇬🇧 Format inspired by [Keep a Changelog](https://keepachangelog.com/). Each entry
> corresponds to a wave (`W0`..`W4`) of the self-correcting loop described in [PLAN.md](PLAN.md).

## [1.0.0] — 2026-08-13

🇮🇹 **Prima release completa**: tutte le ondate pianificate (W0–W4) sono chiuse, `make check`
verde, nessuna voce APERTA in `ERRORS.md`. I nove moduli previsti sono tutti reali e
funzionanti, ciascuno con demo offline deterministica, README bilingue e schema condiviso.

🇬🇧 **First complete release**: every planned wave (W0–W4) is closed, `make check` green, no
OPEN entry in `ERRORS.md`. All nine planned modules are real and working, each with a
deterministic offline demo, a bilingual README, and the shared schema.

### Aggiunto / Added
- **core** — contratto dati condiviso: `Asset`, `Finding`, `Event`, `Evidence`, `Alert`,
  `Incident`; ID tracciabili (`PREFIX-YYYY-NNNNN`); `extra=forbid` su ogni modello; CLI
  unico `olympus <tool> <cmd>`.
- **Argus** (🔴) — OSINT/recon passiva: DNS/MX/SPF/DMARC, Certificate Transparency, export
  `core.Asset`, change monitoring.
- **Hermes** (🔵) — secret scanner: regex a prefissi noti, entropia a doppia soglia,
  scansione della history git, output SARIF con mascheramento, hook pre-commit (dogfoodato
  su questo stesso repo).
- **Helios** (🔴) — network attack-surface mapper: TCP connect scan, scope host/CIDR
  obbligatorio, `core.Finding`/`core.Alert` per servizi ad alto rischio.
- **Apollo** (🔵) — detection engineering: regole YAML mappate su MITRE ATT&CK, motore di
  match, generazione Alert con evidence linking, harness di detection testing.
- **Artemis** (🔴) — web recon: header di sicurezza, misconfigurazioni CORS, content
  discovery, scope host obbligatorio.
- **Minerva** (🔵) — IR/DFIR: apertura incidenti da Alert/Finding, chain of custody
  hash-chained a prova di manomissione, macchina a stati del lifecycle.
- **Proteus** (🔴) — simulazione phishing autorizzata: campagna simulata deterministica,
  pagina di training (mai un form — garantito da test automatici), allowlist destinatari
  obbligatoria. **Mai email reali, mai credenziali reali.**
- **Vulcan** (🟣) — aggregazione cross-modulo via `schema_name` con deduplica, risk scoring
  CVSS+severità, report di pentest Markdown + JSON.
- **Mars** (🟣) — cyber range Docker segmentato (rete `internal`, target vulnerabile-by-design
  sintetico), scenario purple end-to-end offline (`tests/integration/test_purple_scenario.py`)
  che attraversa tutti i moduli mantenendo gli ID tracciabili.

### Qualità / Quality
- `make check` (ruff + mypy --strict + pytest) verde, coverage ≥ 97% per l'intera durata del
  progetto (soglia minima 90%).
- 9 errori reali trovati e risolti tramite verifica end-to-end manuale (non solo test
  automatici) — vedi `ERRORS.md` per il dettaglio, tutti RISOLTI.
- Build riproducibile: `python -m build` produce sdist + wheel identici byte-per-byte
  (hash SHA-256 uguali) su build indipendenti consecutive.

### Versione precedente / Previous version
`0.1.0` — scaffold W0 (contratto dati core, CLI unico, CI, gate configurati).
