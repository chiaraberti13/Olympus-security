# ERRORS — Olympus Security

> Ogni voce APERTA genera un task in TASKS.md. / Every OPEN entry spawns a TASKS.md task.
> Formato / format: ERR-YYYY-MM-DD-nn.

### ERR-2026-08-10-01 — Ruff: StrEnum, datetime.UTC, righe troppo lunghe
- Stato / Status: RISOLTO / RESOLVED
- Contesto / Context: T-001..T-005, primo run di `ruff check`
- Sintomo / Symptom: UP042 (str+Enum), UP017 (timezone.utc), E501 (help CLI > 100 col)
- Causa / Cause: enum classiche invece di StrEnum; alias datetime datato; help su una riga
- Fix: `StrEnum`; `from datetime import UTC`; help Typer su più righe
- Test di regressione / Regression test: `ruff check .` nel gate CI

### ERR-2026-08-10-02 — Mypy strict: tipi enum nei costruttori
- Stato / Status: RISOLTO / RESOLVED
- Contesto / Context: T-006, `mypy .` con pydantic plugin (init_typed)
- Sintomo / Symptom: "asset_type: str incompatible, expected AssetType"
- Causa / Cause: i test costruivano i modelli con stringhe invece di membri enum
- Fix: uso `AssetType.WEB_SERVER`/`AssetType.HOST` nei test
- Test di regressione / Regression test: `mypy .` nel gate CI

### ERR-2026-08-10-03 — Coverage sotto soglia (88.9% < 90%)
- Stato / Status: RISOLTO / RESOLVED
- Contesto / Context: T-006, gate `pytest --cov-fail-under=90`
- Sintomo / Symptom: `core.errors` non testato; demo dei moduli non coperti
- Causa / Cause: mancavano test su ValidationReport e sui comandi `demo`
- Fix: aggiunti test_core_errors + loop sui demo; pragma no-cover su entry-point
- Test di regressione / Regression test: coverage ora 98.7% nel gate CI

### ERR-2026-08-11-01 — `make check` verde solo per caso: `mypy`/`pytest` di PATH isolati dal venv
- Stato / Status: RISOLTO / RESOLVED
- Contesto / Context: T-101, primo `make check` in questo ambiente
- Sintomo / Symptom: `mypy .` → "No module named 'pydantic'"; `pytest` → "unrecognized arguments
  --cov=...". I binari `mypy`/`pytest` su `$PATH` risolvevano a installazioni `uv tool` isolate,
  non all'ambiente Python dove `pip install -e ".[dev]"` aveva installato le dipendenze
- Causa / Cause: `Makefile` invocava `mypy`/`pytest`/`ruff` per nome, dipendendo dall'ordine di
  `$PATH` invece che dall'interprete del progetto
- Fix: `Makefile` ora usa `$(PYTHON) -m {ruff,mypy,pytest}` (variabile `PYTHON ?= python`),
  indipendente da `$PATH`
- Test di regressione / Regression test: `make check` verde in questo ambiente

### ERR-2026-08-11-02 — Ruff B008: `typer.Option(...)` come default di funzione
- Stato / Status: RISOLTO / RESOLVED
- Contesto / Context: T-101, `argus scan --domain/--scope/--log`
- Sintomo / Symptom: `ruff check` segnala B008 sulle chiamate `typer.Option()` nei default
- Causa / Cause: B008 non conosce di default il pattern idiomatico di Typer (chiamata
  intenzionale a ogni definizione di comando, non un mutable-default reale)
- Fix: `tool.ruff.lint.flake8-bugbear.extend-immutable-calls = ["typer.Option", "typer.Argument"]`
- Test di regressione / Regression test: `ruff check .` nel gate CI

### ERR-2026-08-11-03 — Mypy strict: costruttori di eccezione `dnspython` non tipizzati
- Stato / Status: RISOLTO / RESOLVED
- Contesto / Context: T-101, test di `DnspythonResolver` (NXDOMAIN/NoAnswer/Timeout)
- Sintomo / Symptom: "Call to untyped function ... in typed context" pur avendo `dnspython`
  un marker `py.typed`
- Causa / Cause: `dns.resolver.NXDOMAIN.__init__`/`NoAnswer.__init__`/`Timeout.__init__` sono
  dichiarati `(self, *args, **kwargs)` senza annotazioni — gap noto di tipizzazione upstream
- Fix: `# type: ignore[no-untyped-call]` mirato sulle tre chiamate nei test, nessun impatto sul
  codice di produzione
- Test di regressione / Regression test: `mypy .` nel gate CI

### ERR-2026-08-11-04 — CliRunner: `result.stdout` non contiene più `err=True` per difetto
- Stato / Status: RISOLTO / RESOLVED
- Contesto / Context: T-101, test CLI di `argus scan` (blocco fuori scope, scope file mancante)
- Sintomo / Symptom: `assert "out of scope" in result.stdout` fallisce con stdout vuoto
- Causa / Cause: nella versione di Click/Typer installata, `CliRunner` non ha più il flag
  `mix_stderr`: stdout e stderr sono catturati separatamente, ma `result.output` resta il flusso
  combinato
- Fix: asserzioni sui messaggi di errore spostate su `result.output` invece di `result.stdout`
- Test di regressione / Regression test: `pytest` nel gate CI

### ERR-2026-08-11-05 — `argus scan` va in crash se il lookup CT (crt.sh) fallisce
- Stato / Status: RISOLTO / RESOLVED
- Contesto / Context: T-102, smoke test manuale di `olympus argus scan --domain` in questo
  ambiente (egress verso crt.sh bloccato dalla policy del proxy: 403 sul CONNECT)
- Sintomo / Symptom: `CtQueryError` non catturato in `argus/cli.py` → traceback completo,
  comando termina con exit code 1, e la recon DNS (comunque valida) viene persa
- Causa / Cause: la lookup CT è stata trattata come dipendenza rigida invece che come fonte
  OSINT ausiliaria e best-effort; nessun modulo offensivo deve smettere di funzionare per un
  problema di rete su una singola fonte passiva
- Fix: `scan` ora cattura `CtQueryError`, stampa un warning su stderr e continua con
  `subdomains: []`, preservando l'output DNS/MX/SPF/DMARC già raccolto
- Test di regressione / Regression test: `test_scan_survives_ct_lookup_failure` in
  `test_argus_cli_scan.py`
