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

### ERR-2026-08-14-01 — Plugin `pytest-cov` assente nell'ambiente non aggiornabile
- Stato / Status: RISOLTO / RESOLVED
- Contesto / Context: T-102, gate finale `make check`
- Sintomo / Symptom: `python -m pytest` rifiuta gli argomenti `--cov`, `--cov-report` e
  `--cov-fail-under`; `pip install -e ".[dev]"` non può scaricare `hatchling`
- Causa / Cause: l'interprete attivo non include `pytest-cov` e il proxy del package index
  risponde `403 Forbidden`, impedendo l'installazione delle dipendenze di sviluppo dichiarate
- Fix: aggiunto un gate portabile basato sul tracer della standard library, avviato prima di
  pytest e limitato ai frame `src/olympus`; nessuna dipendenza o accesso rete richiesti
- Test di regressione / Regression test: `make check` deve completare il gate coverage ≥ 90%

### ERR-2026-08-14-02 — Ruff: messaggio coverage oltre il limite di riga
- Stato / Status: RISOLTO / RESOLVED
- Contesto / Context: T-901, primo run del gate coverage portabile
- Sintomo / Symptom: E501 su una chiamata `print` lunga 102 caratteri
- Causa / Cause: messaggio e destinazione stderr composti sulla stessa riga
- Fix: messaggio estratto in una variabile locale
- Test di regressione / Regression test: `ruff check .` nel gate CI

### ERR-2026-08-14-03 — Primo tracer portabile sottostima la coverage
- Stato / Status: RISOLTO / RESOLVED
- Contesto / Context: T-901, secondo run del gate coverage portabile
- Sintomo / Symptom: coverage riportata al 67,8% nonostante la suite copra i modelli core
- Causa / Cause: `trace.Trace` applicava filtri interni non adatti alla raccolta avviata da pytest
- Fix: raccolta sostituita con un trace hook limitato esplicitamente a `src/olympus`
- Test di regressione / Regression test: `make check` verifica una coverage ≥ 90%

### ERR-2026-08-14-04 — Ruff B009 sul trace hook
- Stato / Status: RISOLTO / RESOLVED
- Contesto / Context: T-901, trace hook del gate coverage
- Sintomo / Symptom: B009 sull'accesso costante a `f_code` e `f_lineno` tramite `getattr`
- Causa / Cause: parametro frame annotato troppo genericamente come `object`
- Fix: annotazione `FrameType` e accesso diretto agli attributi
- Test di regressione / Regression test: `ruff check .` nel gate CI

### ERR-2026-08-14-05 — Mypy: firma callback incompatibile con `sys.settrace`
- Stato / Status: RISOLTO / RESOLVED
- Contesto / Context: T-901, trace hook del gate coverage
- Sintomo / Symptom: callback annotata con ritorno `object` incompatibile con `TraceFunction`
- Causa / Cause: un trace hook restituisce ricorsivamente una funzione di tracing, non un object
  arbitrario
- Fix: tipo di ritorno reso compatibile con la firma dinamica richiesta dalla standard library
- Test di regressione / Regression test: `mypy .` nel gate CI

### ERR-2026-08-14-06 — Gate W1: lint, typing, regressione demo e coverage
- Stato / Status: RISOLTO / RESOLVED
- Contesto / Context: T-103..T-115, iterazioni del gate W1
- Sintomo / Symptom: S603 sui subprocess Git, tipo opzionale dell'eseguibile Git, test smoke
  ancora legato ai demo scaffold e coverage iniziale 89,3%
- Causa / Cause: hardening subprocess non esplicitato, narrowing globale insufficiente, test
  legacy non aggiornato e percorso CLI Hermes non coperto
- Fix: eseguibile Git risolto a path assoluto, eccezione Ruff motivata, helper tipizzato, smoke
  test aggiornato e test CLI SARIF aggiunto; coverage finale 90,7%
- Test di regressione / Regression test: `make check` completo

### ERR-2026-08-14-07 — T-201: lista export core e ordine import test
- Stato / Status: RISOLTO / RESOLVED
- Contesto / Context: T-201, primo run `ruff check .`
- Sintomo / Symptom: elementi Event/Evidence inseriti dopo la chiusura di `__all__` e I001
  nel nuovo test
- Causa / Cause: applicazione incompleta della patch e import non ordinati
- Fix: elementi spostati dentro `__all__` e import ordinati secondo Ruff
- Test di regressione / Regression test: `ruff check .` nel gate CI

### ERR-2026-08-14-08 — T-201: tipo ID Event non registrato
- Stato / Status: RISOLTO / RESOLVED
- Contesto / Context: T-201, primo test di round-trip Event
- Sintomo / Symptom: `new_id("event")` sollevava `ValueError` per kind sconosciuto
- Causa / Cause: il nuovo modello era stato aggiunto senza il relativo prefisso canonico
- Fix: registrato il prefisso `EVT` nel generatore condiviso
- Test di regressione / Regression test: round-trip Event nel gate pytest

### ERR-2026-08-14-09 — Helios: righe oltre il limite Ruff
- Stato / Status: RISOLTO / RESOLVED
- Contesto / Context: T-202..T-204, primo gate Helios
- Sintomo / Symptom: E501 su firme, validazione porte e payload export
- Causa / Cause: prima stesura troppo compatta
- Fix: firme e strutture dati suddivise, condizione estratta con naming esplicito
- Test di regressione / Regression test: `ruff check .` nel gate CI

### ERR-2026-08-14-10 — W2: smoke demo obsoleto, coverage e import test
- Stato / Status: RISOLTO / RESOLVED
- Contesto / Context: T-205 e T-215, primo test dei demo reali
- Sintomo / Symptom: smoke test attendeva ancora scaffold, coverage 87,8%, I001/E501 nei test CLI
- Causa / Cause: lista legacy non aggiornata e percorsi CLI non ancora esercitati
- Fix: demo rimossi dalla lista scaffold, aggiunti test CLI offline e formattati gli import
- Test di regressione / Regression test: `make check` completo

### ERR-2026-08-14-11 — Apollo accettava solo JSON con estensione YAML
- Stato / Status: RISOLTO / RESOLVED
- Contesto / Context: audit post-W2 del criterio T-211
- Sintomo / Symptom: una regola YAML reale non era caricabile; il demo usava JSON rinominato
- Causa / Cause: JSON è un sottoinsieme YAML 1.2, ma non soddisfa l'UX e il criterio dichiarato
  di authoring delle regole
- Fix: aggiunto parser YAML ristretto senza dipendenze; rifiuta tag, anchor, costruttori,
  duplicati, tab e indentazione ambigua
- Test di regressione / Regression test: fixture YAML reale e rifiuto esplicito dei tag

### ERR-2026-08-14-12 — Test Apollo legato all'eccezione del parser JSON
- Stato / Status: RISOLTO / RESOLVED
- Contesto / Context: T-902, primo test del parser YAML ristretto
- Sintomo / Symptom: la fixture malformata sollevava correttamente `ValueError`, mentre il test
  legacy richiedeva `JSONDecodeError`; coverage transitoria 89,7%
- Causa / Cause: il test esponeva un dettaglio del vecchio parser anziché il contratto pubblico
- Fix: asserzione aggiornata sull'errore semantico e casi regressivi per duplicati, tab e indent
- Test di regressione / Regression test: `make check` completo

### ERR-2026-08-14-13 — Coverage T-902 sotto soglia di una linea
- Stato / Status: RISOLTO / RESOLVED
- Contesto / Context: gate T-902 dopo i test di hardening YAML
- Sintomo / Symptom: 930/1034 linee, 89,9% contro il minimo 90%
- Causa / Cause: ramo di rifiuto delle condizioni duplicate non esercitato
- Fix: aggiunto caso regressivo YAML con chiave condition duplicata
- Test di regressione / Regression test: gate coverage ≥ 90%

### ERR-2026-08-14-14 — Artemis: righe oltre il limite Ruff
- Stato / Status: RISOLTO / RESOLVED
- Contesto / Context: T-304, primo run di verifica
- Sintomo / Symptom: E501 sulla condizione path e sulla firma del test CLI
- Causa / Cause: espressioni corrette ma troppo compatte
- Fix: condizione e firma suddivise su righe leggibili
- Test di regressione / Regression test: `ruff check .` nel gate CI

### ERR-2026-08-14-15 — Coverage T-304 arrotondata a 90,0% ma sotto soglia
- Stato / Status: RISOLTO / RESOLVED
- Contesto / Context: T-304, primo gate test Artemis
- Sintomo / Symptom: 1238/1376 linee (89,97%), visualizzato 90,0% ma correttamente rifiutato
- Causa / Cause: ramo CLI di autorizzazione positiva non esercitato
- Fix: aggiunto test del comando `check-scope` per un URL autorizzato
- Test di regressione / Regression test: gate coverage ≥ 90%

### ERR-2026-08-14-16 — Test demo Minerva modificava un esempio tracciato
- Stato / Status: RISOLTO / RESOLVED
- Contesto / Context: gate finale T-304, audit del working tree
- Sintomo / Symptom: `make check` modificava `examples/output/minerva-incident.json`
- Causa / Cause: il test demo isolava il ledger ma non il nuovo path incident di T-303
- Fix: anche `DEFAULT_INCIDENT` viene reindirizzato dentro `tmp_path`
- Test di regressione / Regression test: working tree stabile dopo `make check`
