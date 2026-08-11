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
