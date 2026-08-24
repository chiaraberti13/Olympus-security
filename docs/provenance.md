# Provenance and upstream attribution

Both upstream projects are implemented **inside this repository** — there is no
runtime Git dependency, submodule, wrapper, or external CLI. The **complete,
unmodified upstream source** of each tool is vendored under `vendor/` and wired
into the `olympus` CLI as a first-class runnable subcommand. This file records
the origin and licence of each vendored tool, as required by the project's
acceptance rules.

## ARGUS (OSINT & reconnaissance toolkit)

- Upstream: <https://github.com/chiaraberti13/ARGUS>
- Vendored revision: `1c7a8310ee64e005878dfa183ca8a384760706c6`
- Location: `vendor/argus/` — complete source (the `argus` package and all its
  modules, `data/`, `docs/`, `scripts/`, `tests/`, `Dockerfile`, `pyproject.toml`,
  `requirements.txt`, and `LICENSE`), preserved verbatim.
- Licence: **MIT** (`vendor/argus/LICENSE`), compatible with this repository.
- Entry point: `olympus argus-native …` forwards every argument to the complete
  ARGUS CLI (subcommands `ip`, `phone`, `username`, `email`, `domain`, `dns`,
  `web`, `mac`, `myip`, `config`, `update`, plus the interactive menu).
- An Olympus-native, scope-first re-implementation of the same passive lookups
  also exists under `src/olympus/argus/` (`olympus argus …`); it is complementary,
  not a replacement, and its capability contract is `docs/parity/argus.json`.

## Vulnerability Assessment Platform

- Upstream: <https://github.com/chiaraberti13/Vulnerability-Assessment-Platform>
- Vendored revision: `6c6b395d79f358372e028fe7094cc673374dd88f`
- Location: `vendor/vulnerability-assessment-platform/` — complete source: the
  FastAPI application (`app.py`, ~40 API/UI routes), all **24 scanner
  integrations** (`scanners/`), the database layer and Alembic migrations
  (`database.py`, `db_migrations/`, `alembic.ini`), report generation
  (`report_generator.py`), background tasks (`celery_app.py`, `background_jobs.py`,
  `tasks.py`), `templates/`, `static/`, `assets/`, `docs/`, `tests/`, the pinned
  `requirements.txt`, `Dockerfile`, `docker-compose.yml`, `installer.sh`, and
  `LICENSE`, preserved verbatim.
- Licence: **MIT** (`vendor/vulnerability-assessment-platform/LICENSE`).
- Olympus-facing name: **AEGIS** (see `docs/vap-to-aegis-rename.md`). Entry
  points: `olympus aegis serve` (web app), `olympus aegis migrate` (DB
  migrations), `olympus aegis workers` (Celery worker), `olympus aegis scanners
  [--check]`, `olympus aegis deps`, `olympus aegis scan`, `olympus aegis info`,
  `olympus aegis doctor`. `olympus vap` remains as a deprecated alias. The
  vendored source and its `VAP_*` configuration contract are unchanged.

## Running the vendored tools

- `bash scripts/setup-vendored-tools.sh` installs both tools' Python
  dependencies into one checkout.
- `pip install -e ".[argus]"` / `pip install -e ".[vap]"` install per-tool
  Python extras; the authoritative VAP pin set is its own `requirements.txt`.
- External scanner **binaries** (nmap, nuclei, sqlmap, wpscan, …) and the full
  runtime (Redis/Celery) are provisioned reproducibly by the vendored
  `installer.sh` and `docker-compose.yml`. When a binary is absent, the scanner
  reports a clear "tool not installed" state instead of failing silently — this
  is upstream behaviour and a sandbox limitation, never a removed feature.

## Notes

- No upstream secrets, credentials, or API keys were copied.
- Vendored code is preserved verbatim and held to its own quality tooling, not
  Olympus's optional helpers.
- Feature-parity tests (`tests/unit/test_vendored_integration.py`) assert that
  every ARGUS module and all 24 VAP scanners are present, so the standalone
  repositories can be deleted without losing functionality.
