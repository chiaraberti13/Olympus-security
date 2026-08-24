# Provenance and upstream attribution

Both upstream projects are implemented **inside this repository** — there is no
runtime Git dependency, submodule, wrapper, or external CLI. This file records
the origin and licence of each imported/adapted component, as required by the
project's acceptance rules.

## ARGUS (OSINT & reconnaissance toolkit)

- Upstream: <https://github.com/chiaraberti13/ARGUS>
- Reviewed revision: `1c7a8310ee64e005878dfa183ca8a384760706c6`
- Upstream licence: **MIT** (compatible with this repository's MIT licence).
- Integration: `src/olympus/argus/`. The passive lookups (IP, phone, username,
  email, domain/RDAP, DNS-over-HTTPS, web recon, MAC) are re-implemented in the
  Olympus style — offline-first cores with injected HTTP/DNS ports, scope
  enforcement, and `core.Asset`/`core.Finding` output. The machine-readable
  capability contract lives in `docs/parity/argus.json`.

## Vulnerability Assessment Platform

- Upstream: <https://github.com/chiaraberti13/Vulnerability-Assessment-Platform>
- Reviewed revision: `6c6b395d79f358372e028fe7094cc673374dd88f`
- Upstream licence: **MIT** (compatible with this repository's MIT licence).
- Integration: `src/olympus/athena/`. The platform's assessment-lifecycle
  responsibilities (validated plans, job orchestration, durable storage, audit,
  reporting) are re-implemented as the Athena module per ADR-002; scanner
  algorithms remain owned by the existing Olympus modules and are composed
  through typed adapters. The parity/gap contract lives in
  `docs/parity/vulnerability-assessment-platform.json`.

## Notes

- No upstream secrets, credentials, or API keys were copied.
- Capability parity is tracked as an explicit manifest with contract tests;
  unported upstream behaviour remains an honest, listed gap rather than a silent
  omission.
