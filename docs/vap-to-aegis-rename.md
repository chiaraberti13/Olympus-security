# VAP → AEGIS rename map

The Olympus-facing Vulnerability Assessment Platform component is named
**AEGIS** (the protective shield of Zeus/Athena — consistent with Olympus's
Greek-mythology taxonomy and thematically apt for a defensive assessment
platform).

## Collision audit (passed)

- `aegis` appears **nowhere** in Olympus-owned code, config, or docs.
- Not an existing `olympus` command, not in the `Source` enum, no importable
  `aegis` Python package.
- Fits the mythological naming scheme (Argus, Athena, Helios, Artemis, …).

## What was renamed (Olympus-owned only)

| Area | Before | After |
| --- | --- | --- |
| Primary CLI command | `olympus vap` | `olympus aegis` |
| Subcommands | serve, migrate, scanners, info | serve, migrate, **workers**, scanners (`--check`), **deps**, **scan**, info, **doctor** |
| Integration Typer app | `vap_app` | `aegis_app` |
| Command help/branding | "Vulnerability Assessment Platform" | "AEGIS — Olympus vulnerability-assessment & scanner-orchestration platform" |
| Python optional-deps extra | `[vap]` | `[aegis]` (`[vap]` kept as an alias) |
| Compose services | `app`, `worker`, `migrate` | `aegis-app`, `aegis-worker`, `aegis-migrate` |
| Provenance enum | (absent) | `Source.AEGIS` added |
| Scanner registry | (none) | `olympus.integrations.scanners` (Olympus-native) |
| Docs | "VAP" references | "AEGIS" (README EN/IT, provenance, install, matrices) |

## What was intentionally **not** renamed (vendored, kept verbatim)

Per the requirement to keep upstream source and provenance intact under
`vendor/`, the following remain unchanged and are exposed *through* the AEGIS
layer, not rewritten:

- the vendored package/app code, its FastAPI application title, and web-interface
  templates/branding;
- the upstream `VAP_*` environment-variable contract (host, port, DB, Celery,
  secrets) — the AEGIS integration passes these through unchanged;
- the vendored `requirements.txt`, `Dockerfile`, `installer.sh`, tests, and
  licence.

This keeps the rename cosmetic-free where it would otherwise alter upstream code.

## Backward compatibility

- `olympus vap …` still works. It prints a deprecation notice to stderr and
  **forwards every argument** to `olympus aegis …`.
- The `[vap]` pip extra still resolves (aliased to `[aegis]`).
- **Planned removal:** the `olympus vap` alias and the `[vap]` extra are
  deprecated and will be removed in a future release. Migrate to `olympus aegis`
  and `.[aegis]`. Obsolete naming is not preserved indefinitely.

## New AEGIS subcommands

```text
olympus aegis serve     [--host --port]     # run the FastAPI web app
olympus aegis migrate                        # alembic upgrade head
olympus aegis workers   [--queue --loglevel] # run a Celery scan worker
olympus aegis scanners  [--check]            # list all 24 (+ binary availability)
olympus aegis deps                           # web stack + scanner binary report
olympus aegis scan      --scanner --target --scope-id --i-am-authorized  # native API
olympus aegis info                           # location + stack importability
olympus aegis doctor                         # runtime diagnostics (secret-safe)
```
