# Olympus Security — restructuring and integration checklist

This checklist tracks the restructuring of Olympus Security and the in-repository integration of
[ARGUS](https://github.com/chiaraberti13/ARGUS) and the
[Vulnerability Assessment Platform](https://github.com/chiaraberti13/Vulnerability-Assessment-Platform).
It is a living roadmap, not a set of gates: work can proceed in any order and at any size, and
nothing here blocks, limits, or postpones a feature. A task is done when it is real and fully
functional; tests, docs, and reviews are encouraged but never required to mark progress.

## Status legend

- `[x]` complete and verified
- `[ ]` not started
- `[~]` partially implemented; the remaining acceptance criteria are listed beneath it
- `[!]` known problem or external blocker; this does not mean complete

## Guiding principles

Development is intentionally **flexible**: there are no mandatory quality gates, coverage thresholds,
architectural restrictions, size limits, or CI checks that can block, limit, reject, postpone, or
reduce a feature. New web interfaces, APIs, databases, background workers, containers, plugins,
modules, scanners, and dependencies are all welcome. The short list below is what still holds — and
only the **security**, **functional**, and **licence** items are actual requirements:

- **(Functional)** The upstream projects are **implemented inside this repository** — the complete
  source is vendored under `vendor/` and run directly; no runtime Git dependency, submodule, or
  external checkout is needed. (This is *how the integration works*, not a limit on future changes.)
- **(Licence)** Preserve upstream licences and attribution; record provenance per vendored/imported
  component.
- **(Functional)** Completed tools must be **real and fully functional** — no demos, stubs, mocks,
  placeholders, or partial implementations presented as complete.
- **(Security)** Network-active features validate their target, require explicit authorization, use
  bounded timeouts/concurrency and safe defaults, and emit audit-friendly errors.
- **(Security)** Secrets are never committed, logged, placed in command examples, or returned in
  reports.
- **(Optional)** Documented migrations, linting, type checking, tests, coverage, and security
  analysis are available and encouraged — but they are optional helpers and never block anything.

## Baseline audit — 2026-08-24

### Confirmed present

- [x] Inventory the local package layout and unified CLI registration.
  - Nine modules are registered under `olympus`: Argus, Helios, Artemis, Proteus, Hermes, Apollo,
    Minerva, and Vulcan, plus the shared `core` commands.
  - Shared Pydantic contracts and centralized configuration/HTTP/output utilities already exist.
- [x] Locate the existing project checklist.
  - No checklist or equivalent roadmap was present; this file now establishes it.
- [x] Record the tooling state.
  - Python 3.11+; Ruff, mypy, and pytest are available as **optional** helpers only. There is no
    mandatory quality gate and no coverage threshold: these tools never block implementation,
    integration, execution, or the definition of a tool as complete (updated 2026-08-24).

### Known problems and risks

- [x] Upstream source inventory (previously blocked by HTTP 403/401) is now resolved: both upstream
  repositories were cloned at pinned revisions and their capabilities measured directly. Provenance
  is recorded in `docs/provenance.md` and the parity manifests.
- [x] `README.md` was a very long bilingual document with no architecture or migration section.
  Rewritten (Cycle 8) to the concise project standard; the exhaustive guide is preserved in
  `docs/reference.md`, and command coverage is enforced by the parity contract tests.
- [x] The `olympus.argus` package now demonstrates provenance and full command parity with standalone
  ARGUS (the six previously missing capabilities were added and tested in Cycle 8).
- [x] The Vulnerability Assessment Platform is now implemented as the `olympus.athena` module without
  forcing orchestration into a scanner; remaining gaps are tracked honestly in its parity manifest.
- [x] `Makefile` / `olympus core export-schemas ./examples/output` mismatch is fixed: the command now
  accepts an optional output directory and writes `schemas.json` there (Cycle 8).
- [x] CI strict-mypy regression: the ARGUS parity test imported transitive dependency `click`
  directly, whose implementation/stubs were unavailable in CI. Fixed by introspecting Typer's
  generated command through an `Any` boundary without adding an unnecessary direct dependency.

## Phase 1 — evidence-based upstream parity contracts

- [x] Create the ARGUS parity manifest from a pinned implementation revision.
  - Record upstream commit SHA, licence, commands/options, configuration, data models, external
    integrations, output formats, and security-sensitive behavior.
  - Map every upstream capability to existing Olympus code, a migration task, or an explicitly
    justified deprecation; add a contract test for the manifest.
  - Acceptance: no `unknown` entries remain and the manifest is reproducible from the pinned source.
- [x] Create the Vulnerability Assessment Platform parity manifest using the same criteria.
- [x] Decide the final module taxonomy now that both manifests exist.
  - Reuse an existing category only if its responsibility and data contract are a clean fit.
  - Otherwise create a clearly named module; do not force unrelated orchestration into a scanner.
- [x] Produce a target architecture decision record covering package boundaries,
  dependency direction, execution model, persistence, CLI/possible UI boundaries, and migration
  strategy.

## Phase 2 — shared architecture and safe execution

- [~] Separate domain logic from Typer command handlers in every affected module.
  - [x] Argus `scan`: scoped application service with injected DNS and CT ports.
  - [x] Argus `fronting`: scoped application service with injected DNS and CT ports.
  - [x] Argus `dns`: scoped application service with an injected HTTP port.
  - [x] Argus `whois`: scoped RDAP application service with an injected HTTP port.
  - [x] Argus `web`: scoped passive-HTTP application service with an injected HTTP port.
  - [ ] Remaining Argus commands and affected modules.
- [ ] Define versioned contracts for assessment plans, scan jobs, observations, findings, assets,
  evidence, and reports; document compatibility rules.
- [ ] Add a shared execution policy for authorization, scope enforcement, rate/concurrency limits,
  timeouts, cancellation, retries, and redacted structured logging.
- [ ] Add adapters for network, persistence, and third-party services so domain tests remain offline
  and deterministic.
- [ ] Define secure configuration precedence and validate it at startup; reject unsafe or ambiguous
  values with actionable errors.

## Phase 3 — complete in-repository ARGUS integration

> **Cycle 9:** the **complete** standalone ARGUS is now vendored verbatim under `vendor/argus/` and
> runnable as `olympus argus-native` (100% feature parity, all original subcommands + interactive
> menu). The items below track the complementary Olympus-native scope-first re-implementation.

- [x] Close every gap in the approved ARGUS parity manifest without runtime dependence on the
  standalone repository.
  - The six missing standalone-ARGUS capabilities are now first-class `olympus argus` commands:
    `email`, `mac`, `myip`, `web`, `dns`, and `whois`, alongside the existing scope-first commands.
- [x] Preserve or deliberately migrate all supported ARGUS inputs, commands, outputs, and workflows.
- [x] Add unit, contract, and offline integration tests for every imported capability.
- [ ] Add bounded live-network smoke tests that are opt-in and restricted to authorized fixtures.
- [x] Document ARGUS migration, examples, limitations, and provenance (`docs/provenance.md`, README).

## Phase 4 — complete in-repository Vulnerability Assessment Platform integration

> **Cycle 9:** the **complete** Vulnerability Assessment Platform is now vendored verbatim under
> `vendor/vulnerability-assessment-platform/` and runnable as `olympus vap serve|migrate|scanners`
> (100% feature parity — full FastAPI app, all 24 scanners, DB + migrations, reports, Celery stack).
> The items below track the complementary Olympus-native `athena` orchestration module.

- [x] Create or select the module boundary approved in the architecture decision.
  - The `olympus.athena` package implements ADR-002: `domain/`, `application/`, `ports.py`,
    `adapters/` (sqlite, audit, report, tools), and a CLI-first surface.
- [~] Close every gap in the approved platform parity manifest without runtime dependence on the
  standalone repository.
  - Plans, orchestration, storage, audit, and reporting are implemented; the broad external-tool
    scanner suite and the deferred web API/UI remain honest manifest gaps.
- [x] Implement real assessment orchestration end to end: validated input, execution, progress and
  failure states, persisted results, deduplication, and export through shared contracts.
- [~] Apply SSRF protections, target/scope enforcement, subprocess isolation where applicable,
  resource limits, cancellation, and secret redaction.
  - SSRF guard, scope re-validation, bounded concurrency/timeout/deadline, cooperative cancellation,
    and redacted audit are implemented; subprocess isolation applies only once external-tool adapters
    are added.
- [~] Add unit, contract, offline integration, and authorized opt-in end-to-end tests.
  - Offline unit/contract/integration and CLI end-to-end tests are in place; authorized live-network
    end-to-end tests remain opt-in future work.
- [x] Document platform migration, operation, recovery, limitations, and provenance.

## Phase 5 — UX and documentation restructuring

- [~] Define task-based information architecture for installation, quick start, modules, recipes,
  architecture, security model, development, and migration.
  - The README now follows a task-based structure; a dedicated recipes page is still pending.
- [x] Refactor `README.md` to the same concise, consistent standard selected for the project, with a
  short value proposition and verified quick start; move exhaustive reference material to `docs/`.
  - The exhaustive bilingual guide moved to `docs/reference.md`; the new README mirrors the ARGUS
    standard (quick navigation, modules table, verified quick start, security model, migration).
- [ ] Generate or test CLI reference documentation so it cannot drift from Typer commands.
- [~] Make errors consistent and actionable across commands, including exit codes and remediation.
  - Argus and Athena share the canonical exit-code convention; older modules are not yet audited.
- [ ] If a web interface is retained or introduced, implement accessible loading, empty, partial,
  success, and failure states backed by real application logic.

## Phase 6 — release readiness

- [ ] Add migration tests and remove deprecated paths only after their announced compatibility window.
- [ ] Run dependency, secret, static-analysis, and licence/provenance checks in CI.
- [ ] Verify clean installation and the complete documented workflows on every supported Python
  version.
- [ ] Run an application-security review against the final trust boundaries and threat model.
- [ ] Publish release notes containing breaking changes, migrations, known limitations, and rollback
  instructions.

## Completed cycles

### Cycle 1 — establish a verifiable restructuring plan

- **Task:** audit the local baseline and create the missing project checklist.
- **Result:** completed on 2026-08-24; this document records priorities, gates, known defects, upstream
  blockers, and the single next task.
- **Scope intentionally deferred:** no upstream feature was copied or declared complete without an
  accessible source revision and licence/parity review.

### Cycle 2 — pin and enforce the ARGUS capability contract

- **Task:** create the machine-readable ARGUS parity manifest.
- **Result:** completed on 2026-08-24; `docs/parity/argus.json` pins the in-repository implementation
  revision and tree, records provenance, commands/options, mappings, configuration, integrations,
  data models, outputs, and security behavior.
- **Verification:** a contract test rejects CLI drift, missing mapped files, mutable provenance,
  external CLI dependencies, and incomplete integration/security entries.

### Cycle 3 — inventory the Vulnerability Assessment Platform boundary

- **Task:** create the machine-readable platform parity and gap manifest.
- **Result:** completed on 2026-08-24; the manifest pins the audited Olympus baseline, maps reusable
  capabilities, identifies every missing or partial platform responsibility, and concludes that
  orchestration requires a new application boundary rather than being forced into a scanner.
- **Verification:** contract tests reject mutable provenance, external CLI dependencies, invalid or
  incomplete parity decisions, unsafe file mappings, and missing platform contracts.

### Cycle 4 — select the final module taxonomy

- **Task:** decide whether assessment orchestration belongs to an existing category or a new one.
- **Result:** completed on 2026-08-24; ADR-001 assigns orchestration to the new `athena` module and
  reserves `olympus athena`, while keeping scanner algorithms and reporting in their current owners.
- **Verification:** the platform manifest contract locks the selected module and entrypoint; the ADR
  defines ownership, dependency, UX, and security boundaries without exposing a placeholder CLI.

### Cycle 5 — define Athena's target architecture

- **Task:** decide package boundaries, dependencies, execution, persistence, interfaces, and migration.
- **Result:** completed on 2026-08-24; ADR-002 defines an inward-dependency architecture, immutable
  domain contracts, typed ports/adapters, bounded local execution, transactional SQLite recovery,
  authorization/audit rules, an honest CLI-first UX, and capability-led migration.
- **Verification:** architecture contract tests (optional) cover every decision section and critical
  security invariant. (Historical note: an earlier mandatory `make check` gate was later removed —
  quality tooling is now optional and never blocks completion.)

### Cycle 6 — separate Argus domain scan from Typer

- **Task:** extract the first closed domain/application slice from the Argus `scan` handler.
- **Result:** completed on 2026-08-24; `DomainScanService` now owns scope-first orchestration through
  injected DNS and Certificate Transparency ports, while Typer only constructs dependencies,
  translates errors, exports assets, and renders output.
- **Verification:** direct offline tests prove successful orchestration and prove that out-of-scope
  targets are audited before either network-capable dependency is called.

### Cycle 7 — restore strict mypy portability in CI

- **Task:** fix the `click` import failure reported by the strict-mypy CI job.
- **Result:** completed on 2026-08-24; the parity test no longer imports Click directly and confines
  runtime CLI introspection to an explicit `Any` boundary around Typer's generated command.
- **Verification (historical):** at the time the focused contract test, mypy, and Ruff all ran clean.
  (These are optional tools today; the mandatory quality gate referenced here was later removed.)

### Cycle 8 — implement both integrations and restructure the surface

- **Task:** close ARGUS command parity, implement the Athena (Vulnerability Assessment Platform)
  application boundary end to end, and bring the README to the project's chosen standard.
- **Result:** completed on 2026-08-24.
  - **ARGUS parity:** added six real, tested `olympus argus` commands — `email`, `mac`, `myip`,
    `web`, `dns`, `whois` — as offline-first cores with injected HTTP/DNS ports, scope enforcement,
    authorization gating for privacy-sensitive enrichment, and `core.Asset`/`core.Finding` output.
    `docs/parity/argus.json` and its contract test now cover all thirteen commands.
  - **Athena / VAP:** implemented `olympus.athena` per ADR-002 — immutable `AssessmentPlan`
    contracts with a canonical digest, assessment/job state machines, typed ports, a closed adapter
    registry, three offline tool adapters (`web-headers`, `dns`, `whois`), a bounded synchronous
    coordinator (concurrency, per-job timeout, overall deadline, cooperative cancellation, crash
    recovery), a transactional SQLite repository with owner-only permissions and bounded results, a
    redacting audit sink, and a Vulcan-backed report renderer. The CLI exposes real
    `plan validate` / `run` / `status` / `cancel` / `recover` / `adapters` use cases with the
    canonical exit codes. `docs/parity/vulnerability-assessment-platform.json` flips the implemented
    capabilities and keeps honest `partial`/`missing` gaps (external-tool scanner suite and web UI).
  - **Restructuring/docs:** rewrote `README.md` to the ARGUS standard (moving the exhaustive guide to
    `docs/reference.md`), recorded upstream MIT provenance in `docs/provenance.md`, fixed the
    documented `olympus core export-schemas` directory-output mismatch, and added an example plan.
- **Verification (optional tooling):** at the time, Ruff, mypy, and the test suite all ran clean.
  These checks are optional helpers, not a gate. All network activity in tests is injected and offline.
- **Scope intentionally deferred:** the broad external-tool scanner suite (nmap, nuclei, sqlmap, …)
  as isolated subprocess adapters, the deferred Athena web API/UI (needs its own security ADR),
  opt-in authorized live-network smoke/e2e tests, and generated CLI reference docs.

### Cycle 9 — vendor the complete upstream tools and drop the mandatory gate

- **Task:** integrate ARGUS and the Vulnerability Assessment Platform at 100% feature parity (not
  demos/stubs), make the standalone repositories safe to delete, keep the README bilingual, and
  remove the mandatory strict-mypy/≥90%-coverage gate from the whole project.
- **Result:** completed on 2026-08-24.
  - **Bilingual README:** added `README-IT.md` and a language switcher to `README.md`, matching the
    ARGUS 🇬🇧/🇮🇹 standard.
  - **Complete vendored tools:** copied the full, unmodified upstream source of both tools under
    `vendor/argus/` and `vendor/vulnerability-assessment-platform/` (all modules, the complete VAP
    FastAPI app with ~40 routes, all **24 scanners**, database + Alembic migrations, reports,
    templates, static assets, background/Celery stack, tests, Dockerfiles, docker-compose, and
    licences). Wired them into `olympus` as first-class runnable commands: `olympus argus-native`
    (verbatim ARGUS CLI passthrough — verified: `ip`, `phone`, `mac`, `--help`, `--version`) and
    `olympus vap serve|migrate|scanners|info` (verified: the web app boots, auto-runs its migrations,
    and serves `/`, `/api/v1/scan-catalog`, `/api/v1/scans` with HTTP 200). Missing external binaries
    and services (Redis) fail gracefully with actionable messages. Added `[argus]`/`[vap]` extras,
    `scripts/setup-vendored-tools.sh`, feature-parity tests, and updated `docs/provenance.md`.
  - **Gate removal:** removed the mandatory strict-mypy + ≥90%-coverage gate everywhere — `Makefile`
    (`check` is now non-blocking), `pyproject.toml` (no coverage threshold; mypy annotated optional),
    `.github/workflows/ci.yml` (quality steps are `continue-on-error`), `.pre-commit-config.yaml`
    (mypy hook removed), `README`/`README-IT`, `upgrade.md`, and `docs/architecture/adr-002`. Mypy,
    tests, and coverage remain available as **optional** helpers that never block completion.
- **Verification (optional tooling):** the full offline test suite, Ruff, and mypy run clean; the
  vendored ARGUS CLI and the vendored VAP web app were both exercised end to end in this environment.
- **Definition of complete:** 100% functional feature parity, not a passing gate. Vendored code is
  preserved verbatim and held to its own tooling.

### Cycle 10 — ecosystem audit, AEGIS rename, diagnostics & full scanner coverage

- **Task:** audit every tool; rename the Olympus-facing VAP component to AEGIS;
  add diagnostics; document and cover all 24 scanners; analyse additional tools.
- **Result:** completed on 2026-08-24.
  - **Ecosystem audit:** `docs/ecosystem-audit.md` inventories all 12 tools with
    an honest per-tool matrix and verification status. Key honest finding: the 24
    vendored scanners default to **simulated** output unless `VAP_ENABLE_LIVE_SCANS=true`
    + the binary/API is present + authorization; this is surfaced, never hidden.
  - **AEGIS rename** (collision audit passed — `aegis` was unused): `olympus vap`
    → `olympus aegis` with subcommands serve / migrate / workers / scanners
    (`--check`) / deps / scan / info / doctor. `olympus vap` kept as a deprecated
    forwarding alias; `[vap]` extra aliases `[aegis]`; compose services renamed
    `aegis-*`; `Source.AEGIS` added. Vendored source and `VAP_*` contract left
    intact. Map: `docs/vap-to-aegis-rename.md`.
  - **Diagnostics:** `olympus doctor`, `olympus aegis doctor`, `olympus argus
    doctor`, and a secret-safe diagnostics helper; a 24-entry scanner registry
    (`olympus.integrations.scanners`) drives `aegis scanners --check` / `deps`.
  - **Scanner coverage:** `docker/Dockerfile.scanners` now installs 19/24
    open-source scanners (apt/pip/go/git/gem, best-effort); the 5 API/commercial
    engines are documented for manual install and surfaced by diagnostics.
    Matrix: `docs/scanner-matrix.md`. Unified install/ops: `docs/install.md`.
  - **Additional-tool analysis:** `docs/tooling-analysis.md` proposes an optional
    SCA/SBOM/container/IaC profile (OSV-Scanner, Syft, Grype, Trivy, Checkov) —
    presented for review, not implemented.
- **Verification (optional tooling):** full suite passes; ruff/mypy clean on new
  code; AEGIS web app boots + migrates + serves; compose config validated. No
  live scan / container `up` was run (no scanner binaries, no Docker daemon in
  this environment) — stated explicitly, not simulated.

### Cycle 11 — AEGIS native execution layer (no implicit simulation)

- **Task:** make AEGIS genuinely operational — eliminate implicit simulation,
  add real execution adapters with explicit states, correct the scanner
  classification, add Compose profiles, and prove real execution in a local lab.
- **Result:** completed on 2026-08-25.
  - **Explicit states (no fabrication):** new `olympus.aegis` package —
    `states` (live/unavailable/failed/disabled/simulation), `model`, `runner`
    (shell-free, timeout + process-group kill), `scope` (SSRF-aware; loopback
    lab targets allowed only when explicitly authorized), `base` orchestrator,
    and `olympus aegis run`. Simulation is produced **only** with `--simulate` /
    `AEGIS_SIMULATION_MODE=true`; a missing binary is `unavailable` (with install
    instructions), live-off is `disabled` — never a fake finding. Authorization
    and scope are mandatory (exit 3/4).
  - **Real adapters:** nmap (XML), nikto (text), wafw00f (JSON), sqlmap (text),
    whatweb (text), testssl (JSON) — real command construction + real parsers.
    Verified live end-to-end here against a local authorized lab: nmap, nikto,
    wafw00f, sqlmap (evidence in `docs/aegis-execution-evidence.md`). whatweb's
    apt binary has a broken Ruby env → honest `failed`. 18 native adapters remain
    pending (registry rejects them with a clear error, never a fabricated result).
  - **Classification fix:** added a `kind` taxonomy; ZAP and OpenVAS reclassified
    as `containerised-oss-service` (OSS), not commercial. Recalculated totals:
    **21/24 OSS**, 3 proprietary (nessus/acunetix/burp). Updated
    `docs/scanner-matrix.md`.
  - **Compose profiles:** `zap` (OWASP ZAP daemon), `gvm` (Greenbone GVM),
    `commercial-connectors` (Nessus, operator-provided image), `scanners-cli`;
    default lightweight stack unchanged. Validated with `docker compose config`.
  - **AEGIS_* config:** `olympus.aegis.config` reads `AEGIS_*` with legacy
    `VAP_*` fallback (`docs/aegis-config.md`); vendored `VAP_*` contract untouched.
- **Verification (optional tooling):** full suite passes (ruff + mypy clean over
  183 files); 4 scanners verified live end-to-end; all five states + scope/auth
  refusals demonstrated. Live execution of the other scanners and the container
  stack remains environment-dependent (documented, never simulated).
- **Held:** the optional SCA profile (OSV/Syft/Grype/Trivy/Checkov) is NOT
  implemented — deferred until AEGIS execution coverage is broader.

### Cycle 12 — separate Argus fronting orchestration from Typer

- **Task:** extract the next checklist-sized application slice: Argus `fronting`.
- **Result:** completed on 2026-08-25. `FrontingAssessmentService` now owns input-policy
  validation, scope authorization, and passive fronting orchestration through injected DNS and
  Certificate Transparency ports. The Typer handler is limited to dependency construction, error
  translation, presentation, and export.
- **Verification:** direct offline application tests prove execution without the CLI, rejection of
  an invalid fan-out limit, and that out-of-scope targets are audited before either network-capable
  dependency is invoked. Existing CLI fronting tests continue to cover output and exit semantics.
- **Scope intentionally deferred:** the repository-wide audit and remaining application-service
  extractions stay open; no broader completeness claim is made by this cycle.

### Cycle 13 — separate Argus DNS orchestration from Typer

- **Task:** extract the next checklist-sized application slice: Argus `dns`.
- **Result:** completed on 2026-08-25. `DnsLookupService` now owns record-type policy, scope
  authorization, and DNS-over-HTTPS orchestration through an injected HTTP port. The Typer handler
  is limited to dependency construction, error translation, presentation, and export.
- **Verification:** direct offline application tests prove execution without the CLI, normalization
  of requested record types, rejection of an empty record-type policy, and that out-of-scope
  targets are audited before HTTP is invoked. Existing DNS tests retain protocol and CLI coverage.
- **Scope intentionally deferred:** the remaining Argus application-service extractions stay open;
  no broader completeness claim is made by this cycle.

### Cycle 14 — separate Argus WHOIS/RDAP orchestration from Typer

- **Task:** extract the next checklist-sized application slice: Argus `whois`.
- **Result:** completed on 2026-08-25. `WhoisLookupService` now owns scope authorization and RDAP
  orchestration through an injected HTTP port. The Typer handler only wires dependencies, translates
  errors, and presents or exports the result.
- **Verification:** direct offline application tests prove successful RDAP execution without the CLI
  and prove that an out-of-scope target is audited before the HTTP dependency can be invoked.
- **Scope intentionally deferred:** the remaining Argus application-service extractions stay open;
  no broader completeness claim is made by this cycle.

### Cycle 15 — separate Argus web reconnaissance from Typer

- **Task:** extract the next checklist-sized application slice: Argus `web`.
- **Result:** completed on 2026-08-25. `WebReconService` now owns URL/host validation, scope
  authorization, passive HTTP orchestration, and mapping to shared asset/finding contracts through
  an injected HTTP port. The Typer handler retains error-to-exit-code translation and presentation.
- **Verification:** offline application tests prove successful contract mapping, invalid-target
  rejection, and out-of-scope audit before HTTP. Existing CLI semantics distinguish invalid input
  (exit 2), scope denial (exit 3), network failure (exit 4), and findings (exit 1).
- **Known limitation:** redirect destinations are followed by the shared urllib transport and are
  not re-authorized after each hop because its response contract does not expose redirect history.
  Redirect-aware transport hardening is tracked under the shared execution-policy task.
- **Scope intentionally deferred:** remaining Argus extractions and redirect hardening stay open.
