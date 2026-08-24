# Olympus Security — restructuring and integration checklist

This checklist is the source of truth for the restructuring of Olympus Security and for the
in-repository integration of [ARGUS](https://github.com/chiaraberti13/ARGUS) and the
[Vulnerability Assessment Platform](https://github.com/chiaraberti13/Vulnerability-Assessment-Platform).
Work proceeds one small, verifiable task at a time. A box may be checked only after its code,
tests, documentation, security review, and migration notes are complete.

## Status legend

- `[x]` complete and verified
- `[ ]` not started
- `[~]` partially implemented; the remaining acceptance criteria are listed beneath it
- `[!]` known problem or external blocker; this does not mean complete

## Non-negotiable acceptance rules

- The two upstream projects must be **implemented inside this repository**. Runtime Git
  dependencies, Git submodules, wrappers around an external checkout, and calls to a separately
  installed upstream CLI are not acceptable.
- Preserve upstream licences and attribution before copying or adapting any upstream code or
  assets. Record provenance per imported component.
- Existing users get documented command and data migrations; breaking changes require an explicit
  rationale.
- Network-active features require strict target validation, explicit authorization, bounded
  timeouts/concurrency, safe defaults, and audit-friendly errors.
- Secrets must never be committed, logged, placed in command examples, or returned in reports.
- A task is complete only when `make check` passes and its user-facing behavior is documented.
- No placeholder UI, simulated success, or disconnected feature is considered an implementation.

## Baseline audit — 2026-08-24

### Confirmed present

- [x] Inventory the local package layout and unified CLI registration.
  - Nine modules are registered under `olympus`: Argus, Helios, Artemis, Proteus, Hermes, Apollo,
    Minerva, and Vulcan, plus the shared `core` commands.
  - Shared Pydantic contracts and centralized configuration/HTTP/output utilities already exist.
- [x] Locate the existing project checklist.
  - No checklist or equivalent roadmap was present; this file now establishes it.
- [x] Record the initial quality-gate state without weakening it.
  - The project requires Python 3.11+, Ruff, strict mypy, pytest, and at least 90% coverage.
  - The current environment lacks the `pytest-cov` plugin, so the configured test command cannot
    run here until development dependencies are installed.

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
  - [ ] **Next task: Argus `fronting` application service.**
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

- [x] Close every gap in the approved ARGUS parity manifest without runtime dependence on the
  standalone repository.
  - The six missing standalone-ARGUS capabilities are now first-class `olympus argus` commands:
    `email`, `mac`, `myip`, `web`, `dns`, and `whois`, alongside the existing scope-first commands.
- [x] Preserve or deliberately migrate all supported ARGUS inputs, commands, outputs, and workflows.
- [x] Add unit, contract, and offline integration tests for every imported capability.
- [ ] Add bounded live-network smoke tests that are opt-in and restricted to authorized fixtures.
- [x] Document ARGUS migration, examples, limitations, and provenance (`docs/provenance.md`, README).

## Phase 4 — complete in-repository Vulnerability Assessment Platform integration

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
- **Verification:** architecture contract tests require every decision section and critical security
  invariant; `make check` remains the completion gate.

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
- **Verification:** the focused contract test, strict mypy, Ruff, and the complete quality gate pass
  without weakening mypy configuration or ignoring missing imports.

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
- **Verification:** `make check` passes — Ruff, strict mypy across 160+ source files, and the
  coverage gate at 93.5% (≥90%). All network activity in tests is injected and offline.
- **Scope intentionally deferred:** the broad external-tool scanner suite (nmap, nuclei, sqlmap, …)
  as isolated subprocess adapters, the deferred Athena web API/UI (needs its own security ADR),
  opt-in authorized live-network smoke/e2e tests, and generated CLI reference docs.
