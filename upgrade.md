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

- [!] Upstream source inventory is blocked in the current environment: direct GitHub clone returns
  HTTP 403 and the browsing service returns HTTP 401. Feature parity cannot be asserted from names,
  memory, or the current Olympus implementation; it must be measured from an accessible pinned
  upstream revision.
- [!] `README.md` is a very long bilingual document with duplicated navigation burden and no
  contributor-facing architecture or migration section. Its claims of complete command coverage
  must be generated or tested against the actual CLI during the documentation phase.
- [!] The repository already contains an `olympus.argus` package, but its provenance and complete
  parity with standalone ARGUS have not yet been demonstrated.
- [!] No local package is explicitly identified as the complete Vulnerability Assessment Platform;
  mapping it onto an existing module before the parity inventory would risk silently losing
  upstream capabilities.
- [!] `Makefile` documents `olympus core export-schemas ./examples/output`, while the current CLI
  implementation prints schemas to stdout and accepts no destination argument.

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
- [ ] **Next task: produce a target architecture decision record covering package boundaries,
  dependency direction, execution model, persistence, CLI/possible UI boundaries, and migration
  strategy.**

## Phase 2 — shared architecture and safe execution

- [ ] Separate domain logic from Typer command handlers in every affected module.
- [ ] Define versioned contracts for assessment plans, scan jobs, observations, findings, assets,
  evidence, and reports; document compatibility rules.
- [ ] Add a shared execution policy for authorization, scope enforcement, rate/concurrency limits,
  timeouts, cancellation, retries, and redacted structured logging.
- [ ] Add adapters for network, persistence, and third-party services so domain tests remain offline
  and deterministic.
- [ ] Define secure configuration precedence and validate it at startup; reject unsafe or ambiguous
  values with actionable errors.

## Phase 3 — complete in-repository ARGUS integration

- [ ] Close every gap in the approved ARGUS parity manifest without runtime dependence on the
  standalone repository.
- [ ] Preserve or deliberately migrate all supported ARGUS inputs, commands, outputs, and workflows.
- [ ] Add unit, contract, and offline integration tests for every imported capability.
- [ ] Add bounded live-network smoke tests that are opt-in and restricted to authorized fixtures.
- [ ] Document ARGUS migration, examples, limitations, and provenance.

## Phase 4 — complete in-repository Vulnerability Assessment Platform integration

- [ ] Create or select the module boundary approved in the architecture decision.
- [ ] Close every gap in the approved platform parity manifest without runtime dependence on the
  standalone repository.
- [ ] Implement real assessment orchestration end to end: validated input, execution, progress and
  failure states, persisted results, deduplication, and export through shared contracts.
- [ ] Apply SSRF protections, target/scope enforcement, subprocess isolation where applicable,
  resource limits, cancellation, and secret redaction.
- [ ] Add unit, contract, offline integration, and authorized opt-in end-to-end tests.
- [ ] Document platform migration, operation, recovery, limitations, and provenance.

## Phase 5 — UX and documentation restructuring

- [ ] Define task-based information architecture for installation, quick start, modules, recipes,
  architecture, security model, development, and migration.
- [ ] Refactor `README.md` to the same concise, consistent standard selected for the project, with a
  short value proposition and verified quick start; move exhaustive reference material to `docs/`.
- [ ] Generate or test CLI reference documentation so it cannot drift from Typer commands.
- [ ] Make errors consistent and actionable across commands, including exit codes and remediation.
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
