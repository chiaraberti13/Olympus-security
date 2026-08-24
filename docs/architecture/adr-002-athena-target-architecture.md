# ADR-002: Athena target architecture

- **Status:** Accepted
- **Date:** 2026-08-24
- **Depends on:** ADR-001
- **Applies to:** the future `olympus.athena` package and `olympus athena` CLI

## Context and quality attributes

Athena will absorb the assessment-lifecycle responsibilities identified by the Vulnerability
Assessment Platform parity manifest while composing Olympus tools rather than duplicating them. The
architecture must prioritize authorization integrity, deterministic recovery, bounded resource use,
partial-result honesty, testability without network access, and a CLI that explains failures without
exposing secrets.

The first supported deployment is a single trusted operator on one host. Multi-user service mode and
a web UI are deliberately deferred: adding either before authentication, authorization, tenancy,
and CSRF/session boundaries exist would create an unsafe implied security model.

## Package boundaries and dependency direction

The target package layout is:

```text
olympus/athena/
├── domain/          # immutable plans, jobs, assessments, transitions; no I/O imports
├── application/     # use cases and orchestration; depends on domain + ports
├── ports/           # Protocol interfaces for runners, repository, clock, IDs, audit, reports
├── adapters/
│   ├── tools/       # in-process adapters for Argus/Helios/Artemis/Hermes/Vulcan
│   ├── sqlite.py    # durable repository implementation
│   └── audit.py     # redacted append-only audit implementation
└── cli.py           # validation/presentation only; calls application use cases
```

Dependencies point inward:

```text
cli ───────────────┐
sqlite/audit ──────┼──> ports <── application ──> domain
tool adapters ─────┘          │
                              └── orchestration policy

tool adapters ──> existing Olympus module APIs
existing modules -X-> athena
domain/application -X-> typer, sqlite3, filesystem, network, existing tool implementations
```

`domain` contains no framework or infrastructure imports. `application` sees integrations only as
typed ports. Adapters may depend on existing modules, but existing modules cannot import Athena.
Circular imports and direct application-to-adapter imports are architecture violations.

## Domain contracts

All persisted contracts carry `schema_name` and integer `schema_version`, reject unknown fields, and
serialize timestamps as UTC ISO 8601. IDs use the existing core ID conventions.

### AssessmentPlan

An immutable plan contains:

- engagement ID and human-readable name;
- one or more normalized target references;
- selected adapter names from a closed registry;
- a scope reference plus its SHA-256 digest;
- immutable authorization context reference, never credentials;
- concurrency, per-job timeout, overall deadline, and retry limits within safe maxima;
- output policy and retention duration.

The persisted plan stores the canonical JSON digest. A changed plan creates a new plan ID; it never
mutates a running or historical assessment.

### Assessment and Job

An assessment references its plan and owns ordered job IDs, aggregate status, timestamps, redacted
failure summaries, result references, and audit sequence. Each job represents exactly one adapter
invocation for one normalized target. Raw secrets, provider tokens, and arbitrary command strings are
forbidden fields.

The state machines are:

```text
assessment: planned -> running -> succeeded | partial | failed | cancelled
job:        queued  -> running -> succeeded | failed | timed_out | cancelled
```

Terminal states never transition. `succeeded` requires every job to succeed; mixed terminal job
states produce `partial`; zero successful jobs with any failure produces `failed`; cancellation is
explicit and never reported as failure or success. Every accepted transition and rejection is
audited.

## Ports and adapter contract

The application layer depends on these minimum ports:

- `AssessmentRepository`: atomic plan/assessment/job reads, compare-and-set transitions, result
  references, and recovery queries;
- `ToolRunner`: stable name/capabilities plus `run(request, cancellation)` returning normalized,
  bounded results;
- `ReportRenderer`: renders through Vulcan without copying its logic;
- `AuditSink`: append-only structured events with monotonic per-assessment sequence numbers;
- `Clock` and `IdProvider`: injected for deterministic tests;
- `Cancellation`: cooperative token checked before and during bounded work.

Adapters receive typed requests, not CLI argument arrays. They must validate scope again, translate
only expected exceptions into redacted error codes, cap output size, and return shared `Asset` and
`Finding` contracts. Unknown adapters are rejected before an assessment is persisted.

## Execution model

The first implementation is a synchronous local coordinator with a bounded worker pool. It does not
spawn a daemon and does not claim distributed execution.

1. Parse and validate the complete plan without network activity.
2. Resolve adapter names from a closed in-process registry.
3. Persist the plan and `planned` assessment atomically.
4. Revalidate authorization/scope digest immediately before execution.
5. Transition to `running`, enqueue a deterministic job list, and execute at most the plan's bounded
   concurrency.
6. Enforce a monotonic overall deadline and per-job timeout. Retries apply only to explicitly
   retryable transport errors, use bounded backoff, and never bypass scope checks.
7. Persist each terminal job and result reference before scheduling more work.
8. Derive and persist the terminal assessment state, then request optional Vulcan reports.

Cancellation prevents queued work from starting and signals running adapters cooperatively. A tool
that cannot guarantee cooperative cancellation is not eligible for the initial registry. Python
threads cannot safely kill arbitrary work, so timeout-capable network primitives remain mandatory.

## Persistence and recovery

Use Python's `sqlite3` for the initial local repository, with foreign keys enabled, WAL mode, a busy
timeout, and transactions for every state transition. The database contains separate versioned
tables for plans, assessments, jobs, result references, and audit events. Large result documents are
written to an assessment-owned directory using create-temporary, `fsync`, atomic rename, and then a
database reference containing SHA-256 and byte length.

Security and integrity rules:

- database and result directories are created with owner-only permissions;
- paths are generated from validated IDs and resolved below the configured storage root;
- user-provided filenames, absolute paths, and `..` traversal are rejected;
- result size and total assessment storage are capped;
- provider credentials and raw discovered secrets are never persisted;
- schema migrations run inside a transaction, create a backup, and fail closed on unknown versions;
- retention deletion is explicit, audited, and confined to the assessment-owned directory.

On startup, recovery changes persisted `running` jobs to `failed` with the stable code
`interrupted`, then derives `partial` or `failed` for the assessment. Athena never silently reruns a
job after a process crash because network actions may not be idempotent; the operator must explicitly
start a new assessment from the immutable plan.

## Authorization, audit, and sensitive data

Authorization context records engagement and scope identity, scope digest, confirmation timestamp,
and operator-supplied reference to documented approval. It is immutable for the assessment. It is
not a replacement for each tool's scope enforcement.

Audit events contain event ID, assessment/job ID, sequence, UTC timestamp, action, outcome, and a
small allowlisted metadata object. Targets are normalized and minimally represented; credentials,
HTTP bodies, environment values, exception representations, and raw findings are prohibited. Error
messages shown to users are derived from stable codes with actionable remediation, while debug detail
remains redacted by default.

## CLI and future API/UI boundaries

The first functional slice exposes only CLI commands backed by real use cases:

```text
olympus athena plan validate PLAN.json
olympus athena run PLAN.json --storage PATH
olympus athena status ASSESSMENT_ID --storage PATH
olympus athena cancel ASSESSMENT_ID --storage PATH
```

`run` prints the assessment ID immediately, displays deterministic job progress when attached to a
terminal, and always supports machine-readable JSON. Exit `0` means succeeded, `1` partial/findings,
`2` invalid input/configuration, `3` authorization/scope denial, and `4` execution/infrastructure
failure. Cancellation has its own explicit result and is never formatted as success.

The CLI contains no domain decisions. A future HTTP API may call the same application use cases but
requires a separate accepted ADR covering authentication, authorization, tenancy, rate limits,
request-size limits, CSRF/CORS, and deployment. A web UI is not served from Athena until that API
boundary exists; no placeholder dashboard is permitted.

## Migration strategy

Migration from the standalone Vulnerability Assessment Platform is capability-led rather than a
file-for-file copy:

1. Preserve the upstream licence and component-level provenance before adapting source or assets.
2. Translate input into versioned `AssessmentPlan`; reject ambiguous fields instead of guessing.
3. Implement one in-process adapter at a time with offline contract tests.
4. Import historical results only through a versioned, dry-run-capable command that validates every
   record and produces a rejection report; never execute scans during import.
5. Keep original IDs as `legacy_id` metadata while issuing canonical Olympus IDs.
6. Compare normalized findings and reports against pinned fixtures before declaring capability
   parity.
7. Do not remove or deprecate standalone Olympus module commands; Athena composes their domain APIs.

There is no runtime compatibility layer to the external repository. Unsupported upstream behavior
remains an explicit manifest gap until implemented and tested in this repository.

## Delivery slices and acceptance

Implementation proceeds in closed vertical slices:

1. domain contracts and transition tests;
2. repository port plus SQLite persistence/recovery tests;
3. runner port plus one offline adapter and bounded coordinator;
4. real CLI `plan validate/run/status/cancel` workflows;
5. remaining adapters, Vulcan reporting, and migration importer;
6. optional API/UI only after its security ADR.

No slice is complete without unit tests, offline integration tests, strict typing, linting, at least
90% project coverage, documentation, and threat-boundary review. Live-network tests remain opt-in,
bounded, and scoped to explicitly authorized fixtures.

## Consequences

This architecture adds adapter and persistence code but keeps scanners reusable, the domain
deterministic, and infrastructure replaceable. SQLite intentionally limits initial horizontal scale;
the repository port permits a later backend without changing domain/application logic. Deferring the
web surface reduces immediate UX breadth but avoids shipping unauthenticated or misleading UI.
