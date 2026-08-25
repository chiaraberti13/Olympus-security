# Shared execution policy

`olympus.core.execution.ExecutionPolicy` is the common boundary around live or
resource-consuming work. It does not replace module-specific scope formats; it
standardizes the order and bounds in which every scope checker and adapter runs.

## Required order

1. Parse input without network or process execution.
2. Validate the execution policy and explicit authorization.
3. Apply the module's dedicated scope gate (domain/URL, resolved IP/CIDR,
   E.164 prefix, OUI, exact handle, or another reviewed dialect).
4. Check cancellation immediately before dispatch.
5. Execute through an injected adapter with the policy timeout, retry budget,
   concurrency, overall deadline, and rate interval.
6. Normalize real results into versioned contracts.
7. Persist a structured audit record after recursive secret/URL-query redaction.

Authorization must precede scope and scope must precede traffic. Discovered
pivots and HTTP redirects repeat scope validation immediately before their own
network action.

## Global bounds

| Setting | Accepted range |
| --- | --- |
| Per-operation timeout | 0.05–3600 seconds |
| Overall deadline | 0.05–86400 seconds |
| Concurrency | 1–64 |
| Retries | 0–5 additional attempts |
| Backoff | 0–60 seconds |
| Minimum request interval | 0–60 seconds |

Modules may impose tighter bounds. They must not silently clamp or widen an
invalid operator value. Retried actions must be read-only/idempotent and retry
only explicit transient failures.

## Cancellation and audit

`CancellationToken` is thread-safe and cooperative. Workers and adapters check
it before starting and between retry attempts; bounded transport/subprocess
timeouts remain mandatory because Python cannot forcibly stop an arbitrary
thread safely.

`StructuredAuditRecord` recursively redacts keys containing authorization,
cookie, credential, password, secret, token, API-key, or access-key markers.
Sensitive URL query values are replaced while non-sensitive routing context is
retained. Athena's narrower allowlist remains an additional protection and now
uses the same URL redactor before SQLite persistence.

## Adoption status

- Core HTTP: validated timeout/retry/backoff/rate policy and cooperative
  cancellation before dispatch/retry.
- ARGUS: shared authorization errors and shared account-concurrency validation;
  dedicated domain/IP/phone/OUI/handle/URL scope gates remain authoritative.
- Athena: plan limits become one shared policy; its formerly unused retry budget
  now drives transient adapter retries, cancellation tokens are issued per job,
  and audit URL queries are redacted before storage.
- Helios: the application service validates ports, requires explicit authorization,
  applies CIDR scope, observes cancellation between probes, and emits versioned
  observations/findings. Scope denials use the shared redacted NDJSON audit format.
- Artemis: every active web command supplies an explicit policy to the DNS-pinned
  transport. Authorization and URL/IP scope precede DNS and traffic; redirects repeat
  scope checks; retries cover transport failures only; rate waits and each request obey
  cancellation and an overall deadline. No low-level network API assumes authorization.
- Proteus: campaign creation requires explicit authorization at both application and
  domain boundaries. Engagement, sender, recipient domains and the HTTPS training origin
  are scope-checked before token generation; cancellation is cooperative, and structured
  audit records contain recipient hashes/domains rather than complete email addresses.
- Hermes: local scans do not invent an authorization requirement, but use shared strict
  timeout/deadline validation and cooperative cancellation. Working-tree enumeration,
  file bytes/counts, Git commits/output, process lifetime and generated artifacts are
  independently bounded; symlinks and non-regular explicit inputs fail closed.
- Apollo, Minerva, Vulcan, and AEGIS adoption is tracked in
  `upgrade.md`; offline-only work uses the same validation/redaction pieces where
  applicable but does not invent network authorization requirements.
