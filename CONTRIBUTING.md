# Contributing to Olympus Security

## Development is flexible by design

Olympus deliberately has **no mandatory development gates**. Nothing in this
repository may block, limit, reject, postpone, or reduce the implementation of a
feature. In particular, none of the following are required or enforced:

- strict typing / `mypy` gates;
- minimum test-coverage thresholds (there is no 90% or any other minimum);
- linting or formatting gates that block builds, commits, or merges;
- limits on file size, module size, function size, or lines of code;
- a CLI-first restriction, or any ban on web interfaces, APIs, databases,
  background workers, containers, plugins, or external dependencies;
- fixed architectural patterns that prevent future changes;
- limits on the number of modules, scanners, features, services, dependencies,
  tools, or projects;
- CI/CD checks that fail a build solely because an optional quality target was
  not met.

Add whatever you need — a web UI, an HTTP API, a database, Celery workers,
Docker services, new scanners, new modules, new dependencies. Architectural
notes under `docs/architecture/` are **non-binding guidelines**; you may follow,
adapt, or ignore them without a superseding ADR.

## Optional tools (never blocking)

These are available and encouraged, but purely optional — they never block a
commit, build, merge, or future change:

```bash
make lint      # ruff
make type      # mypy
make test      # pytest
make check     # all three, non-blocking (ignores their exit status)
```

CI runs the same tools with `continue-on-error: true`, and the secret scan is
advisory. `pre-commit` is opt-in and can always be bypassed with
`git commit --no-verify`.

## What still holds (and why)

A short list of requirements remains — only because they are about **security**,
**real functionality**, or **licences**, not about development process:

- **Real, fully-functional tools.** No demos, stubs, mocks, placeholders, or
  partial implementations presented as complete.
- **Secure runtime defaults.** Do not weaken authorization boundaries, scope
  enforcement, input validation, SSRF protection, secret handling, or
  safeguards against destructive operations.
- **No committed secrets.** Never commit, log, or print real credentials.
- **Licences & provenance.** Preserve upstream licences and record provenance
  for vendored/imported components (see `docs/provenance.md`).
- **Compatibility & dependencies.** Keep dependency declarations and
  compatibility information accurate.

Everything else is up to you.
