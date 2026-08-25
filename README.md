<div align="center">

```
  ___  _  _   _ __  __ ___ _   _ ___
 / _ \| || | | |  \/  | _ \ | | / __|
| (_) | || |_| | |\/| |  _/ |_| \__ \
 \___/|____\__, |_|  |_|_|  \___/|___/
           |___/
```

# 🏛️ Olympus Security

**One CLI for the whole engagement — recon, assessment, exploitation support, detection and reporting.**
*A single binary, one shared data contract, offline-first and scope-safe by design.*

<p align="center">
  <a href="README.md">🇬🇧 English</a> | <a href="README-IT.md">🇮🇹 Italiano</a>
</p>

<p align="center">
  <a href="https://github.com/chiaraberti13/olympus-security/actions"><img src="https://img.shields.io/badge/CI-GitHub%20Actions-blue?style=for-the-badge" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green?style=for-the-badge" alt="License"></a>
  <img src="https://img.shields.io/badge/python-3.11%2B-blue?style=for-the-badge" alt="Python 3.11+">
  <img src="https://img.shields.io/badge/modules-10-blue?style=for-the-badge" alt="10 modules">
</p>

</div>

> [!IMPORTANT]
> **For authorized security testing, research and education only.**
> Every network-active command validates its target against an explicit
> engagement scope and blocks (and audits) anything outside it. You are solely
> responsible for using Olympus **lawfully and with documented authorization**.
> Read the **[legal notice](#-legal--ethical-use)** before use.

---

## Quick Navigation

- **[What is Olympus?](#what-is-olympus)** — what it does, and who it's for.
- **[Modules](#-modules)** — every tool, what it does, and its entry point.
- **[Installation](#-installation)** — one command, Python 3.11+.
- **[Quick start](#-quick-start)** — a verified recon → assessment → report path.
- **[Configuration](#-configuration)** — scope files, config, and secrets.
- **[Project structure](#-project-structure)** — how the repository is laid out.
- **[Development](#-development)** — optional quality tooling (never a gate).
- **[Security model](#-security-model)** — scope, authorization, SSRF, audit.
- **[Migration](#-migration)** — ARGUS and the Vulnerability Assessment Platform.
- **[License](#-license)** — MIT, for the whole repository.
- **[Legal & ethical use](#-legal--ethical-use)** — authorized-only, in practice.

---

## What is Olympus?

Olympus is an offensive-and-defensive security platform driven through a single
binary. Instead of a drawer of unrelated scripts, every capability is a
sub-command of one CLI and speaks the **same data contract** — the same
`Asset`, `Finding`, `Event`, `Evidence`, `Alert` and `Incident` produced by one
module can be consumed by any other without translation.

Two design rules run through the whole project:

- **Offline-first, injected I/O.** Domain logic never talks to the network
  directly; it depends on small typed ports (HTTP client, DNS resolver, tool
  runner) so tests are deterministic and offline, and production wires in the
  real transport.
- **Scope-safe by construction.** Every command that touches a live target
  checks it against an explicit authorized scope first, blocks out-of-scope
  targets, and writes an audit record — never a silent drop.

```console
$ olympus --help
$ olympus argus dns --domain example.com --scope scope.json
$ olympus athena run plan.json --storage ./.athena
```

## 🧰 Modules

| Module | Entry point | What it does |
| --- | --- | --- |
| **Argus** | `olympus argus` | OSINT & passive recon: DNS, WHOIS/RDAP, web headers, IP, phone, email, MAC, accounts, CDN fronting, investigation graphs. |
| **Athena** | `olympus athena` | Assessment **orchestration & lifecycle**: validated plans, bounded job execution, durable SQLite storage, audit trail, reporting. |
| **Helios** | `olympus helios` | Scoped surface scanning and finding export. |
| **Artemis** | `olympus artemis` | Web application probing (fingerprint, content, XSS) within scope. |
| **Proteus** | `olympus proteus` | Social-engineering campaign modelling (authorized, simulated). |
| **Hermes** | `olympus hermes` | Secret & sensitive-data scanning with SARIF output. |
| **Apollo** | `olympus apollo` | Detection rules engine (red/blue) over normalized events. |
| **Minerva** | `olympus minerva` | Incident triage and chain-of-custody records. |
| **Vulcan** | `olympus vulcan` | Aggregation, deduplication, ranking and report rendering. |
| **core** | `olympus core` | Shared data-contract utilities (e.g. `export-schemas`). |
| **ARGUS (complete)** | `olympus argus-native` | The full standalone ARGUS OSINT CLI, vendored verbatim under `vendor/` — every original subcommand plus the interactive menu. |
| **AEGIS (complete)** | `olympus aegis` | The full Vulnerability Assessment Platform, vendored verbatim — FastAPI web app, all **24 scanners**, database + migrations, reports. |

> [!TIP]
> Run any module with `--help` to see its commands, or
> `olympus <module> <command> --help` for a command's options.

## 🚀 Installation

Olympus requires **Python 3.11+**.

```bash
git clone https://github.com/chiaraberti13/olympus-security
cd olympus-security
python -m pip install -e ".[dev]"      # or: make install
olympus --version
```

## 🎯 Quick start

Every network-active command needs a scope file naming the domains you are
authorized to touch:

```bash
cat > scope.json <<'JSON'
{ "engagement": "demo-2026", "allowed_domains": ["example.com"] }
JSON
```

Passive recon with Argus (writes a `core.Asset`/`core.Finding` bundle):

```bash
olympus argus dns   --domain example.com --scope scope.json
olympus argus whois --domain example.com --scope scope.json
olympus argus web   --url https://example.com --scope scope.json --output web.json
```

Orchestrate a whole assessment with Athena, then read the results:

```bash
olympus athena plan validate examples/input/athena-plan.json
olympus athena run examples/input/athena-plan.json --storage ./.athena --report
olympus athena status <ASSESSMENT_ID> --storage ./.athena
```

Athena exits `0` (clean), `1` (findings/partial), `2` (invalid input),
`3` (scope denial) or `4` (execution failure), so it scripts cleanly in CI.

## ⚙️ Configuration

- **Scope files** (JSON) authorize targets per engagement:
  `{"engagement": "...", "allowed_domains": [...], "excluded_domains": [...]}`.
  Argus IP/phone/account scopes use their own keys — see
  [`examples/input/`](examples/input).
- **`olympus.toml`** (optional) sets shared HTTP defaults; resolution order is
  `OLYMPUS_CONFIG` → `./olympus.toml` → `~/.olympus.toml`.
- **Secrets** are read only from environment variables (e.g.
  `OLYMPUS_NUMVERIFY_KEY`) and are **never** logged, exported, or placed in
  reports.

## 🗂️ Project structure

```text
src/olympus/
├── cli.py            # unified `olympus` entry point
├── core/             # shared data contract: models, enums, http, config, ids
├── argus/            # OSINT & passive recon (incl. ARGUS integration)
├── athena/           # assessment orchestration (VAP integration)
│   ├── domain/       # immutable plans, jobs, state machines, audit
│   ├── application/  # coordinator, registry, planning use cases
│   ├── adapters/     # sqlite, audit, reporting, and tool adapters
│   └── cli.py
├── helios/ artemis/ proteus/ hermes/ apollo/ minerva/ vulcan/
docs/                 # architecture (ADRs), parity manifests, reference
examples/             # scope files, plans, sample inputs/outputs
tests/                # offline, deterministic unit & contract tests
```

## 🧪 Development

Quality tooling is **optional** and never blocks work: linting, type checking,
tests, and coverage are helpers, not a completion gate. A tool is "complete"
when it has 100% functional feature parity — not when a gate passes.

```bash
make lint      # ruff (optional)
make type      # mypy   (optional)
make test      # pytest (optional)
make check     # runs all three, non-blocking — informational only
```

See [`docs/architecture/`](docs/architecture) for the accepted design decisions,
[`docs/parity/`](docs/parity) for the upstream capability manifests, and
[`vendor/`](vendor) for the complete, in-repository upstream tools.

## 🔐 Security model

- **Scope enforcement** precedes any live lookup; blocked targets are audited.
- **Explicit authorization** (`--i-am-authorized`) gates privacy-sensitive
  OSINT (e.g. phone/email enrichment about a real person).
- **SSRF guard**: Athena adapters reject targets resolving to non-global IP
  literals and re-validate scope before every request.
- **Bounded execution**: shared HTTP timeouts/retries/rate limits, and Athena
  concurrency, per-job timeouts and overall deadlines with safe maxima.
- **Redacted audit trail**: append-only events with allowlisted metadata only —
  never credentials, bodies, or raw findings.

## 🔁 Migration & vendored tools

The standalone **ARGUS** OSINT toolkit and **Vulnerability Assessment Platform**
are implemented **inside this repository** — no submodule, wrapper, or external
CLI at runtime. The **complete, unmodified upstream source** of each is vendored
under [`vendor/`](vendor) and wired into `olympus` as first-class commands, so
the original repositories can be deleted without losing anything:

```bash
bash scripts/setup-vendored-tools.sh      # install both tools' dependencies

olympus argus-native --help               # the complete ARGUS CLI (verbatim)
olympus argus-native ip 8.8.8.8

olympus aegis scanners                      # all 24 scanner integrations
olympus aegis migrate                       # apply the VAP database migrations
olympus aegis serve --host 127.0.0.1 --port 8000   # serve the full VAP web app
```

### Running the complete VAP platform: native or Docker

**Native (single process, via Olympus):**

```bash
pip install -e ".[aegis]"            # or: bash scripts/setup-vendored-tools.sh
olympus aegis migrate               # apply the database migrations
olympus aegis serve --host 127.0.0.1 --port 8000
```

Redis is optional on the native path: synchronous features work without it, and
queued scans are disabled with a clear warning until Redis is running.

**Docker (full stack, one command):**

```bash
docker compose up --build         # redis + migrate + app + worker
docker compose down               # stop
docker compose down -v            # stop and remove the data volumes
# ...with the open-source scanner binaries baked in:
docker compose -f docker-compose.yml -f docker-compose.scanners.yml up --build
```

| Aspect | What the root `docker-compose.yml` provides |
| --- | --- |
| **Services** | `redis` (broker + result backend + API cache), `migrate` (one-shot Alembic), `app` (FastAPI web app), `worker` (Celery scan worker) |
| **Ports** | app on `http://localhost:8000` (override with `VAP_PORT`); Redis is **not** published to the host |
| **Volumes** | `vap-data` → `/data` (SQLite DB + generated reports), `redis-data` |
| **Initialization / migrations** | `migrate` runs `alembic upgrade head` and must finish (`service_completed_successfully`) before `app` and `worker` start; the app also self-migrates on boot |
| **Health checks** | app `GET /health`, `redis-cli ping`, `celery inspect ping` (with `depends_on: condition: service_healthy`) |
| **Environment** | `VAP_PORT`, `VAP_ENABLE_LIVE_SCANS` (default `false`), `VAP_REQUIRE_HTTPS`, `VAP_DATABASE_URL`, `VAP_CELERY_*`, `VAP_API_CACHE_*`, and secrets `VAP_API_KEY` / `VAP_JWT_SECRET` / `VAP_CSRF_SECRET` — documented in [`.env.docker.example`](.env.docker.example) |
| **Scanner dependencies** | The default image is Python-only, so a scanner whose binary is absent reports a clear "tool not installed" state. `docker-compose.scanners.yml` + [`docker/Dockerfile.scanners`](docker/Dockerfile.scanners) add the reliably-installable open-source scanners (nmap, nikto, whatweb, sqlmap, wafw00f, arjun, wapiti); Go-based (nuclei, httpx, katana, subfinder, dalfox), Ruby (wpscan), and commercial engines (burp, acunetix, nessus, openvas) are installed separately per their own licences |
| **Safe defaults** | live scanning off, HTTPS enforcement configurable, Redis unpublished, secrets blank by default |

For a hardened/HTTPS deployment or PostgreSQL instead of SQLite, set the
corresponding `VAP_*` variables (see `vendor/vulnerability-assessment-platform/.env.example`).

**Real scans, never fabricated:** `olympus aegis run <scanner> --target <t> --scope s.json --i-am-authorized` runs a real scanner with explicit states — `live` / `unavailable` / `failed` / `disabled` / `simulation`. Simulation is produced **only** with `--simulate` (or `AEGIS_SIMULATION_MODE=true`); a missing binary yields `unavailable`, never a fake finding. See [`docs/scanner-matrix.md`](docs/scanner-matrix.md) and [`docs/aegis-execution-evidence.md`](docs/aegis-execution-evidence.md).

External scanner **binaries** and the full runtime (Redis/Celery) are also
provisioned by the vendored `installer.sh` for a non-container setup; a scanner
with no binary present always reports "tool not installed" rather than failing
silently.

Olympus also ships **native** re-implementations: `olympus argus …`
(scope-first OSINT) and `olympus athena …` (assessment orchestration). Their
capability contracts and provenance are pinned in
[`docs/parity/`](docs/parity) and [`docs/provenance.md`](docs/provenance.md);
Athena's architecture is [ADR-002](docs/architecture/adr-002-athena-target-architecture.md).
Exhaustive walkthroughs live in [`docs/reference.md`](docs/reference.md).

## 📄 License

MIT — see [LICENSE](LICENSE). The same license covers the whole repository,
including the in-repository ARGUS and Vulnerability Assessment Platform
integrations.

## ⚠️ Legal & ethical use

Olympus performs **authorized** security testing. Passive modules query only
publicly available information; active modules connect only to targets inside a
declared scope. Use it exclusively where you have **documented permission**
(your own systems, a signed engagement, or a lab you control). Misuse is your
responsibility alone.
