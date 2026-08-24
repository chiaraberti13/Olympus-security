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
  <img src="https://img.shields.io/badge/typed-strict%20mypy-informational?style=for-the-badge" alt="Strict mypy">
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
- **[Development](#-development)** — the single `make check` quality gate.
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

The project has a single quality gate — *green or not done*:

```bash
make check     # ruff (lint) + strict mypy + tests with ≥90% coverage
```

Ruff, strict `mypy`, and a dependency-free coverage gate all run in CI.
See [`docs/architecture/`](docs/architecture) for the accepted design decisions
and [`docs/parity/`](docs/parity) for the upstream capability manifests.

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

## 🔁 Migration

The standalone **ARGUS** OSINT toolkit and **Vulnerability Assessment Platform**
are implemented **inside this repository** — no submodule, wrapper, or external
CLI at runtime. Their capability contracts and provenance are pinned in
[`docs/parity/`](docs/parity), and Athena's target architecture is recorded in
[ADR-002](docs/architecture/adr-002-athena-target-architecture.md).

- ARGUS commands map to `olympus argus …` (see the module `--help`).
- Vulnerability-assessment orchestration maps to `olympus athena …`.

Exhaustive command walkthroughs (including the guided practice-target path) live
in [`docs/reference.md`](docs/reference.md).

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
