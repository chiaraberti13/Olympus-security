<div align="center">

```
     _    ____   ____ _   _ ____
    / \  |  _ \ / ___| | | / ___|
   / _ \ | |_) | |  _| | | \___ \
  / ___ \|  _ <| |_| | |_| |___) |
 /_/   \_\_| \_\\____|\___/|____/
```

# 👁️ Argus

**The all-seeing OSINT & reconnaissance toolkit**
*IP · Domain · DNS · Phone · Username · Email · Web · MAC — one fast, unified CLI*

<p align="center">
  <a href="README.md">🇬🇧 English</a> | <a href="README-IT.md">🇮🇹 Italiano</a>
</p>

<p align="center">
  <a href="https://github.com/chiaraberti13/ARGUS/actions"><img src="https://img.shields.io/badge/CI-GitHub%20Actions-blue?style=for-the-badge" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/chiaraberti13/ARGUS?style=for-the-badge&color=green" alt="License"></a>
  <img src="https://img.shields.io/badge/python-3.8%2B-blue?style=for-the-badge" alt="Python 3.8+">
  <img src="https://img.shields.io/badge/platform-Windows%20%7C%20Ubuntu%20%7C%20macOS-lightgrey?style=for-the-badge" alt="Platforms">
  <img src="https://img.shields.io/badge/modules-9-blue?style=for-the-badge" alt="9 modules">
</p>

</div>

> [!IMPORTANT]
> **For authorized security research, OSINT training and education only.**
> Argus only queries **publicly available** information. You are solely
> responsible for using it **lawfully and ethically** — read the full
> **[disclaimer](docs/DISCLAIMER.md)** before use.

---

## Quick Navigation

- **[What is Argus?](#what-is-argus)** — what it does, and who it's for.
- **[Modules](#-modules)** — every subcommand, what it does, and how username
  detection stays honest.
- **[Installation](#-installation)** — one-command install on Ubuntu, Debian,
  macOS, Windows, or Docker.
- **[Usage](#-usage)** — the interactive menu and the CLI subcommands.
- **[Configuration](#-configuration)** — flags, environment variables and
  config file, in resolution order.
- **[Project structure](#-project-structure)** — how the repository is laid
  out.
- **[Development](#-development)** — venv, tests, lint.
- **[License](#-license)** — MIT, for the whole repository.
- **[Legal & ethical use](#-legal--ethical-use)** — what "publicly available"
  and "passive" mean in practice.

> [!TIP]
> **Found a module idea or a bug?** Open an
> [issue](https://github.com/chiaraberti13/ARGUS/issues).

---

## What is Argus?

**Argus is a command-line toolkit for OSINT (Open Source Intelligence)** —
the practice of gathering information from *public, freely accessible* sources.
It brings together the reconnaissance steps an analyst normally does across a
dozen separate websites and tools into **one fast, consistent interface**, and
performs every lookup **passively**: it only reads public data and never
attacks, logs into, or probes private systems.

Give Argus an identifier — an IP, a domain, a phone number, a username, an email,
a URL or a MAC address — and it enriches it with everything public sources know
about it, then presents the result in clean colored tables and can save a
JSON / CSV / HTML report.

**Who it's for and what it's used for:**
- 🛡️ **Security professionals** — the reconnaissance phase of an *authorized*
  penetration test or red-team engagement (map a target's infrastructure).
- 🔎 **Threat intelligence & incident response** — quickly enrich an indicator
  (IP, domain, hash of an email) seen in logs or an alert.
- 🕵️ **OSINT analysts & investigators** — build a subject's public digital
  footprint from data they have chosen to make public.
- 🙋 **Privacy-conscious individuals** — audit *your own* exposure: which sites
  show your username, what your public IP reveals, what a domain leaks.
- 🎓 **Students & educators** — a hands-on, well-documented way to learn how
  OSINT, DNS, WHOIS, HTTP and geolocation actually work.

## 🧰 Modules

| Command | What it does |
|---------|--------------|
| `ip` | Geolocate an IPv4/IPv6 address (country, city, coords, ISP, ASN, map link) — HTTPS with dual-provider failover |
| `domain` | Domain / WHOIS data via **RDAP**: registrar, creation/expiry dates, name servers, status, DNSSEC |
| `dns` | Resolve A / AAAA / MX / TXT / NS / CNAME / SOA records via **DNS-over-HTTPS** |
| `phone` | Phone-number intelligence: validity, line type, carrier, region, timezones, 4 formats (**offline**) |
| `username` | Hunt a username across **50+ sites concurrently** with per-site detection (status / body-text / redirect) and an honest **blocked** state for anti-bot sites |
| `email` | Passive email OSINT: syntax, MX (mail-capable domain), Gravatar |
| `web` | Website / HTTP recon: status, redirects, server, **security-header audit**, resolved IP |
| `mac` | MAC address → hardware **vendor** (OUI), local/multicast flags |
| `myip` | Discover and geolocate **your own** public IP |
| `update` | Upgrade dependencies and refresh the username site list (`--check` for a dry run) |

Every result can be exported with `--export json|csv|html`.

### Reliable username detection

Naive "HTTP 200 = the profile exists" checks are wrong for most big platforms,
which answer `200` for every URL, redirect unknown users, or block bots. Argus
uses a per-site model (`errorType` in `data/sites.json`):

- **`status_code`** — exists only on a 2xx that was *not* redirected away.
- **`message`** — the page is always 200, so a marker string in the body decides.
- **`response_url`** — a missing profile is detected by its redirect target.

Anti-bot / rate-limit responses (401/403/406/429/451) are reported as
**`blocked`** — an explicit "unknown" — instead of being miscounted as found or
absent, so a result never claims more certainty than it has.

### Staying up to date

```bash
argus update            # upgrade dependencies + refresh the site list
argus update --check    # report what's outdated, change nothing
argus update --sites    # refresh only the username catalogue
```

On launch, the interactive menu prints a **non-blocking** one-line hint when a
newer dependency release exists (cached once per day, disable with
`ARGUS_NO_UPDATE_CHECK=1`). Set `auto_update: true` in the config to upgrade
dependencies automatically at startup (opt-in — it needs the network and is
slower).

## 🚀 Installation

The installer auto-detects your OS, installs Python if needed, creates an
isolated virtual environment, installs Argus and adds an `argus` command to your
PATH. Full step-by-step guide: **[docs/INSTALL.md](docs/INSTALL.md)**.

**Ubuntu / Debian / macOS**
```bash
git clone https://github.com/chiaraberti13/ARGUS.git argus
cd argus
./scripts/install.sh          # add --with-dns for real MX checks in the email module
argus                         # launch the interactive menu
```

**Windows (PowerShell)**
```powershell
git clone https://github.com/chiaraberti13/ARGUS.git argus
cd argus
powershell -ExecutionPolicy Bypass -File scripts\install.ps1
argus
```

**Docker (no local Python needed)**
```bash
docker build -t argus .
docker run --rm -it argus                 # interactive menu
docker run --rm argus ip 8.8.8.8          # one-off command
```

## 🎯 Usage

Run `argus` for the **interactive menu**, or use **subcommands** for scripting:

```bash
argus ip 8.8.8.8
argus domain github.com
argus dns example.com --types A,MX,TXT
argus phone "+14155552671"
argus username torvalds --export html
argus email someone@example.com
argus web example.com
argus mac 3C:22:FB:11:22:33
argus myip
```

Global flags (before or after the subcommand): `--export {json,csv,html}`,
`--timeout SECONDS`, `--workers N`, `--no-color`.
Full reference: **[docs/USAGE.md](docs/USAGE.md)**.

## ⚙️ Configuration

Resolved in order: **CLI flags → environment variables → config file → defaults**.

| Setting | Flag | Env var | Default |
|---------|------|---------|---------|
| Request timeout (s) | `--timeout` | `ARGUS_TIMEOUT` | `8.0` |
| Concurrent workers | `--workers` | `ARGUS_MAX_WORKERS` | `20` |
| Retries | — | `ARGUS_RETRIES` | `2` |
| Output directory | — | `ARGUS_OUTPUT_DIR` | `<script folder>/report` |
| User-Agent | — | `ARGUS_USER_AGENT` | browser UA |
| Disable SSL verify | — | `ARGUS_NO_VERIFY_SSL=1` | (verify on) |
| Startup update hint | — | `ARGUS_NO_UPDATE_CHECK=1` | (check on) |
| Auto-upgrade on launch | — | `ARGUS_AUTO_UPDATE=1` | (off) |

```bash
argus config --init      # write ~/.config/argus/config.json
argus config --show      # print current settings
```

## 🗂️ Project structure

```
argus/
├── argus/                    # the Python package
│   ├── cli.py                # menu + CLI subcommands
│   ├── config.py             # layered configuration
│   ├── ui.py                 # rich UI with plain fallback
│   ├── exporters.py          # JSON / CSV / HTML reports
│   └── modules/               # ip · domain · dns · phone · username · email · web · mac · myip
├── data/sites.json           # 50+ username targets (easy to extend)
├── scripts/                  # install.sh · install.ps1 · run.sh · run.bat
├── docs/                     # INSTALL (EN/IT) · USAGE · DISCLAIMER
├── tests/                    # offline unit tests
├── Dockerfile · Makefile · pyproject.toml
└── .github/workflows/ci.yml  # CI on Ubuntu, macOS, Windows
```

Add a site to the username hunter by editing
[`data/sites.json`](data/sites.json) — no code changes needed.

## 🧪 Development

```bash
make venv     # create .venv and install with dev extras
make test     # run the offline test suite
make lint     # ruff
make run      # launch the menu
```

## 📄 License

Released under the **[MIT License](LICENSE)**.

## ⚠️ Legal & ethical use

Argus queries only **publicly available** information and performs only
**passive** lookups. Use it exclusively on targets you own or are **explicitly
authorized** to investigate. Full terms: **[docs/DISCLAIMER.md](docs/DISCLAIMER.md)**.

---

<p align="center">
  <sub>Made with 👁️ by <a href="https://github.com/chiaraberti13">chiaraberti13</a></sub>
</p>
