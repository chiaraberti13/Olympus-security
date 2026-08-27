# Unified installation & operation

Olympus-native ARGUS and AEGIS, the temporary VAP web compatibility layer, and
the specialist-engine catalogue from one checkout. Linux (Debian/Ubuntu shown;
adapt the package manager for RHEL/Arch).

## 1. Base install (Olympus + native modules)

```bash
git clone https://github.com/chiaraberti13/olympus-security
cd olympus-security
python -m pip install -e ".[dev]"
olympus --version
olympus doctor            # environment diagnostics (binaries, services, deps)
```

## 2. Native ARGUS and temporary VAP dependencies

```bash
olympus argus --help                      # already installed by the base package
bash scripts/setup-vendored-tools.sh      # installs .[aegis,dev] + temporary VAP pins
# or:
pip install -e ".[aegis]"                # temporary VAP web/DB/worker stack
```

## 3. AEGIS — native operation (single host)

```bash
# System services (Debian/Ubuntu):
sudo apt-get update && sudo apt-get install -y redis-server
sudo systemctl enable --now redis-server

olympus aegis migrate                      # initialize / upgrade the database
olympus aegis doctor                       # check web stack, Redis, reports dir, scanners
olympus aegis serve --host 127.0.0.1 --port 8000   # web app  (terminal 1)
olympus aegis workers                      # Celery scan worker (terminal 2)
```

Shutdown: Ctrl-C each process. Reset (native): stop them, delete the SQLite DB
(`vendor/vulnerability-assessment-platform/vap.db`) and the reports dir.

## 4. AEGIS — Docker operation (full stack, one command)

```bash
docker compose up --build                  # redis + aegis-migrate + aegis-app + aegis-worker
docker compose ps                          # health status
docker compose logs -f aegis-app           # follow logs
docker compose down                        # stop
docker compose down -v                     # STOP + reset (removes vap-data / redis-data volumes)
docker compose pull && docker compose up --build -d   # update

# With open-source scanner binaries baked in (19/24):
docker compose -f docker-compose.yml -f docker-compose.scanners.yml up --build
```

Env: copy `.env.docker.example` → `.env` to override `VAP_PORT`,
`VAP_ENABLE_LIVE_SCANS`, secrets, etc. Ports: app on `:8000` (or `VAP_PORT`);
Redis is internal-only. Volumes: `vap-data` (`/data`: SQLite DB + reports),
`redis-data`. Health checks: app `GET /health`, `redis-cli ping`, `celery
inspect ping`. Migrations: the `aegis-migrate` one-shot runs `alembic upgrade
head` before app/worker start.

## 5. Scanner binaries

19 open-source scanners are installed by `docker/Dockerfile.scanners`
(apt/pip/go/git/gem). Check what is actually present:

```bash
olympus aegis scanners --check      # per-scanner binary availability + licence
olympus aegis deps                  # web stack + every scanner binary + version
```

The 5 API/commercial engines (zap, openvas, nessus, burp, acunetix) require
manual install and licence/API configuration via their `VAP_*` settings — see
`docs/scanner-matrix.md`. Live scanning also requires
`VAP_ENABLE_LIVE_SCANS=true` and explicit authorization/scope; otherwise
the native execution path refuses the run or returns an explicit unavailable /
disabled state. Simulation occurs only when the operator explicitly requests it.

## 6. Diagnostics

```bash
olympus doctor           # ecosystem-wide: python deps, git/docker/redis-cli, redis, scanners
olympus aegis doctor     # AEGIS: web stack, Redis, DB/reports dir, live-scan flag, secrets(set?), scanners
olympus argus doctor     # ARGUS: dnspython/phonenumbers, optional API keys (set?)
```

All `doctor` output is secret-safe: it reports whether a secret env var is
*set*, never its value.

## 7. Manual-install dependencies (summary)

| Dependency | Needed for | Install |
| --- | --- | --- |
| redis-server | queued AEGIS scans | `apt-get install redis-server` or the Docker `redis` service |
| 19 OSS scanners | live AEGIS scans | `docker-compose.scanners.yml` or `vendor/.../installer.sh` |
| OWASP ZAP | `zap` scanner | ZAP daemon/docker image + API config |
| OpenVAS/GVM | `openvas` scanner | Greenbone GVM stack (docker/manual) |
| Nessus / Burp / Acunetix | those scanners | vendor installer + commercial licence + API config |
