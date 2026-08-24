#!/usr/bin/env bash
# Reproducible setup for the complete vendored upstream tools (ARGUS + VAP).
#
# This installs the Python dependencies for both vendored tools so they run
# end to end from a single Olympus checkout. External *scanner binaries* used
# by VAP (nmap, nuclei, sqlmap, wpscan, ...) are installed separately by the
# VAP installer or provided by its Docker image — see the notes at the end.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${PYTHON:-python3}"

echo "==> Installing Olympus (editable) with vendored-tool extras"
"$PYTHON" -m pip install -e "$ROOT[argus,vap,dev]"

echo "==> Installing the complete VAP pinned requirements"
"$PYTHON" -m pip install -r "$ROOT/vendor/vulnerability-assessment-platform/requirements.txt"

echo
echo "Done. Run the tools through Olympus:"
echo "  olympus argus-native --help          # complete ARGUS CLI"
echo "  olympus vap scanners                 # list all 24 scanners"
echo "  olympus vap migrate                  # apply VAP DB migrations"
echo "  olympus vap serve --host 127.0.0.1 --port 8000   # serve the VAP web app"
echo
echo "External scanner binaries (nmap, nuclei, sqlmap, wpscan, ...) and the full"
echo "stack (Redis/Celery for queued scans) are provisioned reproducibly by:"
echo "  bash vendor/vulnerability-assessment-platform/installer.sh"
echo "  docker compose -f vendor/vulnerability-assessment-platform/docker-compose.yml up"
echo "  bash vendor/argus/scripts/install.sh   # ARGUS one-command install"
